class CreateSourceUploadSessions < ActiveRecord::Migration[8.1]
  def up
    remove_index :source_snapshots, column: :digest
    add_index :source_snapshots, %i[organization_id project_id digest], unique: true, name: "source_snapshots_project_digest"

    create_table :source_upload_sessions do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.references :project, null: false, foreign_key: { on_delete: :cascade }
      table.references :created_by_account, null: false, foreign_key: { to_table: :accounts }
      table.references :source_snapshot, foreign_key: true
      table.string :state, null: false, default: "authorized", limit: 32
      table.bigint :expected_archive_bytes, null: false
      table.string :expected_archive_sha256, null: false, limit: 71
      table.integer :expected_parts, null: false
      table.string :root_directory, null: false, default: "", limit: 512
      table.integer :excluded_count, null: false, default: 0
      table.jsonb :uploaded_parts, null: false, default: []
      table.integer :finalize_attempts, null: false, default: 0
      table.string :snapshot_sha256, limit: 71
      table.string :manifest_sha256, limit: 71
      table.string :archive_sha256, limit: 71
      table.string :manifest_ref
      table.string :archive_ref
      table.string :signing_key_id, limit: 128
      table.text :last_error
      table.datetime :expires_at, null: false
      table.datetime :finalized_at
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[state expires_at]
      table.check_constraint "public_id ~ '^upl_[0-9a-f-]{36}$'", name: "source_upload_sessions_public_id_format"
      table.check_constraint "state IN ('authorized', 'uploading', 'finalizing', 'complete', 'failed', 'expired', 'canceled')", name: "source_upload_sessions_state"
      table.check_constraint "expected_archive_bytes BETWEEN 1 AND 1073741824", name: "source_upload_sessions_bytes"
      table.check_constraint "expected_parts BETWEEN 1 AND 256", name: "source_upload_sessions_parts"
      table.check_constraint "expected_archive_bytes <= expected_parts::bigint * 16777216", name: "source_upload_sessions_part_capacity"
      table.check_constraint "expected_archive_sha256 ~ '^sha256:[0-9a-f]{64}$'", name: "source_upload_sessions_archive_digest"
      table.check_constraint "excluded_count >= 0", name: "source_upload_sessions_excluded"
      table.check_constraint "jsonb_typeof(uploaded_parts) = 'array'", name: "source_upload_sessions_uploaded_parts"
    end

    execute <<~SQL
      ALTER TABLE source_upload_sessions ENABLE ROW LEVEL SECURITY;
      ALTER TABLE source_upload_sessions FORCE ROW LEVEL SECURITY;
      CREATE POLICY source_upload_sessions_tenant_policy ON source_upload_sessions
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL

    execute <<~SQL
      CREATE FUNCTION lrail_expire_source_upload_sessions(requested_limit integer)
      RETURNS SETOF text AS $$
        WITH candidates AS (
          SELECT id
          FROM source_upload_sessions
          WHERE state IN ('authorized', 'uploading', 'failed')
            AND expires_at <= clock_timestamp()
          ORDER BY expires_at, id
          FOR UPDATE SKIP LOCKED
          LIMIT GREATEST(1, LEAST(COALESCE(requested_limit, 1), 500))
        )
        UPDATE source_upload_sessions AS session
        SET state = 'expired', updated_at = clock_timestamp()
        FROM candidates
        WHERE session.id = candidates.id
        RETURNING session.public_id;
      $$ LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;
      REVOKE ALL ON FUNCTION lrail_expire_source_upload_sessions(integer) FROM PUBLIC;
    SQL

    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    if select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")
      quoted_role = connection.quote_table_name(role)
      execute "GRANT SELECT, INSERT, UPDATE, DELETE ON source_upload_sessions TO #{quoted_role}"
      execute "GRANT USAGE, SELECT ON source_upload_sessions_id_seq TO #{quoted_role}"
    end
    if select_value("SELECT 1 FROM pg_roles WHERE rolname = 'lrail_worker'")
      execute "GRANT EXECUTE ON FUNCTION lrail_expire_source_upload_sessions(integer) TO lrail_worker"
    end
  end

  def down
    execute "DROP FUNCTION IF EXISTS lrail_expire_source_upload_sessions(integer)"
    drop_table :source_upload_sessions
    remove_index :source_snapshots, name: "source_snapshots_project_digest"
    add_index :source_snapshots, :digest, unique: true
  end
end
