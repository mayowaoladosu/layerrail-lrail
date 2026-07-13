class AddDeploymentBuildOrchestration < ActiveRecord::Migration[8.1]
  DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"

  def up
    remove_check_constraint :deployments, name: "deployments_state"
    add_check_constraint :deployments, <<~SQL.squish, name: "deployments_state"
      state IN (
        'created', 'sourcing', 'detecting', 'queued', 'building', 'scanning', 'publishing',
        'artifact_ready', 'scheduling', 'starting', 'verifying', 'ready', 'promoted',
        'canceling', 'canceled', 'failed', 'retrying'
      )
    SQL
    add_column :deployments, :artifact_ready_at, :datetime
    add_column :deployments, :build_mode, :string, null: false, default: "auto", limit: 16
    add_column :deployments, :build_file, :string, limit: 1_024
    add_column :deployments, :accept_detected, :boolean, null: false, default: false
    add_check_constraint :deployments,
      "build_mode IN ('auto', 'repository')",
      name: "deployments_build_mode"
    add_check_constraint :deployments, <<~SQL.squish, name: "deployments_build_configuration"
      (build_mode = 'auto' AND build_file IS NULL) OR
      (build_mode = 'repository' AND build_file IS NOT NULL AND char_length(build_file) BETWEEN 1 AND 1024)
    SQL

    change_column_null :builds, :definition_digest, true
    change_table :builds, bulk: true do |table|
      table.references :deployment, foreign_key: { on_delete: :restrict }
      table.bigint :generation, null: false, default: 1
      table.string :detection_digest, limit: 71
      table.string :detection_ref
      table.string :manifest_digest, limit: 71
      table.string :manifest_ref
      table.string :build_ir_digest, limit: 71
      table.string :build_ir_ref
      table.string :definition_lock_ref
      table.string :assignment_digest, limit: 71
      table.string :logs_digest, limit: 71
      table.string :worker_identity, limit: 512
      table.string :cleanup_state, limit: 32
      table.string :error_code, limit: 128
      table.text :error_message
    end
    add_index :builds, %i[deployment_id generation], unique: true,
      where: "deployment_id IS NOT NULL", name: "builds_deployment_generation"
    add_check_constraint :builds, "generation > 0", name: "builds_generation"
    add_check_constraint :builds,
      "state IN ('accepted', 'running', 'waiting', 'retrying', 'canceling', 'complete', 'failed', 'canceled')",
      name: "builds_state"
    %i[detection_digest manifest_digest build_ir_digest definition_digest assignment_digest logs_digest].each do |column|
      add_check_constraint :builds, "#{column} IS NULL OR #{column} ~ '#{DIGEST_PATTERN}'",
        name: "builds_#{column}"
    end

    create_table :operation_events do |table|
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.references :operation, null: false, foreign_key: { on_delete: :cascade }
      table.references :build, foreign_key: { on_delete: :nullify }
      table.bigint :generation, null: false
      table.bigint :sequence, null: false
      table.integer :attempt, null: false
      table.string :stage, null: false, limit: 64
      table.string :kind, null: false, limit: 64
      table.string :output, limit: 512
      table.string :vertex, limit: 512
      table.string :name, limit: 512
      table.bigint :current
      table.bigint :total
      table.boolean :cached, null: false, default: false
      table.integer :stream, null: false, default: 0
      table.text :line
      table.string :code, limit: 128
      table.text :message
      table.datetime :occurred_at, null: false
      table.timestamps
      table.index %i[operation_id generation sequence], unique: true,
        name: "operation_events_generation_sequence"
      table.index %i[operation_id occurred_at id], name: "operation_events_timeline"
      table.check_constraint "generation > 0", name: "operation_events_generation"
      table.check_constraint "sequence > 0", name: "operation_events_sequence"
      table.check_constraint "attempt > 0", name: "operation_events_attempt"
      table.check_constraint "stream >= 0", name: "operation_events_stream"
      table.check_constraint "char_length(line) <= 16384", name: "operation_events_line_size"
      table.check_constraint "char_length(message) <= 4096", name: "operation_events_message_size"
    end
    execute <<~SQL
      ALTER TABLE operation_events ENABLE ROW LEVEL SECURITY;
      ALTER TABLE operation_events FORCE ROW LEVEL SECURITY;
      CREATE POLICY operation_events_tenant_policy ON operation_events
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL
    grant_runtime_access

    change_table :attestations, bulk: true do |table|
      table.string :payload_digest, limit: 71
      table.string :subject_digest, limit: 71
      table.string :signer_key_id, limit: 128
      table.integer :signer_key_version
      table.string :signer_public_key_digest, limit: 71
      table.string :policy_digest, limit: 71
    end
    add_index :attestations, %i[revision_id kind], unique: true,
      name: "attestations_revision_kind"
    %i[digest payload_digest subject_digest signer_public_key_digest policy_digest].each do |column|
      add_check_constraint :attestations, "#{column} IS NULL OR #{column} ~ '#{DIGEST_PATTERN}'",
        name: "attestations_#{column}"
    end
    add_check_constraint :attestations,
      "kind IN ('sbom', 'vulnerability_scan', 'provenance', 'signature', 'policy_decision')",
      name: "attestations_kind"
    add_check_constraint :attestations,
      "signer_key_version IS NULL OR signer_key_version > 0",
      name: "attestations_signer_key_version"
  end

  def down
    remove_check_constraint :attestations, name: "attestations_signer_key_version"
    remove_check_constraint :attestations, name: "attestations_kind"
    %i[digest payload_digest subject_digest signer_public_key_digest policy_digest].each do |column|
      remove_check_constraint :attestations, name: "attestations_#{column}"
    end
    remove_index :attestations, name: "attestations_revision_kind"
    remove_columns :attestations, :payload_digest, :subject_digest, :signer_key_id,
      :signer_key_version, :signer_public_key_digest, :policy_digest

    drop_table :operation_events

    %i[detection_digest manifest_digest build_ir_digest definition_digest assignment_digest logs_digest].each do |column|
      remove_check_constraint :builds, name: "builds_#{column}"
    end
    remove_check_constraint :builds, name: "builds_state"
    remove_check_constraint :builds, name: "builds_generation"
    remove_index :builds, name: "builds_deployment_generation"
    remove_reference :builds, :deployment, foreign_key: true
    remove_columns :builds, :generation, :detection_digest, :detection_ref, :manifest_digest,
      :manifest_ref, :build_ir_digest, :build_ir_ref, :definition_lock_ref,
      :assignment_digest, :logs_digest, :worker_identity, :cleanup_state,
      :error_code, :error_message
    change_column_null :builds, :definition_digest, false

    remove_column :deployments, :artifact_ready_at
    remove_check_constraint :deployments, name: "deployments_build_configuration" if
      check_constraint_exists?(:deployments, name: "deployments_build_configuration")
    remove_check_constraint :deployments, name: "deployments_build_mode" if
      check_constraint_exists?(:deployments, name: "deployments_build_mode")
    %i[build_mode build_file accept_detected].each do |column|
      remove_column :deployments, column if column_exists?(:deployments, column)
    end
    remove_check_constraint :deployments, name: "deployments_state"
    add_check_constraint :deployments, <<~SQL.squish, name: "deployments_state"
      state IN (
        'created', 'sourcing', 'detecting', 'queued', 'building', 'scanning', 'publishing',
        'scheduling', 'starting', 'verifying', 'ready', 'promoted', 'canceling',
        'canceled', 'failed', 'retrying'
      )
    SQL
  end

  private

  def grant_runtime_access
    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")

    quoted_role = connection.quote_table_name(role)
    execute "GRANT SELECT, INSERT, UPDATE, DELETE ON operation_events TO #{quoted_role}"
    execute "GRANT USAGE, SELECT ON SEQUENCE operation_events_id_seq TO #{quoted_role}"
  end
end
