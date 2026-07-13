class AddGithubSourceProviderBoundary < ActiveRecord::Migration[8.1]
  ID_PATTERN = "^[a-z]{2,5}_[0-9a-f-]{36}$"
  DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
  COMMIT_PATTERN = "^[0-9a-f]{40}([0-9a-f]{24})?$"

  def up
    change_table :source_connections, bulk: true do |table|
      table.string :provider_account_login, limit: 255
      table.bigint :provider_account_id
      table.string :repository_selection, null: false, default: "selected", limit: 16
      table.jsonb :selected_repositories, null: false, default: []
      table.datetime :token_expires_at
      table.datetime :revoked_at
    end
    add_reference :source_connections, :connected_by_account,
      foreign_key: { to_table: :accounts, on_delete: :restrict }
    execute <<~SQL
      UPDATE source_connections
      SET provider_account_login = installation_external_id
      WHERE provider_account_login IS NULL;
      UPDATE source_connections
      SET installation_external_id = (1000000 + id)::text
      WHERE installation_external_id !~ '^[1-9][0-9]{0,19}$';
      UPDATE source_connections
      SET scopes = '["contents:read", "metadata:read"]'::jsonb
      WHERE provider = 'github';
      UPDATE source_connections AS connection
      SET connected_by_account_id = (
        SELECT membership.account_id
        FROM memberships AS membership
        WHERE membership.organization_id = connection.organization_id AND membership.status = 'active'
        ORDER BY CASE membership.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, membership.id
        LIMIT 1
      )
      WHERE connection.connected_by_account_id IS NULL;
    SQL
    change_column_null :source_connections, :provider_account_login, false
    change_column_null :source_connections, :connected_by_account_id, false
    add_check_constraint :source_connections, "provider = 'github'", name: "source_connections_provider"
    add_check_constraint :source_connections, "status IN ('active', 'suspended', 'revoked')", name: "source_connections_status"
    add_check_constraint :source_connections, "installation_external_id ~ '^[1-9][0-9]{0,19}$'", name: "source_connections_installation"
    add_check_constraint :source_connections, "repository_selection IN ('all', 'selected')", name: "source_connections_repository_selection"
    add_check_constraint :source_connections, "jsonb_typeof(scopes) = 'array'", name: "source_connections_scopes_array"
    add_check_constraint :source_connections, "jsonb_typeof(selected_repositories) = 'array'", name: "source_connections_repositories_array"
    add_index :source_connections, %i[provider installation_external_id], unique: true,
      name: "source_connections_global_provider_identity"

    create_table :source_fetches do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.references :project, null: false, foreign_key: { on_delete: :restrict }
      table.references :source_connection, null: false, foreign_key: { on_delete: :restrict }
      table.references :created_by_account, null: false, foreign_key: { to_table: :accounts, on_delete: :restrict }
      table.references :source_snapshot, foreign_key: { on_delete: :restrict }
      table.string :state, null: false, default: "authorized", limit: 32
      table.string :repository, null: false, limit: 201
      table.string :requested_commit_sha, null: false, limit: 64
      table.string :resolved_commit_sha, limit: 64
      table.string :tree_sha, limit: 64
      table.string :root_directory, null: false, default: "", limit: 512
      table.integer :attempt_count, null: false, default: 0
      table.string :snapshot_sha256, limit: 71
      table.string :manifest_sha256, limit: 71
      table.string :archive_sha256, limit: 71
      table.string :manifest_ref
      table.string :archive_ref
      table.string :signing_key_id, limit: 128
      table.string :author, limit: 512
      table.datetime :authored_at
      table.string :policy_version, limit: 128
      table.jsonb :warnings, null: false, default: []
      table.jsonb :submodules, null: false, default: []
      table.jsonb :lfs_digests, null: false, default: []
      table.datetime :token_expires_at
      table.datetime :expires_at, null: false
      table.datetime :finalized_at
      table.text :last_error
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[source_connection_id repository requested_commit_sha], name: "source_fetch_provider_commit"
      table.index %i[state expires_at], name: "source_fetch_expiry_queue"
      table.check_constraint "public_id ~ '#{ID_PATTERN}'", name: "source_fetches_public_id_format"
      table.check_constraint "state IN ('authorized', 'fetching', 'complete', 'failed', 'expired', 'canceled')", name: "source_fetches_state"
      table.check_constraint "requested_commit_sha ~ '#{COMMIT_PATTERN}'", name: "source_fetches_requested_commit"
      table.check_constraint "resolved_commit_sha IS NULL OR resolved_commit_sha ~ '#{COMMIT_PATTERN}'", name: "source_fetches_resolved_commit"
      table.check_constraint "tree_sha IS NULL OR tree_sha ~ '#{COMMIT_PATTERN}'", name: "source_fetches_tree"
      table.check_constraint "snapshot_sha256 IS NULL OR snapshot_sha256 ~ '#{DIGEST_PATTERN}'", name: "source_fetches_snapshot_digest"
      table.check_constraint "policy_version IS NULL OR char_length(policy_version) BETWEEN 1 AND 128", name: "source_fetches_policy_version"
      table.check_constraint "jsonb_typeof(warnings) = 'array'", name: "source_fetches_warnings_array"
      table.check_constraint "jsonb_typeof(submodules) = 'array'", name: "source_fetches_submodules_array"
      table.check_constraint "jsonb_typeof(lfs_digests) = 'array'", name: "source_fetches_lfs_array"
      table.check_constraint "attempt_count >= 0", name: "source_fetches_attempts"
    end

    execute <<~SQL
      ALTER TABLE source_fetches ENABLE ROW LEVEL SECURITY;
      ALTER TABLE source_fetches FORCE ROW LEVEL SECURITY;
      CREATE POLICY source_fetches_tenant_policy ON source_fetches
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL

    create_table :source_provider_deliveries do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.references :source_connection, null: false, foreign_key: { on_delete: :restrict }
      table.string :provider, null: false, limit: 32
      table.string :external_delivery_id, null: false, limit: 128
      table.string :event_type, null: false, limit: 64
      table.string :action, limit: 64
      table.string :payload_digest, null: false, limit: 71
      table.string :state, null: false, default: "received", limit: 32
      table.string :repository, limit: 201
      table.string :ref, limit: 512
      table.string :commit_sha, limit: 64
      table.string :base_commit_sha, limit: 64
      table.integer :pull_request_number
      table.boolean :forced, null: false, default: false
      table.boolean :deleted, null: false, default: false
      table.datetime :processed_at
      table.integer :attempt_count, null: false, default: 0
      table.string :processing_token, limit: 128
      table.datetime :processing_started_at
      table.text :last_error
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[provider external_delivery_id], unique: true, name: "source_provider_delivery_dedupe"
      table.index %i[source_connection_id repository event_type created_at], name: "source_provider_delivery_timeline"
      table.check_constraint "public_id ~ '#{ID_PATTERN}'", name: "source_provider_deliveries_public_id_format"
      table.check_constraint "provider = 'github'", name: "source_provider_deliveries_provider"
      table.check_constraint "payload_digest ~ '#{DIGEST_PATTERN}'", name: "source_provider_deliveries_digest"
      table.check_constraint "state IN ('received', 'processing', 'processed', 'ignored', 'failed')", name: "source_provider_deliveries_state"
      table.check_constraint "attempt_count >= 0", name: "source_provider_deliveries_attempts"
      table.check_constraint "commit_sha IS NULL OR commit_sha ~ '#{COMMIT_PATTERN}'", name: "source_provider_deliveries_commit"
      table.check_constraint "base_commit_sha IS NULL OR base_commit_sha ~ '#{COMMIT_PATTERN}'", name: "source_provider_deliveries_base_commit"
    end

    execute <<~SQL
      ALTER TABLE source_provider_deliveries ENABLE ROW LEVEL SECURITY;
      ALTER TABLE source_provider_deliveries FORCE ROW LEVEL SECURITY;
      CREATE POLICY source_provider_deliveries_tenant_policy ON source_provider_deliveries
      FOR SELECT
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL

    create_table :project_source_bindings do |table|
      table.string :public_id, null: false, limit: 64
      table.references :organization, null: false, foreign_key: { on_delete: :cascade }
      table.references :project, null: false, foreign_key: { on_delete: :cascade }, index: { unique: true }
      table.references :source_connection, null: false, foreign_key: { on_delete: :restrict }
      table.references :created_by_account, null: false, foreign_key: { to_table: :accounts, on_delete: :restrict }
      table.references :current_source_fetch, foreign_key: { to_table: :source_fetches, on_delete: :nullify }
      table.references :last_provider_delivery, foreign_key: { to_table: :source_provider_deliveries, on_delete: :nullify }
      table.string :repository, null: false, limit: 201
      table.string :production_branch, null: false, default: "main", limit: 255
      table.string :root_directory, null: false, default: "", limit: 512
      table.boolean :automatic_deployments, null: false, default: true
      table.string :current_ref, limit: 512
      table.string :requested_commit_sha, limit: 64
      table.bigint :generation, null: false, default: 1
      table.timestamps
      table.index :public_id, unique: true
      table.index %i[source_connection_id repository automatic_deployments], name: "project_source_provider_lookup"
      table.check_constraint "public_id ~ '#{ID_PATTERN}'", name: "project_source_bindings_public_id_format"
      table.check_constraint "repository ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$'", name: "project_source_bindings_repository"
      table.check_constraint "requested_commit_sha IS NULL OR requested_commit_sha ~ '#{COMMIT_PATTERN}'", name: "project_source_bindings_commit"
      table.check_constraint "generation > 0", name: "project_source_bindings_generation"
    end

    execute <<~SQL
      ALTER TABLE project_source_bindings ENABLE ROW LEVEL SECURITY;
      ALTER TABLE project_source_bindings FORCE ROW LEVEL SECURITY;
      CREATE POLICY project_source_bindings_tenant_policy ON project_source_bindings
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL

    add_reference :source_fetches, :project_source_binding,
      foreign_key: { on_delete: :restrict }
    add_reference :source_fetches, :source_provider_delivery,
      foreign_key: { on_delete: :restrict }
    add_reference :source_fetches, :superseded_by_source_fetch,
      foreign_key: { to_table: :source_fetches, on_delete: :restrict }
    add_column :source_fetches, :superseded_at, :datetime
    add_index :source_fetches, %i[project_source_binding_id source_provider_delivery_id],
      unique: true,
      where: "project_source_binding_id IS NOT NULL AND source_provider_delivery_id IS NOT NULL",
      name: "source_fetch_provider_effect"

    create_provider_delivery_function
    create_provider_delivery_work_functions
    configure_provider_delivery_role
  end

  def down
    execute "DROP FUNCTION IF EXISTS lrail_finish_github_provider_delivery(text, text, boolean, text)"
    execute "DROP FUNCTION IF EXISTS lrail_claim_github_provider_delivery(text, text)"
    execute "DROP FUNCTION IF EXISTS lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text)"
    remove_reference :source_fetches, :superseded_by_source_fetch, foreign_key: { to_table: :source_fetches }
    remove_reference :source_fetches, :source_provider_delivery, foreign_key: true
    remove_reference :source_fetches, :project_source_binding, foreign_key: true
    drop_table :project_source_bindings
    drop_table :source_provider_deliveries
    drop_table :source_fetches
    remove_check_constraint :source_connections, name: "source_connections_repositories_array"
    remove_check_constraint :source_connections, name: "source_connections_scopes_array"
    remove_check_constraint :source_connections, name: "source_connections_repository_selection"
    remove_check_constraint :source_connections, name: "source_connections_installation"
    remove_check_constraint :source_connections, name: "source_connections_status"
    remove_check_constraint :source_connections, name: "source_connections_provider"
    remove_index :source_connections, name: "source_connections_global_provider_identity"
    remove_columns :source_connections, :provider_account_login, :provider_account_id,
      :repository_selection, :selected_repositories, :token_expires_at, :revoked_at
    remove_reference :source_connections, :connected_by_account, foreign_key: { to_table: :accounts }
  end

  private

  def create_provider_delivery_function
    execute <<~SQL
      CREATE FUNCTION lrail_apply_github_provider_delivery(
        installation_id text,
        delivery_id text,
        delivery_event text,
        delivery_action text,
        payload_sha256 text,
        repository_name text,
        git_ref text,
        head_commit text,
        base_commit text,
        pr_number integer,
        was_forced boolean,
        was_deleted boolean,
        processing_state text,
        next_connection_status text,
        account_login text,
        account_id bigint,
        repository_selection_value text,
        repositories_mode text,
        repository_values jsonb,
        delivery_public_id text,
        event_public_id text,
        audit_public_id text,
        request_id text
      ) RETURNS jsonb AS $$
      DECLARE
        connection_row source_connections%ROWTYPE;
        existing_digest text;
        existing_delivery_public_id text;
        existing_delivery_state text;
        existing_processing_started_at timestamptz;
        next_repositories jsonb;
        organization_public_id_value text;
        actor_public_id_value text;
      BEGIN
        IF delivery_event NOT IN ('push', 'pull_request', 'installation', 'installation_repositories')
           OR processing_state NOT IN ('received', 'processed', 'ignored')
            OR installation_id !~ '^[1-9][0-9]{0,19}$'
           OR delivery_id !~ '^[0-9A-Za-z-]{8,128}$'
           OR payload_sha256 !~ '#{DIGEST_PATTERN}'
           OR delivery_public_id !~ '#{ID_PATTERN}'
           OR event_public_id !~ '#{ID_PATTERN}'
           OR audit_public_id !~ '#{ID_PATTERN}'
           OR request_id !~ '^req_[0-9a-f]{32}$'
           OR char_length(delivery_action) > 64
           OR char_length(account_login) > 255
           OR (account_id IS NOT NULL AND account_id < 1)
           OR (head_commit IS NOT NULL AND head_commit !~ '#{COMMIT_PATTERN}')
           OR (base_commit IS NOT NULL AND base_commit !~ '#{COMMIT_PATTERN}')
           OR (repository_name <> '' AND repository_name !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$')
           OR char_length(git_ref) > 512
           OR (pr_number IS NOT NULL AND pr_number < 1)
           OR next_connection_status NOT IN ('', 'active', 'suspended', 'revoked')
           OR repository_selection_value NOT IN ('', 'all', 'selected')
           OR repositories_mode NOT IN ('none', 'replace', 'add', 'remove')
           OR (repository_values IS NOT NULL AND jsonb_typeof(repository_values) <> 'array')
           OR EXISTS (
             SELECT 1 FROM jsonb_array_elements_text(COALESCE(repository_values, '[]'::jsonb)) AS repository(value)
             WHERE value !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$'
           )
           OR (
             delivery_event = 'push' AND (
               COALESCE(repository_name, '') = '' OR COALESCE(git_ref, '') = '' OR
               pr_number IS NOT NULL OR repositories_mode <> 'none' OR
               (was_deleted AND head_commit IS NOT NULL) OR
               (NOT was_deleted AND head_commit IS NULL) OR
               (was_deleted AND processing_state <> 'ignored') OR
               (NOT was_deleted AND processing_state <> 'received')
             )
           )
           OR (
             delivery_event = 'pull_request' AND (
               COALESCE(repository_name, '') = '' OR COALESCE(git_ref, '') = '' OR
               head_commit IS NULL OR base_commit IS NULL OR pr_number IS NULL OR
               was_forced OR repositories_mode <> 'none' OR
               (delivery_action IN ('opened', 'reopened', 'synchronize') AND processing_state <> 'received') OR
               (delivery_action NOT IN ('opened', 'reopened', 'synchronize') AND processing_state <> 'ignored')
             )
           )
           OR (
             delivery_event = 'installation' AND (
               COALESCE(delivery_action, '') = '' OR COALESCE(account_login, '') = '' OR account_id IS NULL OR
               processing_state NOT IN ('processed', 'ignored') OR
               repository_name IS NOT NULL OR git_ref IS NOT NULL OR head_commit IS NOT NULL OR
               base_commit IS NOT NULL OR pr_number IS NOT NULL OR was_forced OR was_deleted
             )
           )
           OR (
             delivery_event = 'installation_repositories' AND (
               delivery_action NOT IN ('added', 'removed') OR
               repository_selection_value NOT IN ('all', 'selected') OR
               repositories_mode NOT IN ('add', 'remove') OR
               processing_state <> 'processed' OR
               repository_name IS NOT NULL OR git_ref IS NOT NULL OR head_commit IS NOT NULL OR
               base_commit IS NOT NULL OR pr_number IS NOT NULL OR was_forced OR was_deleted
             )
           ) THEN
          RAISE EXCEPTION 'invalid GitHub provider delivery' USING ERRCODE = '22023';
        END IF;

        SELECT * INTO connection_row
        FROM source_connections
        WHERE provider = 'github' AND installation_external_id = installation_id
        LIMIT 1;
        IF connection_row.id IS NULL THEN
          RETURN jsonb_build_object('outcome', 'unknown_installation', 'work_pending', false);
        END IF;
        SELECT public_id INTO organization_public_id_value FROM organizations WHERE id = connection_row.organization_id;
        SELECT account.public_id INTO actor_public_id_value
        FROM memberships AS membership
        JOIN accounts AS account ON account.id = membership.account_id
        WHERE membership.organization_id = connection_row.organization_id
          AND membership.status = 'active'
        ORDER BY
          CASE WHEN membership.account_id = connection_row.connected_by_account_id THEN 0 ELSE 1 END,
          CASE membership.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'developer' THEN 2 ELSE 3 END,
          membership.id
        LIMIT 1;
        IF actor_public_id_value IS NULL THEN
          RETURN jsonb_build_object('outcome', 'unknown_installation', 'work_pending', false);
        END IF;

        PERFORM pg_advisory_xact_lock(hashtextextended('github:' || delivery_id, 0));

        SELECT payload_digest, public_id, state, processing_started_at
        INTO existing_digest, existing_delivery_public_id, existing_delivery_state, existing_processing_started_at
        FROM source_provider_deliveries
        WHERE provider = 'github' AND external_delivery_id = delivery_id;
        IF existing_digest IS NOT NULL THEN
          RETURN jsonb_build_object(
            'outcome', CASE WHEN existing_digest = payload_sha256 THEN 'duplicate' ELSE 'mismatch' END,
            'delivery_public_id', existing_delivery_public_id,
            'organization_public_id', organization_public_id_value,
            'actor_public_id', actor_public_id_value,
            'work_pending', connection_row.status = 'active' AND existing_digest = payload_sha256 AND (
              existing_delivery_state IN ('received', 'failed') OR
              (existing_delivery_state = 'processing' AND existing_processing_started_at < clock_timestamp() - interval '20 minutes')
            )
          );
        END IF;

        IF delivery_event IN ('push', 'pull_request') AND connection_row.status <> 'active' THEN
          processing_state := 'ignored';
        END IF;

        next_repositories := connection_row.selected_repositories;
        IF repositories_mode = 'replace' THEN
          next_repositories := COALESCE(repository_values, '[]'::jsonb);
        ELSIF repositories_mode = 'add' THEN
          SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb) INTO next_repositories
          FROM (
            SELECT DISTINCT value
            FROM jsonb_array_elements_text(connection_row.selected_repositories || COALESCE(repository_values, '[]'::jsonb))
          ) AS values;
        ELSIF repositories_mode = 'remove' THEN
          SELECT COALESCE(jsonb_agg(value ORDER BY value), '[]'::jsonb) INTO next_repositories
          FROM jsonb_array_elements_text(connection_row.selected_repositories) AS values(value)
          WHERE NOT COALESCE(repository_values, '[]'::jsonb) ? value;
        ELSIF repositories_mode <> 'none' THEN
          RAISE EXCEPTION 'invalid GitHub repository update mode' USING ERRCODE = '22023';
        END IF;

        INSERT INTO source_provider_deliveries(
          public_id, organization_id, source_connection_id, provider, external_delivery_id,
          event_type, action, payload_digest, state, repository, ref, commit_sha,
          base_commit_sha, pull_request_number, forced, deleted, processed_at, created_at, updated_at
        ) VALUES (
          delivery_public_id, connection_row.organization_id, connection_row.id, 'github', delivery_id,
          delivery_event, NULLIF(delivery_action, ''), payload_sha256, processing_state,
          NULLIF(repository_name, ''), NULLIF(git_ref, ''), head_commit,
          base_commit, pr_number, was_forced, was_deleted,
          CASE WHEN processing_state IN ('processed', 'ignored') THEN clock_timestamp() END,
          clock_timestamp(), clock_timestamp()
        );

        UPDATE source_connections
        SET status = COALESCE(NULLIF(next_connection_status, ''), status),
            revoked_at = CASE
              WHEN next_connection_status = 'revoked' THEN clock_timestamp()
              WHEN next_connection_status = 'active' THEN NULL
              ELSE revoked_at
            END,
            provider_account_login = COALESCE(NULLIF(account_login, ''), provider_account_login),
            provider_account_id = COALESCE(account_id, provider_account_id),
            repository_selection = COALESCE(NULLIF(repository_selection_value, ''), repository_selection),
            selected_repositories = next_repositories,
            last_webhook_at = clock_timestamp(),
            updated_at = clock_timestamp()
        WHERE id = connection_row.id;

        IF repositories_mode = 'remove' THEN
          UPDATE project_source_bindings
          SET automatic_deployments = false,
              generation = generation + 1,
              updated_at = clock_timestamp()
          WHERE source_connection_id = connection_row.id
            AND repository IN (SELECT jsonb_array_elements_text(COALESCE(repository_values, '[]'::jsonb)));
        END IF;
        IF next_connection_status IN ('suspended', 'revoked') THEN
          UPDATE project_source_bindings
          SET automatic_deployments = false,
              generation = generation + 1,
              updated_at = clock_timestamp()
          WHERE source_connection_id = connection_row.id
            AND automatic_deployments = true;
          UPDATE source_provider_deliveries
          SET state = 'ignored',
              processed_at = clock_timestamp(),
              processing_token = NULL,
              processing_started_at = NULL,
              last_error = NULL,
              updated_at = clock_timestamp()
          WHERE source_connection_id = connection_row.id
            AND state IN ('received', 'failed');
        END IF;

        INSERT INTO outbox_events(
          public_id, organization_id, event_type, schema_version, resource_type,
          resource_public_id, resource_version, actor_type, actor_public_id, correlation_id, data,
          occurred_at, publish_attempts, organization_public_id, created_at, updated_at
        ) VALUES (
          event_public_id, connection_row.organization_id, 'source.provider.' || delivery_event, 1,
          'source_connection', connection_row.public_id, 1, 'system', NULL, request_id,
          jsonb_strip_nulls(jsonb_build_object(
            'delivery_id', delivery_id, 'event_type', delivery_event, 'action', NULLIF(delivery_action, ''),
            'repository', NULLIF(repository_name, ''), 'ref', NULLIF(git_ref, ''),
            'commit_sha', head_commit, 'base_commit_sha', base_commit,
            'pull_request_number', pr_number, 'forced', was_forced, 'deleted', was_deleted
          )),
          clock_timestamp(), 0, organization_public_id_value, clock_timestamp(), clock_timestamp()
        );

        INSERT INTO audit_events(
          public_id, organization_id, actor_type, authentication_method, action,
          resource_type, resource_public_id, request_id, outcome, policy_version,
          metadata, occurred_at
        ) VALUES (
          audit_public_id, connection_row.organization_id, 'system', 'provider_webhook',
          'source.provider.webhook', 'source_connection', connection_row.public_id,
          request_id, 'succeeded', '2026-07-12.v1',
          jsonb_build_object('delivery_id', delivery_id, 'event_type', delivery_event),
          clock_timestamp()
        );

        RETURN jsonb_build_object(
          'outcome', processing_state,
          'delivery_public_id', delivery_public_id,
          'organization_public_id', organization_public_id_value,
          'actor_public_id', actor_public_id_value,
          'work_pending', processing_state = 'received'
        );
      END;
      $$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;
      REVOKE ALL ON FUNCTION lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text) FROM PUBLIC;
    SQL
  end

  def create_provider_delivery_work_functions
    execute <<~SQL
      CREATE FUNCTION lrail_claim_github_provider_delivery(delivery_public_id text, lease_token text)
      RETURNS text AS $$
      DECLARE
        claimed_state text;
        current_state text;
      BEGIN
        IF delivery_public_id !~ '#{ID_PATTERN}' OR lease_token !~ '^[0-9A-Za-z-]{8,128}$' THEN
          RAISE EXCEPTION 'invalid provider delivery lease' USING ERRCODE = '22023';
        END IF;

        UPDATE source_provider_deliveries
        SET state = 'processing',
            attempt_count = CASE
              WHEN state = 'processing' AND processing_token = lease_token THEN attempt_count
              ELSE attempt_count + 1
            END,
            processing_token = lease_token,
            processing_started_at = clock_timestamp(),
            last_error = NULL,
            updated_at = clock_timestamp()
        WHERE public_id = delivery_public_id
          AND organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
          AND (
            state IN ('received', 'failed') OR
            (state = 'processing' AND (
              processing_token = lease_token OR processing_started_at < clock_timestamp() - interval '20 minutes'
            ))
          )
        RETURNING state INTO claimed_state;
        IF claimed_state IS NOT NULL THEN
          RETURN 'claimed';
        END IF;

        SELECT state INTO current_state
        FROM source_provider_deliveries
        WHERE public_id = delivery_public_id
          AND organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id);
        RETURN CASE
          WHEN current_state IN ('processed', 'ignored') THEN 'complete'
          WHEN current_state = 'processing' THEN 'busy'
          ELSE 'unknown'
        END;
      END;
      $$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;

      CREATE FUNCTION lrail_finish_github_provider_delivery(
        delivery_public_id text,
        lease_token text,
        succeeded boolean,
        error_code text
      ) RETURNS boolean AS $$
      DECLARE
        updated_id bigint;
      BEGIN
        IF delivery_public_id !~ '#{ID_PATTERN}' OR lease_token !~ '^[0-9A-Za-z-]{8,128}$'
           OR char_length(error_code) > 128 THEN
          RAISE EXCEPTION 'invalid provider delivery completion' USING ERRCODE = '22023';
        END IF;

        UPDATE source_provider_deliveries
        SET state = CASE WHEN succeeded THEN 'processed' ELSE 'failed' END,
            processed_at = CASE WHEN succeeded THEN clock_timestamp() ELSE NULL END,
            processing_token = NULL,
            processing_started_at = NULL,
            last_error = CASE WHEN succeeded THEN NULL ELSE NULLIF(error_code, '') END,
            updated_at = clock_timestamp()
        WHERE public_id = delivery_public_id
          AND organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
          AND state = 'processing'
          AND processing_token = lease_token
        RETURNING id INTO updated_id;
        RETURN updated_id IS NOT NULL;
      END;
      $$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;

      REVOKE ALL ON FUNCTION lrail_claim_github_provider_delivery(text, text) FROM PUBLIC;
      REVOKE ALL ON FUNCTION lrail_finish_github_provider_delivery(text, text, boolean, text) FROM PUBLIC;
    SQL
  end

  def configure_provider_delivery_role
    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")

    quoted_role = connection.quote_table_name(role)
    execute "GRANT SELECT, INSERT, UPDATE, DELETE ON source_fetches, project_source_bindings TO #{quoted_role}"
    execute "GRANT USAGE, SELECT ON source_fetches_id_seq, project_source_bindings_id_seq TO #{quoted_role}"
    execute "REVOKE ALL ON source_provider_deliveries FROM #{quoted_role}"
    execute "GRANT SELECT ON source_provider_deliveries TO #{quoted_role}"
    execute "REVOKE ALL ON source_provider_deliveries_id_seq FROM #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_apply_github_provider_delivery(text, text, text, text, text, text, text, text, text, integer, boolean, boolean, text, text, text, bigint, text, text, jsonb, text, text, text, text) TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_claim_github_provider_delivery(text, text) TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_finish_github_provider_delivery(text, text, boolean, text) TO #{quoted_role}"
  end
end
