class CreateControlPlaneCore < ActiveRecord::Migration[8.1]
  RESOURCE_ID_PATTERN = "^[a-z]{2,5}_[0-9a-f-]{36}$"
  ORGANIZATION_SCOPED_TABLES = %i[
    projects environments services service_routes source_connections source_snapshots builds build_steps
    revisions attestations operations deployments deployment_transitions releases release_targets
    rollout_steps domains ownership_challenges dns_changes certificates edge_route_versions addons
    addon_backups attachments credential_versions api_keys oauth_clients webhooks webhook_deliveries
    schedules outbox_events workflow_runs idempotency_keys audit_events usage_ledger email_intents
  ].freeze

  def change
    add_column :accounts, :public_id, :string, null: false
    add_column :accounts, :display_name, :string, null: false, default: "Developer"
    add_timestamps :accounts, null: true
    add_index :accounts, :public_id, unique: true
    add_check_constraint :accounts, "public_id ~ '#{RESOURCE_ID_PATTERN}'", name: "accounts_public_id_format"

    create_identity_tables
    create_project_tables
    create_delivery_tables
    create_edge_tables
    create_data_tables
    create_automation_tables
    create_reliability_tables

    reversible do |direction|
      direction.up do
        create_tenant_policies
        create_append_only_guards
        create_membership_owner_guard
        grant_runtime_role
      end
      direction.down do
        execute "DROP FUNCTION IF EXISTS lrail_block_mutation()"
        execute "DROP FUNCTION IF EXISTS lrail_membership_owner_guard()"
        execute "DROP FUNCTION IF EXISTS lrail_account_has_membership(bigint)"
      end
    end
  end

  private

  def create_identity_tables
    create_table :organizations do |t|
      resource_id t, :org
      t.references :created_by_account, null: false, foreign_key: { to_table: :accounts }
      t.string :slug, null: false, limit: 63
      t.string :name, null: false, limit: 100
      t.string :plan, null: false, default: "free"
      t.boolean :personal, null: false, default: false
      t.integer :lock_version, null: false, default: 0
      t.datetime :deletion_requested_at
      t.datetime :retention_until
      t.timestamps
      t.index :slug, unique: true
      t.check_constraint "slug ~ '^[a-z][a-z0-9-]{0,62}$'", name: "organizations_slug_format"
      t.check_constraint "plan IN ('free', 'pro', 'enterprise')", name: "organizations_plan"
    end

    create_table :memberships do |t|
      resource_id t, :mbr
      t.references :account, null: false, foreign_key: { on_delete: :cascade }
      t.references :organization, null: false, foreign_key: { on_delete: :cascade }
      t.string :role, null: false
      t.string :status, null: false, default: "active"
      t.datetime :revoked_at
      t.timestamps
      t.index %i[account_id organization_id], unique: true
      t.check_constraint "role IN ('owner', 'admin', 'developer', 'operator', 'billing', 'auditor')", name: "memberships_role"
      t.check_constraint "status IN ('active', 'suspended', 'revoked')", name: "memberships_status"
    end

    create_table :invitations do |t|
      resource_id t, :inv
      t.references :organization, null: false, foreign_key: { on_delete: :cascade }
      t.references :inviter, null: false, foreign_key: { to_table: :accounts }
      t.citext :email, null: false
      t.string :role, null: false
      t.string :token_digest, null: false
      t.datetime :expires_at, null: false
      t.datetime :accepted_at
      t.datetime :revoked_at
      t.timestamps
      t.index %i[organization_id email], unique: true, where: "accepted_at IS NULL AND revoked_at IS NULL"
      t.index :token_digest, unique: true
    end
  end

  def create_project_tables
    create_table :projects do |t|
      resource_id t, :prj
      tenant_reference t
      t.string :slug, null: false, limit: 63
      t.string :name, null: false, limit: 100
      t.text :description
      t.string :status, null: false, default: "healthy"
      t.integer :manifest_revision, null: false, default: 1
      t.jsonb :manifest, null: false, default: {}
      t.integer :lock_version, null: false, default: 0
      t.datetime :deletion_requested_at
      t.datetime :retention_until
      t.timestamps
      t.index %i[organization_id slug], unique: true
      t.check_constraint "status IN ('healthy', 'degraded', 'deploying', 'paused')", name: "projects_status"
    end

    create_table :environments do |t|
      resource_id t, :env
      tenant_reference t
      t.references :project, null: false, foreign_key: { on_delete: :cascade }
      t.string :slug, null: false, limit: 63
      t.string :name, null: false, limit: 100
      t.boolean :protected, null: false, default: false
      t.bigint :generation, null: false, default: 1
      t.string :health, null: false, default: "unknown"
      t.integer :lock_version, null: false, default: 0
      t.timestamps
      t.index %i[project_id slug], unique: true
      t.check_constraint "generation > 0", name: "environments_generation"
      t.check_constraint "health IN ('healthy', 'degraded', 'deploying', 'paused', 'unknown')", name: "environments_health"
    end

    create_table :services do |t|
      resource_id t, :svc
      tenant_reference t
      t.references :project, null: false, foreign_key: { on_delete: :cascade }
      t.string :slug, null: false, limit: 63
      t.string :name, null: false, limit: 100
      t.string :kind, null: false
      t.string :framework
      t.string :health, null: false, default: "unknown"
      t.jsonb :build_specification, null: false, default: {}
      t.jsonb :runtime_specification, null: false, default: {}
      t.integer :lock_version, null: false, default: 0
      t.timestamps
      t.index %i[project_id slug], unique: true
      t.check_constraint "kind IN ('web', 'worker', 'private_service', 'static')", name: "services_kind"
      t.check_constraint "health IN ('healthy', 'degraded', 'deploying', 'paused', 'unknown')", name: "services_health"
    end

    create_table :service_routes do |t|
      resource_id t, :rte
      tenant_reference t
      t.references :service, null: false, foreign_key: { on_delete: :cascade }
      t.references :environment, null: false, foreign_key: { on_delete: :cascade }
      t.string :hostname
      t.string :path_prefix, null: false, default: "/"
      t.string :protocol, null: false, default: "https"
      t.integer :priority, null: false, default: 0
      t.timestamps
      t.index %i[environment_id hostname path_prefix], unique: true, name: "service_routes_unique_match"
    end
  end

  def create_delivery_tables
    create_table :source_connections do |t|
      resource_id t, :src
      tenant_reference t
      t.string :provider, null: false
      t.string :installation_external_id, null: false
      t.string :status, null: false, default: "active"
      t.jsonb :scopes, null: false, default: []
      t.datetime :last_webhook_at
      t.timestamps
      t.index %i[organization_id provider installation_external_id], unique: true, name: "source_connections_provider_identity"
    end

    create_table :source_snapshots do |t|
      resource_id t, :snp
      tenant_reference t
      t.references :project, null: false, foreign_key: { on_delete: :cascade }
      t.references :source_connection, foreign_key: true
      t.string :kind, null: false
      t.string :repository
      t.string :commit_sha
      t.string :digest, null: false
      t.string :object_ref, null: false
      t.bigint :size_bytes, null: false
      t.datetime :retention_until, null: false
      t.timestamps
      t.index :digest, unique: true
      t.check_constraint "size_bytes >= 0", name: "source_snapshots_size"
    end

    create_table :builds do |t|
      resource_id t, :bld
      tenant_reference t
      t.references :source_snapshot, null: false, foreign_key: true
      t.string :definition_digest, null: false
      t.string :state, null: false, default: "accepted"
      t.string :network_profile, null: false, default: "none"
      t.string :artifact_digest
      t.datetime :started_at
      t.datetime :completed_at
      t.timestamps
      t.index %i[organization_id definition_digest]
    end

    create_table :build_steps do |t|
      tenant_reference t
      t.references :build, null: false, foreign_key: { on_delete: :cascade }
      t.integer :position, null: false
      t.string :name, null: false
      t.string :state, null: false
      t.string :failure_code
      t.datetime :started_at
      t.datetime :completed_at
      t.index %i[build_id position], unique: true
    end

    create_table :revisions do |t|
      resource_id t, :rev
      tenant_reference t
      t.references :service, null: false, foreign_key: true
      t.references :build, null: false, foreign_key: true
      t.string :image_digest, null: false
      t.string :manifest_digest, null: false
      t.string :sbom_ref, null: false
      t.string :provenance_ref, null: false
      t.string :signature_ref, null: false
      t.string :scan_state, null: false
      t.string :policy_state, null: false
      t.timestamps
      t.index :image_digest, unique: true
      t.index :manifest_digest, unique: true
    end

    create_table :attestations do |t|
      tenant_reference t
      t.references :revision, null: false, foreign_key: { on_delete: :cascade }
      t.string :kind, null: false
      t.string :digest, null: false
      t.string :object_ref, null: false
      t.timestamps
      t.index %i[revision_id kind], unique: true
    end

    create_table :operations do |t|
      resource_id t, :op
      tenant_reference t
      t.string :resource_type, null: false
      t.string :resource_public_id, null: false
      t.string :state, null: false, default: "accepted"
      t.string :stage, null: false, default: "accepted"
      t.integer :completed_steps, null: false, default: 0
      t.integer :total_steps, null: false, default: 0
      t.text :waiting_reason
      t.string :error_code
      t.text :error_message
      t.jsonb :conditions, null: false, default: []
      t.string :workflow_id
      t.timestamps
      t.index %i[organization_id resource_type resource_public_id]
      t.index :workflow_id, unique: true, where: "workflow_id IS NOT NULL"
      t.check_constraint "state IN ('accepted', 'running', 'waiting', 'retrying', 'succeeded', 'failed', 'canceling', 'canceled')", name: "operations_state"
    end

    create_table :deployments do |t|
      resource_id t, :dep
      tenant_reference t
      t.references :project, null: false, foreign_key: true
      t.references :environment, null: false, foreign_key: true
      t.references :source_snapshot, foreign_key: true
      t.references :revision, foreign_key: true
      t.references :operation, null: false, foreign_key: true
      t.string :state, null: false, default: "created"
      t.jsonb :source, null: false, default: {}
      t.integer :manifest_revision, null: false
      t.text :reason, null: false
      t.integer :lock_version, null: false, default: 0
      t.datetime :ready_at
      t.datetime :promoted_at
      t.datetime :canceled_at
      t.timestamps
      t.index %i[project_id created_at]
      t.check_constraint "jsonb_typeof(source) = 'object'", name: "deployments_source_object"
      t.check_constraint "state IN ('created', 'sourcing', 'detecting', 'queued', 'building', 'scanning', 'publishing', 'scheduling', 'starting', 'verifying', 'ready', 'promoted', 'canceling', 'canceled', 'failed', 'retrying')", name: "deployments_state"
    end

    create_table :deployment_transitions do |t|
      tenant_reference t
      t.references :deployment, null: false, foreign_key: { on_delete: :cascade }
      t.string :from_state
      t.string :to_state, null: false
      t.string :reason, null: false
      t.string :actor_type, null: false
      t.string :actor_public_id
      t.string :correlation_id, null: false
      t.jsonb :metadata, null: false, default: {}
      t.datetime :created_at, null: false
      t.index %i[deployment_id created_at]
    end

    create_table :releases do |t|
      resource_id t, :rel
      tenant_reference t
      t.references :service, null: false, foreign_key: true
      t.references :environment, null: false, foreign_key: true
      t.references :revision, null: false, foreign_key: true
      t.references :deployment, foreign_key: true
      t.bigint :generation, null: false
      t.string :state, null: false, default: "draft"
      t.string :rollout_policy, null: false, default: "default_canary"
      t.integer :traffic_weight, null: false, default: 0
      t.datetime :activated_at
      t.timestamps
      t.index %i[service_id environment_id generation], unique: true, name: "releases_monotonic_generation"
      t.check_constraint "traffic_weight BETWEEN 0 AND 100", name: "releases_traffic_weight"
      t.check_constraint "state IN ('draft', 'policy_check', 'provisioning', 'previewing', 'shifting', 'verifying', 'active', 'paused', 'aborting', 'rolled_back', 'superseded', 'retired')", name: "releases_state"
    end

    add_reference :services, :current_release, foreign_key: { to_table: :releases }

    create_table :release_targets do |t|
      tenant_reference t
      t.references :release, null: false, foreign_key: { on_delete: :cascade }
      t.string :cell_public_id, null: false
      t.string :region, null: false
      t.bigint :desired_generation, null: false
      t.bigint :observed_generation
      t.string :state, null: false, default: "pending"
      t.jsonb :conditions, null: false, default: []
      t.timestamps
      t.index %i[release_id cell_public_id], unique: true
    end

    create_table :rollout_steps do |t|
      tenant_reference t
      t.references :release, null: false, foreign_key: { on_delete: :cascade }
      t.integer :position, null: false
      t.integer :traffic_weight, null: false
      t.integer :duration_seconds, null: false
      t.string :state, null: false, default: "pending"
      t.jsonb :analysis, null: false, default: {}
      t.timestamps
      t.index %i[release_id position], unique: true
    end
  end

  def create_edge_tables
    create_table :domains do |t|
      resource_id t, :dom
      tenant_reference t
      t.references :project, null: false, foreign_key: true
      t.references :environment, null: false, foreign_key: true
      t.references :service, null: false, foreign_key: true
      t.citext :hostname, null: false
      t.string :mode, null: false
      t.string :state, null: false, default: "requested"
      t.datetime :verified_at
      t.datetime :revalidation_due_at
      t.integer :lock_version, null: false, default: 0
      t.timestamps
      t.index :hostname, unique: true, where: "state NOT IN ('released', 'expired')"
    end

    create_table :ownership_challenges do |t|
      tenant_reference t
      t.references :domain, null: false, foreign_key: { on_delete: :cascade }
      t.string :record_name, null: false
      t.binary :verifier, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at
      t.jsonb :evidence, null: false, default: {}
      t.timestamps
      t.index %i[domain_id expires_at]
    end

    create_table :dns_changes do |t|
      tenant_reference t
      t.references :domain, null: false, foreign_key: { on_delete: :cascade }
      t.string :operation_id, null: false
      t.bigint :generation, null: false
      t.string :previous_fingerprint
      t.jsonb :records, null: false
      t.string :state, null: false, default: "pending"
      t.timestamps
      t.index :operation_id, unique: true
    end

    create_table :certificates do |t|
      resource_id t, :crt
      tenant_reference t
      t.references :domain, null: false, foreign_key: { on_delete: :cascade }
      t.string :state, null: false, default: "pending"
      t.string :key_id
      t.string :fingerprint
      t.jsonb :sans, null: false, default: []
      t.datetime :not_before
      t.datetime :not_after
      t.datetime :renewal_due_at
      t.timestamps
      t.index :fingerprint, unique: true, where: "fingerprint IS NOT NULL"
    end

    create_table :edge_route_versions do |t|
      tenant_reference t
      t.references :domain, null: false, foreign_key: { on_delete: :cascade }
      t.references :release, null: false, foreign_key: true
      t.string :edge_generation_public_id, null: false
      t.string :canonical_digest, null: false
      t.string :state, null: false, default: "staged"
      t.jsonb :conditions, null: false, default: []
      t.timestamps
      t.index :edge_generation_public_id, unique: true
    end
  end

  def create_data_tables
    create_table :addons do |t|
      resource_id t, :add
      tenant_reference t
      t.references :project, null: false, foreign_key: true
      t.references :environment, null: false, foreign_key: true
      t.string :name, null: false
      t.string :engine, null: false
      t.string :version_channel, null: false
      t.string :topology, null: false
      t.string :size_profile, null: false
      t.string :storage_profile, null: false
      t.string :region, null: false
      t.string :state, null: false, default: "requested"
      t.boolean :deletion_protection, null: false, default: true
      t.jsonb :conditions, null: false, default: []
      t.string :provider_resource_id
      t.integer :lock_version, null: false, default: 0
      t.timestamps
      t.index %i[environment_id name], unique: true
      t.index %i[engine provider_resource_id], unique: true, where: "provider_resource_id IS NOT NULL"
    end

    create_table :addon_backups do |t|
      resource_id t, :bkp
      tenant_reference t
      t.references :addon, null: false, foreign_key: { on_delete: :cascade }
      t.string :kind, null: false
      t.string :state, null: false, default: "pending"
      t.datetime :started_at
      t.datetime :completed_at
      t.datetime :restorable_from
      t.datetime :restorable_until
      t.string :encryption_key_id
      t.string :digest
      t.bigint :size_bytes
      t.jsonb :object_locations, null: false, default: []
      t.timestamps
    end

    create_table :attachments do |t|
      resource_id t, :att
      tenant_reference t
      t.references :addon, null: false, foreign_key: { on_delete: :cascade }
      t.references :service, null: false, foreign_key: { on_delete: :cascade }
      t.references :environment, null: false, foreign_key: { on_delete: :cascade }
      t.string :name, null: false
      t.bigint :credential_version, null: false
      t.string :state, null: false, default: "pending"
      t.timestamps
      t.index %i[environment_id name], unique: true
    end

    create_table :credential_versions do |t|
      tenant_reference t
      t.references :addon, null: false, foreign_key: { on_delete: :cascade }
      t.bigint :version, null: false
      t.string :secret_public_id, null: false
      t.string :state, null: false, default: "next"
      t.datetime :issued_at, null: false
      t.datetime :revoked_at
      t.timestamps
      t.index %i[addon_id version], unique: true
    end
  end

  def create_automation_tables
    create_table :api_keys do |t|
      resource_id t, :key
      tenant_reference t
      t.references :account, foreign_key: true
      t.string :name, null: false
      t.string :prefix, null: false
      t.string :secret_digest, null: false
      t.jsonb :scopes, null: false, default: []
      t.jsonb :constraints, null: false, default: {}
      t.datetime :expires_at
      t.datetime :last_used_at
      t.datetime :revoked_at
      t.timestamps
      t.index :prefix, unique: true
      t.index :secret_digest, unique: true
    end

    create_table :oauth_clients do |t|
      resource_id t, :key
      tenant_reference t
      t.string :name, null: false
      t.string :client_digest, null: false
      t.jsonb :redirect_uris, null: false, default: []
      t.jsonb :scopes, null: false, default: []
      t.datetime :revoked_at
      t.timestamps
      t.index :client_digest, unique: true
    end

    create_table :webhooks do |t|
      resource_id t, :wh
      tenant_reference t
      t.references :project, foreign_key: true
      t.string :url, null: false
      t.string :state, null: false, default: "verification_pending"
      t.jsonb :event_types, null: false, default: []
      t.string :secret_digest, null: false
      t.integer :signature_version, null: false, default: 1
      t.datetime :verified_at
      t.timestamps
    end

    create_table :webhook_deliveries do |t|
      resource_id t, :whd
      tenant_reference t
      t.references :webhook, null: false, foreign_key: { on_delete: :cascade }
      t.string :event_public_id, null: false
      t.integer :attempt, null: false, default: 1
      t.string :state, null: false, default: "pending"
      t.integer :response_status
      t.datetime :next_attempt_at
      t.datetime :completed_at
      t.timestamps
      t.index %i[webhook_id event_public_id attempt], unique: true, name: "webhook_delivery_attempt"
    end

    create_table :schedules do |t|
      resource_id t, :sch
      tenant_reference t
      t.references :project, null: false, foreign_key: true
      t.references :environment, null: false, foreign_key: true
      t.string :name, null: false
      t.string :expression, null: false
      t.string :timezone, null: false
      t.string :overlap_policy, null: false
      t.jsonb :target, null: false
      t.jsonb :retry_policy, null: false, default: {}
      t.boolean :enabled, null: false, default: true
      t.datetime :next_run_at
      t.timestamps
      t.index %i[environment_id name], unique: true
      t.index :next_run_at, where: "enabled = true"
    end
  end

  def create_reliability_tables
    create_table :outbox_events do |t|
      resource_id t, :evt
      tenant_reference t
      t.string :event_type, null: false
      t.integer :schema_version, null: false, default: 1
      t.string :resource_type, null: false
      t.string :resource_public_id, null: false
      t.bigint :resource_version, null: false
      t.string :actor_type, null: false
      t.string :actor_public_id
      t.string :correlation_id, null: false
      t.string :causation_id
      t.string :traceparent
      t.jsonb :data, null: false, default: {}
      t.datetime :occurred_at, null: false
      t.datetime :published_at
      t.integer :publish_attempts, null: false, default: 0
      t.text :publish_error
      t.timestamps
      t.index %i[published_at occurred_at], name: "outbox_unpublished_age"
    end

    create_table :workflow_runs do |t|
      tenant_reference t
      t.string :workflow_id, null: false
      t.string :workflow_type, null: false
      t.string :resource_public_id, null: false
      t.string :state, null: false, default: "accepted"
      t.string :run_id
      t.jsonb :conditions, null: false, default: []
      t.datetime :started_at
      t.datetime :completed_at
      t.timestamps
      t.index :workflow_id, unique: true
    end

    create_table :idempotency_keys do |t|
      tenant_reference t
      t.string :principal_public_id, null: false
      t.string :http_method, null: false
      t.string :normalized_route, null: false
      t.string :key_digest, null: false
      t.string :request_fingerprint, null: false
      t.string :command_public_id
      t.integer :response_status
      t.jsonb :response_body
      t.datetime :expires_at, null: false
      t.timestamps
      t.index %i[organization_id principal_public_id http_method normalized_route key_digest], unique: true, name: "idempotency_scope_unique"
      t.index :expires_at
    end

    create_table :audit_events do |t|
      resource_id t, :evt
      tenant_reference t
      t.string :actor_type, null: false
      t.string :actor_public_id
      t.string :authentication_method
      t.string :action, null: false
      t.string :reason
      t.string :resource_type, null: false
      t.string :resource_public_id, null: false
      t.string :before_fingerprint
      t.string :after_fingerprint
      t.string :request_id, null: false
      t.string :trace_id
      t.string :workflow_id
      t.string :incident_public_id
      t.string :ip_prefix
      t.string :device_summary
      t.string :outcome, null: false
      t.string :policy_version, null: false
      t.jsonb :metadata, null: false, default: {}
      t.datetime :occurred_at, null: false
      t.index %i[organization_id occurred_at]
      t.index %i[resource_type resource_public_id occurred_at], name: "audit_resource_timeline"
    end

    create_table :usage_ledger do |t|
      resource_id t, :use
      tenant_reference t
      t.string :meter_type, null: false
      t.bigint :quantity, null: false
      t.string :unit, null: false
      t.datetime :period_start, null: false
      t.datetime :period_end, null: false
      t.string :resource_public_id, null: false
      t.string :source_id, null: false
      t.string :source_epoch, null: false
      t.bigint :sequence, null: false
      t.string :correlation_id, null: false
      t.string :correction_of_public_id
      t.jsonb :meter_attributes, null: false, default: {}
      t.timestamps
      t.index %i[source_id source_epoch sequence], unique: true, name: "usage_source_sequence"
      t.index %i[organization_id period_start meter_type], name: "usage_period_meter"
      t.check_constraint "period_end > period_start", name: "usage_period_order"
      t.check_constraint "quantity <> 0", name: "usage_nonzero"
    end

    create_table :email_intents do |t|
      resource_id t, :evt
      tenant_reference t
      t.references :account, foreign_key: true
      t.string :template, null: false
      t.integer :template_version, null: false
      t.citext :recipient, null: false
      t.string :locale, null: false, default: "en"
      t.jsonb :data, null: false, default: {}
      t.jsonb :tags, null: false, default: {}
      t.string :idempotency_key, null: false
      t.string :state, null: false, default: "pending"
      t.string :provider_message_id
      t.datetime :next_attempt_at
      t.datetime :delivered_at
      t.timestamps
      t.index :idempotency_key, unique: true
      t.index %i[state next_attempt_at]
    end
  end

  def create_tenant_policies
    execute <<~SQL
      CREATE FUNCTION lrail_account_has_membership(target_organization_id bigint)
      RETURNS boolean AS $$
        SELECT EXISTS (
          SELECT 1 FROM memberships
          WHERE organization_id = target_organization_id
            AND account_id::text = current_setting('lrail.account_id', true)
            AND status = 'active'
        );
      $$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp;
      REVOKE ALL ON FUNCTION lrail_account_has_membership(bigint) FROM PUBLIC;
    SQL

    execute <<~SQL
      ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
      ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
      CREATE POLICY organizations_tenant_policy ON organizations
      USING (
        (
          id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(id)
        )
        OR created_by_account_id::text = current_setting('lrail.account_id', true)
      )
      WITH CHECK (created_by_account_id::text = current_setting('lrail.account_id', true));
    SQL

    execute <<~SQL
      ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
      ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
      CREATE POLICY memberships_tenant_policy ON memberships
      USING (
        account_id::text = current_setting('lrail.account_id', true)
        OR (
          organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
        )
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND (
          lrail_account_has_membership(organization_id)
          OR (
            account_id::text = current_setting('lrail.account_id', true)
            AND role = 'owner'
            AND EXISTS (
              SELECT 1 FROM organizations
              WHERE organizations.id = organization_id
                AND organizations.created_by_account_id::text = current_setting('lrail.account_id', true)
            )
          )
        )
      );
    SQL

    execute <<~SQL
      ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
      ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
      CREATE POLICY invitations_tenant_policy ON invitations
      USING (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      )
      WITH CHECK (
        organization_id::text = current_setting('lrail.organization_id', true)
        AND lrail_account_has_membership(organization_id)
      );
    SQL

    ORGANIZATION_SCOPED_TABLES.each do |table|
      execute <<~SQL
        ALTER TABLE #{table} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE #{table} FORCE ROW LEVEL SECURITY;
        CREATE POLICY #{table}_tenant_policy ON #{table}
        USING (
          organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
        )
        WITH CHECK (
          organization_id::text = current_setting('lrail.organization_id', true)
          AND lrail_account_has_membership(organization_id)
        );
      SQL
    end
  end

  def create_append_only_guards
    execute <<~SQL
      CREATE FUNCTION lrail_block_mutation() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
      END;
      $$ LANGUAGE plpgsql;
    SQL

    %i[deployment_transitions audit_events usage_ledger].each do |table|
      execute <<~SQL
        CREATE TRIGGER #{table}_append_only
        BEFORE UPDATE OR DELETE ON #{table}
        FOR EACH ROW EXECUTE FUNCTION lrail_block_mutation();
      SQL
    end
  end

  def create_membership_owner_guard
    execute <<~SQL
      CREATE FUNCTION lrail_membership_owner_guard() RETURNS trigger AS $$
      BEGIN
        IF OLD.role = 'owner' AND OLD.status = 'active'
           AND (TG_OP = 'DELETE' OR NEW.role <> 'owner' OR NEW.status <> 'active')
           AND NOT EXISTS (
             SELECT 1 FROM memberships
             WHERE organization_id = OLD.organization_id
               AND role = 'owner' AND status = 'active' AND id <> OLD.id
           ) THEN
          RAISE EXCEPTION 'organization must retain an active owner' USING ERRCODE = '23514';
        END IF;
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
      END;
      $$ LANGUAGE plpgsql;

      CREATE TRIGGER memberships_owner_guard
      BEFORE UPDATE OR DELETE ON memberships
      FOR EACH ROW EXECUTE FUNCTION lrail_membership_owner_guard();
    SQL
  end

  def grant_runtime_role
    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")

    quoted_role = connection.quote_table_name(role)
    execute "GRANT USAGE ON SCHEMA public TO #{quoted_role}"
    execute "GRANT EXECUTE ON FUNCTION lrail_account_has_membership(bigint) TO #{quoted_role}"
    execute "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO #{quoted_role}"
    execute "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO #{quoted_role}"
    execute "REVOKE ALL ON account_password_hashes FROM #{quoted_role}"
    execute "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{quoted_role}"
    execute "GRANT SELECT (id) ON account_password_hashes TO #{quoted_role}"
    execute "REVOKE ALL ON account_previous_password_hashes FROM #{quoted_role}"
    execute "GRANT INSERT, UPDATE, DELETE ON account_previous_password_hashes TO #{quoted_role}"
    execute "GRANT SELECT (id, account_id) ON account_previous_password_hashes TO #{quoted_role}"
  end

  def resource_id(table, _prefix)
    table.string :public_id, null: false, limit: 64
    table.index :public_id, unique: true
    table.check_constraint "public_id ~ '#{RESOURCE_ID_PATTERN}'", name: "#{table.name}_public_id_format"
  end

  def tenant_reference(table)
    table.references :organization, null: false, foreign_key: { on_delete: :cascade }
  end
end
