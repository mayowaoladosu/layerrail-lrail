# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_07_12_204512) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "citext"
  enable_extension "pg_catalog.plpgsql"

  create_table "account_active_session_keys", primary_key: ["account_id", "session_id"], force: :cascade do |t|
    t.bigint "account_id", null: false
    t.datetime "created_at", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.datetime "last_use", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.string "session_id", null: false
    t.index ["account_id"], name: "index_account_active_session_keys_on_account_id"
  end

  create_table "account_authentication_audit_logs", force: :cascade do |t|
    t.bigint "account_id", null: false
    t.datetime "at", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.text "message", null: false
    t.jsonb "metadata"
    t.index ["account_id", "at"], name: "index_account_authentication_audit_logs_on_account_id_and_at"
    t.index ["account_id"], name: "index_account_authentication_audit_logs_on_account_id"
    t.index ["at"], name: "index_account_authentication_audit_logs_on_at"
  end

  create_table "account_lockouts", force: :cascade do |t|
    t.datetime "deadline", null: false
    t.datetime "email_last_sent"
    t.string "key", null: false
  end

  create_table "account_login_change_keys", force: :cascade do |t|
    t.datetime "deadline", null: false
    t.string "key", null: false
    t.string "login", null: false
  end

  create_table "account_login_failures", force: :cascade do |t|
    t.integer "number", default: 1, null: false
  end

  create_table "account_otp_keys", force: :cascade do |t|
    t.string "key", null: false
    t.datetime "last_use", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.integer "num_failures", default: 0, null: false
  end

  create_table "account_password_hashes", force: :cascade do |t|
    t.string "password_hash", null: false
  end

  create_table "account_password_reset_keys", force: :cascade do |t|
    t.datetime "deadline", null: false
    t.datetime "email_last_sent", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.string "key", null: false
  end

  create_table "account_previous_password_hashes", force: :cascade do |t|
    t.bigint "account_id"
    t.string "password_hash", null: false
    t.index ["account_id"], name: "index_account_previous_password_hashes_on_account_id"
  end

  create_table "account_recovery_codes", primary_key: ["id", "code"], force: :cascade do |t|
    t.string "code", null: false
    t.bigint "id", null: false
  end

  create_table "account_remember_keys", force: :cascade do |t|
    t.datetime "deadline", null: false
    t.string "key", null: false
  end

  create_table "account_verification_keys", force: :cascade do |t|
    t.datetime "email_last_sent", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.string "key", null: false
    t.datetime "requested_at", default: -> { "CURRENT_TIMESTAMP" }, null: false
  end

  create_table "account_webauthn_keys", primary_key: ["account_id", "webauthn_id"], force: :cascade do |t|
    t.bigint "account_id", null: false
    t.datetime "last_use", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.string "public_key", null: false
    t.integer "sign_count", null: false
    t.string "webauthn_id", null: false
    t.index ["account_id"], name: "index_account_webauthn_keys_on_account_id"
  end

  create_table "account_webauthn_user_ids", force: :cascade do |t|
    t.string "webauthn_id", null: false
  end

  create_table "accounts", force: :cascade do |t|
    t.datetime "created_at"
    t.string "display_name", default: "Developer", null: false
    t.citext "email", null: false
    t.string "public_id", null: false
    t.integer "status", default: 1, null: false
    t.datetime "updated_at"
    t.index ["email"], name: "index_accounts_on_email", unique: true, where: "(status = ANY (ARRAY[1, 2]))"
    t.index ["public_id"], name: "index_accounts_on_public_id", unique: true
    t.check_constraint "email ~ '^[^,;@ \r\n]+@[^,@; \r\n]+.[^,@; \r\n]+$'::citext", name: "valid_email"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "accounts_public_id_format"
  end

  create_table "addon_backups", force: :cascade do |t|
    t.bigint "addon_id", null: false
    t.datetime "completed_at"
    t.datetime "created_at", null: false
    t.string "digest"
    t.string "encryption_key_id"
    t.string "kind", null: false
    t.jsonb "object_locations", default: [], null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "restorable_from"
    t.datetime "restorable_until"
    t.bigint "size_bytes"
    t.datetime "started_at"
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["addon_id"], name: "index_addon_backups_on_addon_id"
    t.index ["organization_id"], name: "index_addon_backups_on_organization_id"
    t.index ["public_id"], name: "index_addon_backups_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "addon_backups_public_id_format"
  end

  create_table "addons", force: :cascade do |t|
    t.jsonb "conditions", default: [], null: false
    t.datetime "created_at", null: false
    t.boolean "deletion_protection", default: true, null: false
    t.string "engine", null: false
    t.bigint "environment_id", null: false
    t.integer "lock_version", default: 0, null: false
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.string "provider_resource_id"
    t.string "public_id", limit: 64, null: false
    t.string "region", null: false
    t.string "size_profile", null: false
    t.string "state", default: "requested", null: false
    t.string "storage_profile", null: false
    t.string "topology", null: false
    t.datetime "updated_at", null: false
    t.string "version_channel", null: false
    t.index ["engine", "provider_resource_id"], name: "index_addons_on_engine_and_provider_resource_id", unique: true, where: "(provider_resource_id IS NOT NULL)"
    t.index ["environment_id", "name"], name: "index_addons_on_environment_id_and_name", unique: true
    t.index ["environment_id"], name: "index_addons_on_environment_id"
    t.index ["organization_id"], name: "index_addons_on_organization_id"
    t.index ["project_id"], name: "index_addons_on_project_id"
    t.index ["public_id"], name: "index_addons_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "addons_public_id_format"
  end

  create_table "api_keys", force: :cascade do |t|
    t.bigint "account_id"
    t.jsonb "constraints", default: {}, null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at"
    t.datetime "last_used_at"
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.string "prefix", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "revoked_at"
    t.jsonb "scopes", default: [], null: false
    t.string "secret_digest", null: false
    t.datetime "updated_at", null: false
    t.index ["account_id"], name: "index_api_keys_on_account_id"
    t.index ["organization_id"], name: "index_api_keys_on_organization_id"
    t.index ["prefix"], name: "index_api_keys_on_prefix", unique: true
    t.index ["public_id"], name: "index_api_keys_on_public_id", unique: true
    t.index ["secret_digest"], name: "index_api_keys_on_secret_digest", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "api_keys_public_id_format"
  end

  create_table "attachments", force: :cascade do |t|
    t.bigint "addon_id", null: false
    t.datetime "created_at", null: false
    t.bigint "credential_version", null: false
    t.bigint "environment_id", null: false
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.bigint "service_id", null: false
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["addon_id"], name: "index_attachments_on_addon_id"
    t.index ["environment_id", "name"], name: "index_attachments_on_environment_id_and_name", unique: true
    t.index ["environment_id"], name: "index_attachments_on_environment_id"
    t.index ["organization_id"], name: "index_attachments_on_organization_id"
    t.index ["public_id"], name: "index_attachments_on_public_id", unique: true
    t.index ["service_id"], name: "index_attachments_on_service_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "attachments_public_id_format"
  end

  create_table "attestations", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "digest", null: false
    t.string "kind", null: false
    t.string "object_ref", null: false
    t.bigint "organization_id", null: false
    t.bigint "revision_id", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_attestations_on_organization_id"
    t.index ["revision_id", "kind"], name: "index_attestations_on_revision_id_and_kind", unique: true
    t.index ["revision_id"], name: "index_attestations_on_revision_id"
  end

  create_table "audit_events", force: :cascade do |t|
    t.string "action", null: false
    t.string "actor_public_id"
    t.string "actor_type", null: false
    t.string "after_fingerprint"
    t.string "authentication_method"
    t.string "before_fingerprint"
    t.string "device_summary"
    t.string "incident_public_id"
    t.string "ip_prefix"
    t.jsonb "metadata", default: {}, null: false
    t.datetime "occurred_at", null: false
    t.bigint "organization_id", null: false
    t.string "outcome", null: false
    t.string "policy_version", null: false
    t.string "public_id", limit: 64, null: false
    t.string "reason"
    t.string "request_id", null: false
    t.string "resource_public_id", null: false
    t.string "resource_type", null: false
    t.string "trace_id"
    t.string "workflow_id"
    t.index ["organization_id", "occurred_at"], name: "index_audit_events_on_organization_id_and_occurred_at"
    t.index ["organization_id"], name: "index_audit_events_on_organization_id"
    t.index ["public_id"], name: "index_audit_events_on_public_id", unique: true
    t.index ["resource_type", "resource_public_id", "occurred_at"], name: "audit_resource_timeline"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "audit_events_public_id_format"
  end

  create_table "build_steps", force: :cascade do |t|
    t.bigint "build_id", null: false
    t.datetime "completed_at"
    t.string "failure_code"
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.integer "position", null: false
    t.datetime "started_at"
    t.string "state", null: false
    t.index ["build_id", "position"], name: "index_build_steps_on_build_id_and_position", unique: true
    t.index ["build_id"], name: "index_build_steps_on_build_id"
    t.index ["organization_id"], name: "index_build_steps_on_organization_id"
  end

  create_table "builds", force: :cascade do |t|
    t.string "artifact_digest"
    t.datetime "completed_at"
    t.datetime "created_at", null: false
    t.string "definition_digest", null: false
    t.string "network_profile", default: "none", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.bigint "source_snapshot_id", null: false
    t.datetime "started_at"
    t.string "state", default: "accepted", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id", "definition_digest"], name: "index_builds_on_organization_id_and_definition_digest"
    t.index ["organization_id"], name: "index_builds_on_organization_id"
    t.index ["public_id"], name: "index_builds_on_public_id", unique: true
    t.index ["source_snapshot_id"], name: "index_builds_on_source_snapshot_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "builds_public_id_format"
  end

  create_table "certificates", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "domain_id", null: false
    t.string "fingerprint"
    t.string "key_id"
    t.datetime "not_after"
    t.datetime "not_before"
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "renewal_due_at"
    t.jsonb "sans", default: [], null: false
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["domain_id"], name: "index_certificates_on_domain_id"
    t.index ["fingerprint"], name: "index_certificates_on_fingerprint", unique: true, where: "(fingerprint IS NOT NULL)"
    t.index ["organization_id"], name: "index_certificates_on_organization_id"
    t.index ["public_id"], name: "index_certificates_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "certificates_public_id_format"
  end

  create_table "credential_versions", force: :cascade do |t|
    t.bigint "addon_id", null: false
    t.datetime "created_at", null: false
    t.datetime "issued_at", null: false
    t.bigint "organization_id", null: false
    t.datetime "revoked_at"
    t.string "secret_public_id", null: false
    t.string "state", default: "next", null: false
    t.datetime "updated_at", null: false
    t.bigint "version", null: false
    t.index ["addon_id", "version"], name: "index_credential_versions_on_addon_id_and_version", unique: true
    t.index ["addon_id"], name: "index_credential_versions_on_addon_id"
    t.index ["organization_id"], name: "index_credential_versions_on_organization_id"
  end

  create_table "deployment_transitions", force: :cascade do |t|
    t.string "actor_public_id"
    t.string "actor_type", null: false
    t.string "correlation_id", null: false
    t.datetime "created_at", null: false
    t.bigint "deployment_id", null: false
    t.string "from_state"
    t.jsonb "metadata", default: {}, null: false
    t.bigint "organization_id", null: false
    t.string "reason", null: false
    t.string "to_state", null: false
    t.index ["deployment_id", "created_at"], name: "index_deployment_transitions_on_deployment_id_and_created_at"
    t.index ["deployment_id"], name: "index_deployment_transitions_on_deployment_id"
    t.index ["organization_id"], name: "index_deployment_transitions_on_organization_id"
  end

  create_table "deployments", force: :cascade do |t|
    t.datetime "canceled_at"
    t.datetime "created_at", null: false
    t.bigint "environment_id", null: false
    t.integer "lock_version", default: 0, null: false
    t.integer "manifest_revision", null: false
    t.bigint "operation_id", null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.datetime "promoted_at"
    t.string "public_id", limit: 64, null: false
    t.datetime "ready_at"
    t.text "reason", null: false
    t.bigint "revision_id"
    t.jsonb "source", default: {}, null: false
    t.bigint "source_snapshot_id"
    t.string "state", default: "created", null: false
    t.datetime "updated_at", null: false
    t.index ["environment_id"], name: "index_deployments_on_environment_id"
    t.index ["operation_id"], name: "index_deployments_on_operation_id"
    t.index ["organization_id"], name: "index_deployments_on_organization_id"
    t.index ["project_id", "created_at"], name: "index_deployments_on_project_id_and_created_at"
    t.index ["project_id"], name: "index_deployments_on_project_id"
    t.index ["public_id"], name: "index_deployments_on_public_id", unique: true
    t.index ["revision_id"], name: "index_deployments_on_revision_id"
    t.index ["source_snapshot_id"], name: "index_deployments_on_source_snapshot_id"
    t.check_constraint "jsonb_typeof(source) = 'object'::text", name: "deployments_source_object"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "deployments_public_id_format"
    t.check_constraint "state::text = ANY (ARRAY['created'::character varying, 'sourcing'::character varying, 'detecting'::character varying, 'queued'::character varying, 'building'::character varying, 'scanning'::character varying, 'publishing'::character varying, 'scheduling'::character varying, 'starting'::character varying, 'verifying'::character varying, 'ready'::character varying, 'promoted'::character varying, 'canceling'::character varying, 'canceled'::character varying, 'failed'::character varying, 'retrying'::character varying]::text[])", name: "deployments_state"
  end

  create_table "dns_changes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "domain_id", null: false
    t.bigint "generation", null: false
    t.string "operation_id", null: false
    t.bigint "organization_id", null: false
    t.string "previous_fingerprint"
    t.jsonb "records", null: false
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["domain_id"], name: "index_dns_changes_on_domain_id"
    t.index ["operation_id"], name: "index_dns_changes_on_operation_id", unique: true
    t.index ["organization_id"], name: "index_dns_changes_on_organization_id"
  end

  create_table "domains", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "environment_id", null: false
    t.citext "hostname", null: false
    t.integer "lock_version", default: 0, null: false
    t.string "mode", null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "revalidation_due_at"
    t.bigint "service_id", null: false
    t.string "state", default: "requested", null: false
    t.datetime "updated_at", null: false
    t.datetime "verified_at"
    t.index ["environment_id"], name: "index_domains_on_environment_id"
    t.index ["hostname"], name: "index_domains_on_hostname", unique: true, where: "((state)::text <> ALL ((ARRAY['released'::character varying, 'expired'::character varying])::text[]))"
    t.index ["organization_id"], name: "index_domains_on_organization_id"
    t.index ["project_id"], name: "index_domains_on_project_id"
    t.index ["public_id"], name: "index_domains_on_public_id", unique: true
    t.index ["service_id"], name: "index_domains_on_service_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "domains_public_id_format"
  end

  create_table "edge_route_versions", force: :cascade do |t|
    t.string "canonical_digest", null: false
    t.jsonb "conditions", default: [], null: false
    t.datetime "created_at", null: false
    t.bigint "domain_id", null: false
    t.string "edge_generation_public_id", null: false
    t.bigint "organization_id", null: false
    t.bigint "release_id", null: false
    t.string "state", default: "staged", null: false
    t.datetime "updated_at", null: false
    t.index ["domain_id"], name: "index_edge_route_versions_on_domain_id"
    t.index ["edge_generation_public_id"], name: "index_edge_route_versions_on_edge_generation_public_id", unique: true
    t.index ["organization_id"], name: "index_edge_route_versions_on_organization_id"
    t.index ["release_id"], name: "index_edge_route_versions_on_release_id"
  end

  create_table "email_intents", force: :cascade do |t|
    t.bigint "account_id"
    t.datetime "created_at", null: false
    t.jsonb "data", default: {}, null: false
    t.datetime "delivered_at"
    t.string "idempotency_key", null: false
    t.string "locale", default: "en", null: false
    t.datetime "next_attempt_at"
    t.bigint "organization_id", null: false
    t.string "provider_message_id"
    t.string "public_id", limit: 64, null: false
    t.citext "recipient", null: false
    t.string "state", default: "pending", null: false
    t.jsonb "tags", default: {}, null: false
    t.string "template", null: false
    t.integer "template_version", null: false
    t.datetime "updated_at", null: false
    t.index ["account_id"], name: "index_email_intents_on_account_id"
    t.index ["idempotency_key"], name: "index_email_intents_on_idempotency_key", unique: true
    t.index ["organization_id"], name: "index_email_intents_on_organization_id"
    t.index ["public_id"], name: "index_email_intents_on_public_id", unique: true
    t.index ["state", "next_attempt_at"], name: "index_email_intents_on_state_and_next_attempt_at"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "email_intents_public_id_format"
  end

  create_table "environments", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "generation", default: 1, null: false
    t.string "health", default: "unknown", null: false
    t.integer "lock_version", default: 0, null: false
    t.string "name", limit: 100, null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.boolean "protected", default: false, null: false
    t.string "public_id", limit: 64, null: false
    t.string "slug", limit: 63, null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_environments_on_organization_id"
    t.index ["project_id", "slug"], name: "index_environments_on_project_id_and_slug", unique: true
    t.index ["project_id"], name: "index_environments_on_project_id"
    t.index ["public_id"], name: "index_environments_on_public_id", unique: true
    t.check_constraint "generation > 0", name: "environments_generation"
    t.check_constraint "health::text = ANY (ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying, 'unknown'::character varying]::text[])", name: "environments_health"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "environments_public_id_format"
  end

  create_table "idempotency_keys", force: :cascade do |t|
    t.string "command_public_id"
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.string "http_method", null: false
    t.string "key_digest", null: false
    t.string "normalized_route", null: false
    t.bigint "organization_id", null: false
    t.string "principal_public_id", null: false
    t.string "request_fingerprint", null: false
    t.jsonb "response_body"
    t.integer "response_status"
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_idempotency_keys_on_expires_at"
    t.index ["organization_id", "principal_public_id", "http_method", "normalized_route", "key_digest"], name: "idempotency_scope_unique", unique: true
    t.index ["organization_id"], name: "index_idempotency_keys_on_organization_id"
  end

  create_table "invitations", force: :cascade do |t|
    t.datetime "accepted_at"
    t.datetime "created_at", null: false
    t.citext "email", null: false
    t.datetime "expires_at", null: false
    t.bigint "inviter_id", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "revoked_at"
    t.string "role", null: false
    t.string "token_digest", null: false
    t.datetime "updated_at", null: false
    t.index ["inviter_id"], name: "index_invitations_on_inviter_id"
    t.index ["organization_id", "email"], name: "index_invitations_on_organization_id_and_email", unique: true, where: "((accepted_at IS NULL) AND (revoked_at IS NULL))"
    t.index ["organization_id"], name: "index_invitations_on_organization_id"
    t.index ["public_id"], name: "index_invitations_on_public_id", unique: true
    t.index ["token_digest"], name: "index_invitations_on_token_digest", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "invitations_public_id_format"
  end

  create_table "memberships", force: :cascade do |t|
    t.bigint "account_id", null: false
    t.datetime "created_at", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "revoked_at"
    t.string "role", null: false
    t.string "status", default: "active", null: false
    t.datetime "updated_at", null: false
    t.index ["account_id", "organization_id"], name: "index_memberships_on_account_id_and_organization_id", unique: true
    t.index ["account_id"], name: "index_memberships_on_account_id"
    t.index ["organization_id"], name: "index_memberships_on_organization_id"
    t.index ["public_id"], name: "index_memberships_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "memberships_public_id_format"
    t.check_constraint "role::text = ANY (ARRAY['owner'::character varying, 'admin'::character varying, 'developer'::character varying, 'operator'::character varying, 'billing'::character varying, 'auditor'::character varying]::text[])", name: "memberships_role"
    t.check_constraint "status::text = ANY (ARRAY['active'::character varying, 'suspended'::character varying, 'revoked'::character varying]::text[])", name: "memberships_status"
  end

  create_table "oauth_clients", force: :cascade do |t|
    t.string "client_digest", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.jsonb "redirect_uris", default: [], null: false
    t.datetime "revoked_at"
    t.jsonb "scopes", default: [], null: false
    t.datetime "updated_at", null: false
    t.index ["client_digest"], name: "index_oauth_clients_on_client_digest", unique: true
    t.index ["organization_id"], name: "index_oauth_clients_on_organization_id"
    t.index ["public_id"], name: "index_oauth_clients_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "oauth_clients_public_id_format"
  end

  create_table "operations", force: :cascade do |t|
    t.integer "completed_steps", default: 0, null: false
    t.jsonb "conditions", default: [], null: false
    t.datetime "created_at", null: false
    t.string "error_code"
    t.text "error_message"
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.string "resource_public_id", null: false
    t.string "resource_type", null: false
    t.string "stage", default: "accepted", null: false
    t.string "state", default: "accepted", null: false
    t.integer "total_steps", default: 0, null: false
    t.datetime "updated_at", null: false
    t.text "waiting_reason"
    t.string "workflow_id"
    t.index ["organization_id", "resource_type", "resource_public_id"], name: "idx_on_organization_id_resource_type_resource_publi_d374b329c8"
    t.index ["organization_id"], name: "index_operations_on_organization_id"
    t.index ["public_id"], name: "index_operations_on_public_id", unique: true
    t.index ["workflow_id"], name: "index_operations_on_workflow_id", unique: true, where: "(workflow_id IS NOT NULL)"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "operations_public_id_format"
    t.check_constraint "state::text = ANY (ARRAY['accepted'::character varying, 'running'::character varying, 'waiting'::character varying, 'retrying'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'canceling'::character varying, 'canceled'::character varying]::text[])", name: "operations_state"
  end

  create_table "organizations", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "created_by_account_id", null: false
    t.datetime "deletion_requested_at"
    t.integer "lock_version", default: 0, null: false
    t.string "name", limit: 100, null: false
    t.boolean "personal", default: false, null: false
    t.string "plan", default: "free", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "retention_until"
    t.string "slug", limit: 63, null: false
    t.datetime "updated_at", null: false
    t.index ["created_by_account_id"], name: "index_organizations_on_created_by_account_id"
    t.index ["public_id"], name: "index_organizations_on_public_id", unique: true
    t.index ["slug"], name: "index_organizations_on_slug", unique: true
    t.check_constraint "plan::text = ANY (ARRAY['free'::character varying, 'pro'::character varying, 'enterprise'::character varying]::text[])", name: "organizations_plan"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "organizations_public_id_format"
    t.check_constraint "slug::text ~ '^[a-z][a-z0-9-]{0,62}$'::text", name: "organizations_slug_format"
  end

  create_table "outbox_events", force: :cascade do |t|
    t.string "actor_public_id"
    t.string "actor_type", null: false
    t.string "causation_id"
    t.string "correlation_id", null: false
    t.datetime "created_at", null: false
    t.jsonb "data", default: {}, null: false
    t.string "event_type", null: false
    t.datetime "occurred_at", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.integer "publish_attempts", default: 0, null: false
    t.text "publish_error"
    t.datetime "published_at"
    t.string "resource_public_id", null: false
    t.string "resource_type", null: false
    t.bigint "resource_version", null: false
    t.integer "schema_version", default: 1, null: false
    t.string "traceparent"
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_outbox_events_on_organization_id"
    t.index ["public_id"], name: "index_outbox_events_on_public_id", unique: true
    t.index ["published_at", "occurred_at"], name: "outbox_unpublished_age"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "outbox_events_public_id_format"
  end

  create_table "ownership_challenges", force: :cascade do |t|
    t.datetime "consumed_at"
    t.datetime "created_at", null: false
    t.bigint "domain_id", null: false
    t.jsonb "evidence", default: {}, null: false
    t.datetime "expires_at", null: false
    t.bigint "organization_id", null: false
    t.string "record_name", null: false
    t.datetime "updated_at", null: false
    t.binary "verifier", null: false
    t.index ["domain_id", "expires_at"], name: "index_ownership_challenges_on_domain_id_and_expires_at"
    t.index ["domain_id"], name: "index_ownership_challenges_on_domain_id"
    t.index ["organization_id"], name: "index_ownership_challenges_on_organization_id"
  end

  create_table "projects", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "deletion_requested_at"
    t.text "description"
    t.integer "lock_version", default: 0, null: false
    t.jsonb "manifest", default: {}, null: false
    t.integer "manifest_revision", default: 1, null: false
    t.string "name", limit: 100, null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.datetime "retention_until"
    t.string "slug", limit: 63, null: false
    t.string "status", default: "healthy", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id", "slug"], name: "index_projects_on_organization_id_and_slug", unique: true
    t.index ["organization_id"], name: "index_projects_on_organization_id"
    t.index ["public_id"], name: "index_projects_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "projects_public_id_format"
    t.check_constraint "status::text = ANY (ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying]::text[])", name: "projects_status"
  end

  create_table "release_targets", force: :cascade do |t|
    t.string "cell_public_id", null: false
    t.jsonb "conditions", default: [], null: false
    t.datetime "created_at", null: false
    t.bigint "desired_generation", null: false
    t.bigint "observed_generation"
    t.bigint "organization_id", null: false
    t.string "region", null: false
    t.bigint "release_id", null: false
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_release_targets_on_organization_id"
    t.index ["release_id", "cell_public_id"], name: "index_release_targets_on_release_id_and_cell_public_id", unique: true
    t.index ["release_id"], name: "index_release_targets_on_release_id"
  end

  create_table "releases", force: :cascade do |t|
    t.datetime "activated_at"
    t.datetime "created_at", null: false
    t.bigint "deployment_id"
    t.bigint "environment_id", null: false
    t.bigint "generation", null: false
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.bigint "revision_id", null: false
    t.string "rollout_policy", default: "default_canary", null: false
    t.bigint "service_id", null: false
    t.string "state", default: "draft", null: false
    t.integer "traffic_weight", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["deployment_id"], name: "index_releases_on_deployment_id"
    t.index ["environment_id"], name: "index_releases_on_environment_id"
    t.index ["organization_id"], name: "index_releases_on_organization_id"
    t.index ["public_id"], name: "index_releases_on_public_id", unique: true
    t.index ["revision_id"], name: "index_releases_on_revision_id"
    t.index ["service_id", "environment_id", "generation"], name: "releases_monotonic_generation", unique: true
    t.index ["service_id"], name: "index_releases_on_service_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "releases_public_id_format"
    t.check_constraint "state::text = ANY (ARRAY['draft'::character varying, 'policy_check'::character varying, 'provisioning'::character varying, 'previewing'::character varying, 'shifting'::character varying, 'verifying'::character varying, 'active'::character varying, 'paused'::character varying, 'aborting'::character varying, 'rolled_back'::character varying, 'superseded'::character varying, 'retired'::character varying]::text[])", name: "releases_state"
    t.check_constraint "traffic_weight >= 0 AND traffic_weight <= 100", name: "releases_traffic_weight"
  end

  create_table "revisions", force: :cascade do |t|
    t.bigint "build_id", null: false
    t.datetime "created_at", null: false
    t.string "image_digest", null: false
    t.string "manifest_digest", null: false
    t.bigint "organization_id", null: false
    t.string "policy_state", null: false
    t.string "provenance_ref", null: false
    t.string "public_id", limit: 64, null: false
    t.string "sbom_ref", null: false
    t.string "scan_state", null: false
    t.bigint "service_id", null: false
    t.string "signature_ref", null: false
    t.datetime "updated_at", null: false
    t.index ["build_id"], name: "index_revisions_on_build_id"
    t.index ["image_digest"], name: "index_revisions_on_image_digest", unique: true
    t.index ["manifest_digest"], name: "index_revisions_on_manifest_digest", unique: true
    t.index ["organization_id"], name: "index_revisions_on_organization_id"
    t.index ["public_id"], name: "index_revisions_on_public_id", unique: true
    t.index ["service_id"], name: "index_revisions_on_service_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "revisions_public_id_format"
  end

  create_table "rollout_steps", force: :cascade do |t|
    t.jsonb "analysis", default: {}, null: false
    t.datetime "created_at", null: false
    t.integer "duration_seconds", null: false
    t.bigint "organization_id", null: false
    t.integer "position", null: false
    t.bigint "release_id", null: false
    t.string "state", default: "pending", null: false
    t.integer "traffic_weight", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_rollout_steps_on_organization_id"
    t.index ["release_id", "position"], name: "index_rollout_steps_on_release_id_and_position", unique: true
    t.index ["release_id"], name: "index_rollout_steps_on_release_id"
  end

  create_table "schedules", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.boolean "enabled", default: true, null: false
    t.bigint "environment_id", null: false
    t.string "expression", null: false
    t.string "name", null: false
    t.datetime "next_run_at"
    t.bigint "organization_id", null: false
    t.string "overlap_policy", null: false
    t.bigint "project_id", null: false
    t.string "public_id", limit: 64, null: false
    t.jsonb "retry_policy", default: {}, null: false
    t.jsonb "target", null: false
    t.string "timezone", null: false
    t.datetime "updated_at", null: false
    t.index ["environment_id", "name"], name: "index_schedules_on_environment_id_and_name", unique: true
    t.index ["environment_id"], name: "index_schedules_on_environment_id"
    t.index ["next_run_at"], name: "index_schedules_on_next_run_at", where: "(enabled = true)"
    t.index ["organization_id"], name: "index_schedules_on_organization_id"
    t.index ["project_id"], name: "index_schedules_on_project_id"
    t.index ["public_id"], name: "index_schedules_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "schedules_public_id_format"
  end

  create_table "service_routes", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.bigint "environment_id", null: false
    t.string "hostname"
    t.bigint "organization_id", null: false
    t.string "path_prefix", default: "/", null: false
    t.integer "priority", default: 0, null: false
    t.string "protocol", default: "https", null: false
    t.string "public_id", limit: 64, null: false
    t.bigint "service_id", null: false
    t.datetime "updated_at", null: false
    t.index ["environment_id", "hostname", "path_prefix"], name: "service_routes_unique_match", unique: true
    t.index ["environment_id"], name: "index_service_routes_on_environment_id"
    t.index ["organization_id"], name: "index_service_routes_on_organization_id"
    t.index ["public_id"], name: "index_service_routes_on_public_id", unique: true
    t.index ["service_id"], name: "index_service_routes_on_service_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "service_routes_public_id_format"
  end

  create_table "services", force: :cascade do |t|
    t.jsonb "build_specification", default: {}, null: false
    t.datetime "created_at", null: false
    t.bigint "current_release_id"
    t.string "framework"
    t.string "health", default: "unknown", null: false
    t.string "kind", null: false
    t.integer "lock_version", default: 0, null: false
    t.string "name", limit: 100, null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.string "public_id", limit: 64, null: false
    t.jsonb "runtime_specification", default: {}, null: false
    t.string "slug", limit: 63, null: false
    t.datetime "updated_at", null: false
    t.index ["current_release_id"], name: "index_services_on_current_release_id"
    t.index ["organization_id"], name: "index_services_on_organization_id"
    t.index ["project_id", "slug"], name: "index_services_on_project_id_and_slug", unique: true
    t.index ["project_id"], name: "index_services_on_project_id"
    t.index ["public_id"], name: "index_services_on_public_id", unique: true
    t.check_constraint "health::text = ANY (ARRAY['healthy'::character varying, 'degraded'::character varying, 'deploying'::character varying, 'paused'::character varying, 'unknown'::character varying]::text[])", name: "services_health"
    t.check_constraint "kind::text = ANY (ARRAY['web'::character varying, 'worker'::character varying, 'private_service'::character varying, 'static'::character varying]::text[])", name: "services_kind"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "services_public_id_format"
  end

  create_table "source_connections", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "installation_external_id", null: false
    t.datetime "last_webhook_at"
    t.bigint "organization_id", null: false
    t.string "provider", null: false
    t.string "public_id", limit: 64, null: false
    t.jsonb "scopes", default: [], null: false
    t.string "status", default: "active", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id", "provider", "installation_external_id"], name: "source_connections_provider_identity", unique: true
    t.index ["organization_id"], name: "index_source_connections_on_organization_id"
    t.index ["public_id"], name: "index_source_connections_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "source_connections_public_id_format"
  end

  create_table "source_snapshots", force: :cascade do |t|
    t.string "commit_sha"
    t.datetime "created_at", null: false
    t.string "digest", null: false
    t.string "kind", null: false
    t.string "object_ref", null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id", null: false
    t.string "public_id", limit: 64, null: false
    t.string "repository"
    t.datetime "retention_until", null: false
    t.bigint "size_bytes", null: false
    t.bigint "source_connection_id"
    t.datetime "updated_at", null: false
    t.index ["digest"], name: "index_source_snapshots_on_digest", unique: true
    t.index ["organization_id"], name: "index_source_snapshots_on_organization_id"
    t.index ["project_id"], name: "index_source_snapshots_on_project_id"
    t.index ["public_id"], name: "index_source_snapshots_on_public_id", unique: true
    t.index ["source_connection_id"], name: "index_source_snapshots_on_source_connection_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "source_snapshots_public_id_format"
    t.check_constraint "size_bytes >= 0", name: "source_snapshots_size"
  end

  create_table "usage_ledger", force: :cascade do |t|
    t.string "correction_of_public_id"
    t.string "correlation_id", null: false
    t.datetime "created_at", null: false
    t.jsonb "meter_attributes", default: {}, null: false
    t.string "meter_type", null: false
    t.bigint "organization_id", null: false
    t.datetime "period_end", null: false
    t.datetime "period_start", null: false
    t.string "public_id", limit: 64, null: false
    t.bigint "quantity", null: false
    t.string "resource_public_id", null: false
    t.bigint "sequence", null: false
    t.string "source_epoch", null: false
    t.string "source_id", null: false
    t.string "unit", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id", "period_start", "meter_type"], name: "usage_period_meter"
    t.index ["organization_id"], name: "index_usage_ledger_on_organization_id"
    t.index ["public_id"], name: "index_usage_ledger_on_public_id", unique: true
    t.index ["source_id", "source_epoch", "sequence"], name: "usage_source_sequence", unique: true
    t.check_constraint "period_end > period_start", name: "usage_period_order"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "usage_ledger_public_id_format"
    t.check_constraint "quantity <> 0", name: "usage_nonzero"
  end

  create_table "webhook_deliveries", force: :cascade do |t|
    t.integer "attempt", default: 1, null: false
    t.datetime "completed_at"
    t.datetime "created_at", null: false
    t.string "event_public_id", null: false
    t.datetime "next_attempt_at"
    t.bigint "organization_id", null: false
    t.string "public_id", limit: 64, null: false
    t.integer "response_status"
    t.string "state", default: "pending", null: false
    t.datetime "updated_at", null: false
    t.bigint "webhook_id", null: false
    t.index ["organization_id"], name: "index_webhook_deliveries_on_organization_id"
    t.index ["public_id"], name: "index_webhook_deliveries_on_public_id", unique: true
    t.index ["webhook_id", "event_public_id", "attempt"], name: "webhook_delivery_attempt", unique: true
    t.index ["webhook_id"], name: "index_webhook_deliveries_on_webhook_id"
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "webhook_deliveries_public_id_format"
  end

  create_table "webhooks", force: :cascade do |t|
    t.datetime "created_at", null: false
    t.jsonb "event_types", default: [], null: false
    t.bigint "organization_id", null: false
    t.bigint "project_id"
    t.string "public_id", limit: 64, null: false
    t.string "secret_digest", null: false
    t.integer "signature_version", default: 1, null: false
    t.string "state", default: "verification_pending", null: false
    t.datetime "updated_at", null: false
    t.string "url", null: false
    t.datetime "verified_at"
    t.index ["organization_id"], name: "index_webhooks_on_organization_id"
    t.index ["project_id"], name: "index_webhooks_on_project_id"
    t.index ["public_id"], name: "index_webhooks_on_public_id", unique: true
    t.check_constraint "public_id::text ~ '^[a-z]{2,5}_[0-9a-f-]{36}$'::text", name: "webhooks_public_id_format"
  end

  create_table "workflow_runs", force: :cascade do |t|
    t.datetime "completed_at"
    t.jsonb "conditions", default: [], null: false
    t.datetime "created_at", null: false
    t.bigint "organization_id", null: false
    t.string "resource_public_id", null: false
    t.string "run_id"
    t.datetime "started_at"
    t.string "state", default: "accepted", null: false
    t.datetime "updated_at", null: false
    t.string "workflow_id", null: false
    t.string "workflow_type", null: false
    t.index ["organization_id"], name: "index_workflow_runs_on_organization_id"
    t.index ["workflow_id"], name: "index_workflow_runs_on_workflow_id", unique: true
  end

  add_foreign_key "account_active_session_keys", "accounts"
  add_foreign_key "account_authentication_audit_logs", "accounts"
  add_foreign_key "account_lockouts", "accounts", column: "id"
  add_foreign_key "account_login_change_keys", "accounts", column: "id"
  add_foreign_key "account_login_failures", "accounts", column: "id"
  add_foreign_key "account_otp_keys", "accounts", column: "id"
  add_foreign_key "account_password_hashes", "accounts", column: "id", on_delete: :cascade
  add_foreign_key "account_password_reset_keys", "accounts", column: "id"
  add_foreign_key "account_previous_password_hashes", "accounts"
  add_foreign_key "account_recovery_codes", "accounts", column: "id"
  add_foreign_key "account_remember_keys", "accounts", column: "id"
  add_foreign_key "account_verification_keys", "accounts", column: "id"
  add_foreign_key "account_webauthn_keys", "accounts"
  add_foreign_key "account_webauthn_user_ids", "accounts", column: "id"
  add_foreign_key "addon_backups", "addons", on_delete: :cascade
  add_foreign_key "addon_backups", "organizations", on_delete: :cascade
  add_foreign_key "addons", "environments"
  add_foreign_key "addons", "organizations", on_delete: :cascade
  add_foreign_key "addons", "projects"
  add_foreign_key "api_keys", "accounts"
  add_foreign_key "api_keys", "organizations", on_delete: :cascade
  add_foreign_key "attachments", "addons", on_delete: :cascade
  add_foreign_key "attachments", "environments", on_delete: :cascade
  add_foreign_key "attachments", "organizations", on_delete: :cascade
  add_foreign_key "attachments", "services", on_delete: :cascade
  add_foreign_key "attestations", "organizations", on_delete: :cascade
  add_foreign_key "attestations", "revisions", on_delete: :cascade
  add_foreign_key "audit_events", "organizations", on_delete: :cascade
  add_foreign_key "build_steps", "builds", on_delete: :cascade
  add_foreign_key "build_steps", "organizations", on_delete: :cascade
  add_foreign_key "builds", "organizations", on_delete: :cascade
  add_foreign_key "builds", "source_snapshots"
  add_foreign_key "certificates", "domains", on_delete: :cascade
  add_foreign_key "certificates", "organizations", on_delete: :cascade
  add_foreign_key "credential_versions", "addons", on_delete: :cascade
  add_foreign_key "credential_versions", "organizations", on_delete: :cascade
  add_foreign_key "deployment_transitions", "deployments", on_delete: :cascade
  add_foreign_key "deployment_transitions", "organizations", on_delete: :cascade
  add_foreign_key "deployments", "environments"
  add_foreign_key "deployments", "operations"
  add_foreign_key "deployments", "organizations", on_delete: :cascade
  add_foreign_key "deployments", "projects"
  add_foreign_key "deployments", "revisions"
  add_foreign_key "deployments", "source_snapshots"
  add_foreign_key "dns_changes", "domains", on_delete: :cascade
  add_foreign_key "dns_changes", "organizations", on_delete: :cascade
  add_foreign_key "domains", "environments"
  add_foreign_key "domains", "organizations", on_delete: :cascade
  add_foreign_key "domains", "projects"
  add_foreign_key "domains", "services"
  add_foreign_key "edge_route_versions", "domains", on_delete: :cascade
  add_foreign_key "edge_route_versions", "organizations", on_delete: :cascade
  add_foreign_key "edge_route_versions", "releases"
  add_foreign_key "email_intents", "accounts"
  add_foreign_key "email_intents", "organizations", on_delete: :cascade
  add_foreign_key "environments", "organizations", on_delete: :cascade
  add_foreign_key "environments", "projects", on_delete: :cascade
  add_foreign_key "idempotency_keys", "organizations", on_delete: :cascade
  add_foreign_key "invitations", "accounts", column: "inviter_id"
  add_foreign_key "invitations", "organizations", on_delete: :cascade
  add_foreign_key "memberships", "accounts", on_delete: :cascade
  add_foreign_key "memberships", "organizations", on_delete: :cascade
  add_foreign_key "oauth_clients", "organizations", on_delete: :cascade
  add_foreign_key "operations", "organizations", on_delete: :cascade
  add_foreign_key "organizations", "accounts", column: "created_by_account_id"
  add_foreign_key "outbox_events", "organizations", on_delete: :cascade
  add_foreign_key "ownership_challenges", "domains", on_delete: :cascade
  add_foreign_key "ownership_challenges", "organizations", on_delete: :cascade
  add_foreign_key "projects", "organizations", on_delete: :cascade
  add_foreign_key "release_targets", "organizations", on_delete: :cascade
  add_foreign_key "release_targets", "releases", on_delete: :cascade
  add_foreign_key "releases", "deployments"
  add_foreign_key "releases", "environments"
  add_foreign_key "releases", "organizations", on_delete: :cascade
  add_foreign_key "releases", "revisions"
  add_foreign_key "releases", "services"
  add_foreign_key "revisions", "builds"
  add_foreign_key "revisions", "organizations", on_delete: :cascade
  add_foreign_key "revisions", "services"
  add_foreign_key "rollout_steps", "organizations", on_delete: :cascade
  add_foreign_key "rollout_steps", "releases", on_delete: :cascade
  add_foreign_key "schedules", "environments"
  add_foreign_key "schedules", "organizations", on_delete: :cascade
  add_foreign_key "schedules", "projects"
  add_foreign_key "service_routes", "environments", on_delete: :cascade
  add_foreign_key "service_routes", "organizations", on_delete: :cascade
  add_foreign_key "service_routes", "services", on_delete: :cascade
  add_foreign_key "services", "organizations", on_delete: :cascade
  add_foreign_key "services", "projects", on_delete: :cascade
  add_foreign_key "services", "releases", column: "current_release_id"
  add_foreign_key "source_connections", "organizations", on_delete: :cascade
  add_foreign_key "source_snapshots", "organizations", on_delete: :cascade
  add_foreign_key "source_snapshots", "projects", on_delete: :cascade
  add_foreign_key "source_snapshots", "source_connections"
  add_foreign_key "usage_ledger", "organizations", on_delete: :cascade
  add_foreign_key "webhook_deliveries", "organizations", on_delete: :cascade
  add_foreign_key "webhook_deliveries", "webhooks", on_delete: :cascade
  add_foreign_key "webhooks", "organizations", on_delete: :cascade
  add_foreign_key "webhooks", "projects"
  add_foreign_key "workflow_runs", "organizations", on_delete: :cascade
end
