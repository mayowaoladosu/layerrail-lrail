class AddApiKeyAuthenticationBoundary < ActiveRecord::Migration[8.1]
  def up
    change_column_null :api_keys, :account_id, false
    add_check_constraint :api_keys, "prefix ~ '^[A-Za-z0-9]{12}$'", name: "api_keys_prefix_format"
    add_check_constraint :api_keys, "secret_digest LIKE '$argon2id$%'", name: "api_keys_argon_digest"
    add_check_constraint :api_keys, "jsonb_typeof(scopes) = 'array'", name: "api_keys_scopes_array"
    add_check_constraint :api_keys, "jsonb_typeof(constraints) = 'object'", name: "api_keys_constraints_object"

    execute <<~SQL
      CREATE FUNCTION lrail_find_api_key(candidate_prefix text)
      RETURNS TABLE (
        key_id bigint,
        key_public_id varchar,
        organization_id bigint,
        account_id bigint,
        secret_digest varchar,
        scopes jsonb,
        constraints jsonb,
        expires_at timestamptz,
        last_used_at timestamptz
      ) AS $$
        SELECT
          id,
          public_id,
          api_keys.organization_id,
          api_keys.account_id,
          api_keys.secret_digest,
          api_keys.scopes,
          api_keys.constraints,
          api_keys.expires_at,
          api_keys.last_used_at
        FROM api_keys
        WHERE prefix = candidate_prefix
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > clock_timestamp())
        LIMIT 1;
      $$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp SET row_security = off;
      REVOKE ALL ON FUNCTION lrail_find_api_key(text) FROM PUBLIC;
    SQL

    role = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(role)}")

    execute "GRANT EXECUTE ON FUNCTION lrail_find_api_key(text) TO #{connection.quote_table_name(role)}"
  end

  def down
    execute "DROP FUNCTION IF EXISTS lrail_find_api_key(text)"
    remove_check_constraint :api_keys, name: "api_keys_constraints_object"
    remove_check_constraint :api_keys, name: "api_keys_scopes_array"
    remove_check_constraint :api_keys, name: "api_keys_argon_digest"
    remove_check_constraint :api_keys, name: "api_keys_prefix_format"
    change_column_null :api_keys, :account_id, true
  end
end
