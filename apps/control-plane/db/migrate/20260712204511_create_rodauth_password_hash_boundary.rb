require "rodauth/migrations"
require "sequel/core"

class CreateRodauthPasswordHashBoundary < ActiveRecord::Migration[8.1]
  def up
    create_table :account_password_hashes, id: false do |t|
      t.bigint :id, primary_key: true
      t.foreign_key :accounts, column: :id, on_delete: :cascade
      t.string :password_hash, null: false
    end

    sequel_db = Sequel.postgres(extensions: :activerecord_connection, keep_reference: false)
    Rodauth.create_database_authentication_functions(sequel_db, argon2: true)
    Rodauth.create_database_previous_password_check_functions(sequel_db, argon2: true)

    execute "REVOKE ALL ON account_password_hashes FROM PUBLIC"
    execute "REVOKE ALL ON account_previous_password_hashes FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION rodauth_get_salt(bigint) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION rodauth_valid_password_hash(bigint, text) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION rodauth_get_previous_salt(bigint) FROM PUBLIC"
    execute "REVOKE ALL ON FUNCTION rodauth_previous_password_hash_match(bigint, text) FROM PUBLIC"

    app_role_name = ENV.fetch("LRAIL_WEB_DATABASE_ROLE", "lrail_web")
    return unless select_value("SELECT 1 FROM pg_roles WHERE rolname = #{connection.quote(app_role_name)}")

    app_role = connection.quote_table_name(app_role_name)
    execute "GRANT INSERT, UPDATE, DELETE ON account_password_hashes TO #{app_role}"
    execute "GRANT SELECT (id) ON account_password_hashes TO #{app_role}"
    execute "GRANT INSERT, UPDATE, DELETE ON account_previous_password_hashes TO #{app_role}"
    execute "GRANT SELECT (id, account_id) ON account_previous_password_hashes TO #{app_role}"
    execute "GRANT USAGE ON SEQUENCE account_previous_password_hashes_id_seq TO #{app_role}"
    execute "GRANT EXECUTE ON FUNCTION rodauth_get_salt(bigint) TO #{app_role}"
    execute "GRANT EXECUTE ON FUNCTION rodauth_valid_password_hash(bigint, text) TO #{app_role}"
    execute "GRANT EXECUTE ON FUNCTION rodauth_get_previous_salt(bigint) TO #{app_role}"
    execute "GRANT EXECUTE ON FUNCTION rodauth_previous_password_hash_match(bigint, text) TO #{app_role}"
  end

  def down
    sequel_db = Sequel.postgres(extensions: :activerecord_connection, keep_reference: false)
    Rodauth.drop_database_previous_password_check_functions(sequel_db)
    Rodauth.drop_database_authentication_functions(sequel_db)
    drop_table :account_password_hashes
  end
end
