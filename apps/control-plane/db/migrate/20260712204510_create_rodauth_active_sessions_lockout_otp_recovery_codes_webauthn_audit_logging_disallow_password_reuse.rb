class CreateRodauthActiveSessionsLockoutOtpRecoveryCodesWebauthnAuditLoggingDisallowPasswordReuse < ActiveRecord::Migration[8.1]
  def change
    # Used by the active sessions feature
    create_table :account_active_session_keys, primary_key: [ :account_id, :session_id ] do |t|
      t.references :account, foreign_key: true
      t.string :session_id
      t.datetime :created_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      t.datetime :last_use, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end

    # Used by the lockout feature
    create_table :account_login_failures, id: false do |t|
      t.bigint :id, primary_key: true
      t.foreign_key :accounts, column: :id
      t.integer :number, null: false, default: 1
    end
    create_table :account_lockouts, id: false do |t|
      t.bigint :id, primary_key: true
      t.foreign_key :accounts, column: :id
      t.string :key, null: false
      t.datetime :deadline, null: false
      t.datetime :email_last_sent
    end

    # Used by the otp feature
    create_table :account_otp_keys, id: false do |t|
      t.bigint :id, primary_key: true
      t.foreign_key :accounts, column: :id
      t.string :key, null: false
      t.integer :num_failures, null: false, default: 0
      t.datetime :last_use, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end

    # Used by the recovery codes feature
    create_table :account_recovery_codes, primary_key: [ :id, :code ] do |t|
      t.bigint :id
      t.foreign_key :accounts, column: :id
      t.string :code
    end

    # Used by the webauthn feature
    create_table :account_webauthn_user_ids, id: false do |t|
      t.bigint :id, primary_key: true
      t.foreign_key :accounts, column: :id
      t.string :webauthn_id, null: false
    end
    create_table :account_webauthn_keys, primary_key: [ :account_id, :webauthn_id ] do |t|
      t.references :account, foreign_key: true
      t.string :webauthn_id
      t.string :public_key, null: false
      t.integer :sign_count, null: false
      t.datetime :last_use, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end

    # Used by the audit logging feature
    create_table :account_authentication_audit_logs do |t|
      t.references :account, foreign_key: true, null: false
      t.datetime :at, null: false, default: -> { "CURRENT_TIMESTAMP" }
      t.text :message, null: false
      t.jsonb :metadata
      t.index [ :account_id, :at ]
      t.index :at
    end

    # Used by the disallow password reuse feature
    create_table :account_previous_password_hashes do |t|
      t.references :account, foreign_key: true
      t.string :password_hash, null: false
    end
  end
end
