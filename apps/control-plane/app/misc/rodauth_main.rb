require "sequel/core"
require "uri"

class RodauthMain < Rodauth::Rails::Auth
  configure do
    # List of authentication features that are loaded.
    enable :create_account, :verify_account, :verify_account_grace_period,
      :login, :logout, :remember, :json,
      :reset_password, :change_password, :change_login, :verify_login_change,
      :close_account, :argon2, :update_password_hash, :lockout,
      :active_sessions, :session_expiration, :audit_logging,
      :otp, :recovery_codes, :webauthn, :webauthn_login,
      :confirm_password, :password_grace_period, :disallow_password_reuse

    # See the Rodauth documentation for the list of available config options:
    # http://rodauth.jeremyevans.net/documentation.html

    # ==> General
    # Initialize Sequel and have it reuse Active Record's database connection.
    db Sequel.postgres(extensions: :activerecord_connection, keep_reference: false)
    # Avoid DB query that checks accounts table schema at boot time.
    convert_token_id_to_integer? { Account.columns_hash["id"].type == :integer }

    # Change prefix of table and foreign key column names from default "account"
    # accounts_table :users
    # verify_account_table :user_verification_keys
    # verify_login_change_table :user_login_change_keys
    # reset_password_table :user_password_reset_keys
    # remember_table :user_remember_keys

    # The secret key used for hashing public-facing tokens for various features.
    # Defaults to Rails `secret_key_base`, but you can use your own secret key.
    # hmac_secret "48d4673c5ed066d94a7cb0ad14757fd04ec24c9827a111aae145fdabe524101758d1e29e4a9cb926df7e41c5f826b080c993863fd20b828f5bbdf254908b48dc"

    # Use a rotatable password pepper when hashing passwords with Argon2.
    argon2_secret { hmac_secret }

    # Since we're using argon2, prevent loading the bcrypt gem to save memory.
    require_bcrypt? false

    # Browser sessions and JSON authentication share the same guarded account
    # lifecycle. Public API automation uses separate OAuth/API-key resources.
    only_json? false
    create_account_autologin? false

    # Handle login and password confirmation fields on the client side.
    # require_password_confirmation? false
    # require_login_confirmation? false

    # Use path prefix for all routes.
    prefix "/auth"

    # Specify the controller used for view rendering, CSRF, and callbacks.
    rails_controller { RodauthController }

    # Make built-in page titles accessible in your views via an instance variable.
    title_instance_variable :@page_title

    # Store account status in an integer column without foreign key constraint.
    account_status_column :status

    password_hash_table :account_password_hashes
    use_database_authentication_functions? true

    # Set password when creating account instead of when verifying.
    verify_account_set_password? false

    # Change some default param keys.
    login_param "email"
    login_confirm_param "email-confirm"
    no_matching_login_message "Unable to authenticate with those credentials"
    invalid_password_message "Unable to authenticate with those credentials"
    already_an_account_with_this_login_message "If this email can be used, further instructions will be sent"
    # password_confirm_param "confirm_password"

    login_redirect "/console"
    login_return_to_requested_location? true
    # two_factor_auth_return_to_requested_location? true # if using MFA

    # Autologin the user after they have reset their password.
    # reset_password_autologin? true

    # Delete the account record when the user has closed their account.
    # delete_account_on_close? true

    # Redirect to the app from login and registration pages if already logged in.
    # already_logged_in { redirect login_redirect }

    # ==> Emails
    send_email do |email|
      account_database_id = account_id
      db.after_commit do
        ::Email::Enqueue.from_mail(account: Account.find(account_database_id), message: email)
      end
    end

    # ==> Flash
    # Override default flash messages.
    # create_account_notice_flash "Your account has been created. Please verify your account by visiting the confirmation link sent to your email address."
    # require_login_error_flash "Login is required for accessing this page"
    # login_notice_flash nil

    # ==> Validation
    # Override default validation error messages.
    # no_matching_login_message "user with this email address doesn't exist"
    # already_an_account_with_this_login_message "user with this email address already exists"
    # password_too_short_message { "needs to have at least #{password_minimum_length} characters" }
    # login_does_not_meet_requirements_message { "invalid email#{", #{login_requirement_message}" if login_requirement_message}" }

    password_minimum_length 12
    # Having a maximum password length set prevents long password DoS attacks.
    password_maximum_length 256

    # Custom password complexity requirements (alternative to password_complexity feature).
    # password_meets_requirements? do |password|
    #   super(password) && password_complex_enough?(password)
    # end
    # auth_class_eval do
    #   def password_complex_enough?(password)
    #     return true if password.match?(/\d/) && password.match?(/[^a-zA-Z\d]/)
    #     set_password_requirement_error_message(:password_simple, "requires one number and one special character")
    #     false
    #   end
    # end

    # ==> Remember Feature
    # Remember only explicit user requests.
    after_login { remember_login if param_or_nil("remember") == "1" }

    # Or only remember users that have ticked a "Remember Me" checkbox on login.
    # after_login { remember_login if param_or_nil("remember") }

    # Extend user's remember period when remembered via a cookie
    extend_remember_deadline? true

    max_session_lifetime 12.hours.to_i
    session_inactivity_timeout 30.minutes.to_i
    max_invalid_logins 8
    account_lockouts_deadline_interval Hash[minutes: 15]

    webauthn_origin { ENV.fetch("LRAIL_WEBAUTHN_ORIGIN", "http://localhost:3000") }
    webauthn_rp_id { URI(webauthn_origin).host }
    webauthn_rp_name "Lrail"

    audit_log_metadata_default do
      {
        request_id: rails_request.request_id,
        ip_prefix: rails_request.remote_ip,
        user_agent: rails_request.user_agent.to_s.first(160)
      }
    end

    # ==> Hooks
    # Validate custom fields in the create account form.
    before_create_account do
      timestamp = Time.current
      account[:public_id] = PlatformId.generate(:acct, now: timestamp)
      account[:display_name] = login_param_value.split("@", 2).first.to_s.titleize.first(100).presence || "Developer"
      account[:created_at] = timestamp
      account[:updated_at] = timestamp
    end

    # Perform additional actions after the account is created.
    after_create_account do
      Identity::ProvisionPersonalOrganization.call(account_id: account_id)
    end

    # Do additional cleanup after the account is closed.
    # after_close_account do
    #   Profile.find_by!(account_id: account_id).destroy
    # end

    # ==> Deadlines
    # Change default deadlines for some actions.
    verify_account_grace_period 0
    reset_password_deadline_interval Hash[hours: 1]
    verify_login_change_deadline_interval Hash[hours: 1]
    remember_deadline_interval Hash[days: 14]
  end
end
