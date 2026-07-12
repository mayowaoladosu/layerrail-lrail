require "openssl"

# Be sure to restart your server when you modify this file.

# Define an application-wide content security policy.
# See the Securing Rails Applications Guide for more information:
# https://guides.rubyonrails.org/security.html#content-security-policy-header

Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self
    policy.base_uri :self
    policy.connect_src :self
    policy.font_src :self
    policy.form_action :self
    policy.frame_ancestors :none
    policy.frame_src :none
    policy.img_src :self, :data
    policy.manifest_src :self
    policy.media_src :self
    policy.object_src :none
    policy.script_src :self
    policy.style_src :self
    policy.worker_src :self
    policy.upgrade_insecure_requests true if Rails.env.production?
  end

  config.content_security_policy_nonce_generator = lambda do |request|
    OpenSSL::HMAC.hexdigest("SHA256", Rails.application.secret_key_base, request.session.id.to_s)
  end
  config.content_security_policy_nonce_directives = %w[script-src style-src]
  config.content_security_policy_nonce_auto = true
end
