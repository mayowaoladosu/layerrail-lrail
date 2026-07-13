require "openssl"

module SourceProviders
  InvalidWebhook = Class.new(StandardError)
  DuplicateMismatch = Class.new(StandardError)
  MAX_WEBHOOK_BYTES = 2.megabytes
  DELIVERY_PATTERN = /\A[0-9a-f-]{8,128}\z/i
  SUPPORTED_EVENTS = %w[push pull_request installation installation_repositories ping].freeze

  def self.webhook_secret
    ENV.fetch("LRAIL_GITHUB_WEBHOOK_SECRET") { local_value("github-webhook-local-only-not-a-secret") }
  end

  def self.local_value(value)
    raise KeyError, "GitHub provider configuration is required in production" if Rails.env.production?

    value
  end

  private_class_method :local_value
end
