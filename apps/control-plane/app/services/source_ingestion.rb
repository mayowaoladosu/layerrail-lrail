module SourceIngestion
  InvalidInput = Class.new(StandardError)
  InProgress = Class.new(StandardError)
  LOCAL_GATEWAY_URL = "http://127.0.0.1:58080"
  LOCAL_GRANT_KEY = "__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA"
  LOCAL_SIGNING_KEYS = {
    "source-finalizer-local-v1" => "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
  }.freeze
  LOCAL_OBJECT_PREFIX = "s3://lrail-source/"

  def self.gateway_client
    GatewayClient.new(
      base_url: ENV.fetch("LRAIL_SOURCE_GATEWAY_URL") { local_value(LOCAL_GATEWAY_URL) },
      grant_signer: GrantSigner.new(key: ENV.fetch("LRAIL_SOURCE_GRANT_KEY") { local_value(LOCAL_GRANT_KEY) }),
      result_verifier: ResultVerifier.new(
        keys: signing_keys,
        object_prefix: ENV.fetch("LRAIL_SOURCE_OBJECT_PREFIX") { local_value(LOCAL_OBJECT_PREFIX) },
      ),
    )
  end

  def self.signing_keys
    encoded = ENV["LRAIL_SOURCE_SIGNING_PUBLIC_KEYS"]
    return local_value(LOCAL_SIGNING_KEYS) unless encoded

    raw = JSON.parse(encoded)
    raise KeyError, "source signing key set must not be empty" unless raw.is_a?(Hash) && raw.any?

    raw
  rescue JSON::ParserError
    raise KeyError, "LRAIL_SOURCE_SIGNING_PUBLIC_KEYS must be a JSON key map"
  end

  def self.local_value(value)
    raise KeyError, "production source gateway configuration is required" if Rails.env.production?

    value
  end

  private_class_method :local_value
end
