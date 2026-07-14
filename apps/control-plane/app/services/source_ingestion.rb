module SourceIngestion
  InvalidInput = Class.new(StandardError)
  InProgress = Class.new(StandardError)
  LOCAL_GATEWAY_URL = "http://127.0.0.1:58080"
  LOCAL_GRANT_KEY = "__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA"
  LOCAL_SIGNING_KEYS = {
    "source-finalizer-local-v1" => "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
  }.freeze
  LOCAL_OBJECT_PREFIX = "s3://lrail-source/"
  LOCAL_LAB_ROOT = Rails.root.join("../..", ".work", "mb-lab").expand_path.freeze

  def self.gateway_client
    grant_key = ENV.fetch("LRAIL_SOURCE_GRANT_KEY") { local_grant_key }
    keys = signing_keys
    object_prefix = ENV.fetch("LRAIL_SOURCE_OBJECT_PREFIX") { local_value(LOCAL_OBJECT_PREFIX) }
    GatewayClient.new(
      base_url: ENV.fetch("LRAIL_SOURCE_GATEWAY_URL") { local_value(LOCAL_GATEWAY_URL) },
      grant_signer: GrantSigner.new(key: grant_key),
      result_verifier: ResultVerifier.new(
        keys:,
        object_prefix:,
      ),
      fetch_grant_signer: FetchGrantSigner.new(key: grant_key),
      fetch_result_verifier: FetchResultVerifier.new(keys:, object_prefix:),
    )
  end

  def self.signing_keys
    encoded = ENV["LRAIL_SOURCE_SIGNING_PUBLIC_KEYS"]
    encoded ||= local_lab_file("source-signing-public-keys.json", maximum_bytes: 64.kilobytes)
    return local_value(LOCAL_SIGNING_KEYS) unless encoded

    raw = JSON.parse(encoded)
    raise KeyError, "source signing key set must not be empty" unless raw.is_a?(Hash) && raw.any?

    raw
  rescue JSON::ParserError
    raise KeyError, "LRAIL_SOURCE_SIGNING_PUBLIC_KEYS must be a JSON key map"
  end

  def self.local_grant_key
    local_lab_file("source-grant-key", maximum_bytes: 256)&.strip.presence || local_value(LOCAL_GRANT_KEY)
  end

  def self.local_lab_file(name, maximum_bytes:)
    local_value(nil)
    path = LOCAL_LAB_ROOT.join(name)
    stat = path.lstat
    raise KeyError, "local source lab configuration is unsafe" unless stat.file? && !stat.symlink? && stat.size.between?(1, maximum_bytes)

    path.binread
  rescue Errno::ENOENT
    nil
  end

  def self.local_value(value)
    raise KeyError, "production source gateway configuration is required" if Rails.env.production?

    value
  end

  private_class_method :local_value, :local_grant_key, :local_lab_file
end
