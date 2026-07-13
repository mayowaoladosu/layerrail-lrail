require "base64"
require "openssl"

module SourceIngestion
  class FetchGrantSigner
    AUDIENCE = "lrail-source-gateway"

    def initialize(key:)
      @key = Base64.urlsafe_decode64(pad(key))
      raise ArgumentError, "source grant key must contain 32 bytes" unless @key.bytesize == 32
    end

    def sign(fetch)
      grant = {
        "version" => 1,
        "audience" => AUDIENCE,
        "fetch_id" => fetch.public_id,
        "organization_id" => fetch.organization.public_id,
        "project_id" => fetch.project.public_id,
        "creator_id" => fetch.created_by_account.public_id,
        "source_connection_id" => fetch.source_connection.public_id,
        "provider" => fetch.source_connection.provider,
        "installation_id" => fetch.source_connection.installation_external_id,
        "repository" => fetch.repository,
        "commit_sha" => fetch.requested_commit_sha,
        "root_directory" => fetch.root_directory,
        "expires_at" => fetch.expires_at.utc.iso8601
      }
      payload = Base64.urlsafe_encode64(CanonicalJson.dump(grant), padding: false)
      message = "f1.#{payload}"
      signature = OpenSSL::HMAC.digest("SHA256", @key, message)
      "#{message}.#{Base64.urlsafe_encode64(signature, padding: false)}"
    end

    private

    def pad(value)
      value.to_s + ("=" * ((4 - value.to_s.length % 4) % 4))
    end
  end
end
