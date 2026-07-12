require "base64"
require "openssl"

module SourceIngestion
  class GrantSigner
    AUDIENCE = "lrail-source-gateway"

    def initialize(key:)
      @key = Base64.urlsafe_decode64(pad(key))
      raise ArgumentError, "source grant key must contain 32 bytes" unless @key.bytesize == 32
    end

    def sign(session)
      grant = {
        "version" => 1,
        "audience" => AUDIENCE,
        "session_id" => session.public_id,
        "organization_id" => session.organization.public_id,
        "project_id" => session.project.public_id,
        "creator_id" => session.created_by_account.public_id,
        "root_directory" => session.root_directory,
        "excluded_count" => session.excluded_count,
        "expected_archive_bytes" => session.expected_archive_bytes,
        "expected_archive_sha256" => session.expected_archive_sha256,
        "expected_parts" => session.expected_parts,
        "expires_at" => session.expires_at.utc.iso8601(6)
      }
      payload = Base64.urlsafe_encode64(CanonicalJson.dump(grant), padding: false)
      message = "v1.#{payload}"
      signature = OpenSSL::HMAC.digest("SHA256", @key, message)
      "#{message}.#{Base64.urlsafe_encode64(signature, padding: false)}"
    end

    private

    def pad(value)
      value.to_s + ("=" * ((4 - value.to_s.length % 4) % 4))
    end
  end
end
