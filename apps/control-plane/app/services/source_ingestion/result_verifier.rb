require "base64"
require "openssl"

module SourceIngestion
  class ResultVerifier
    Invalid = Class.new(StandardError)
    DIGEST_PATTERN = /\Asha256:[0-9a-f]{64}\z/
    ED25519_SPKI_PREFIX = [ "302a300506032b6570032100" ].pack("H*").freeze

    def initialize(keys:, object_prefix:)
      @keys = keys.transform_values { |value| decode_public_key(value) }.freeze
      @object_prefix = object_prefix.to_s
      raise Invalid, "source object prefix must be an s3 URI" unless @object_prefix.match?(%r{\As3://[^/]+/})
    end

    def verify!(payload, expected_session:)
      input = payload.deep_stringify_keys
      raise Invalid, "signed source result fields are invalid" unless input.keys.sort == %w[key_id result signature]

      result = input.fetch("result")
      validate_result!(result, expected_session:)
      key = @keys.fetch(input.fetch("key_id")) { raise Invalid, "source signing key is unknown" }
      signature = Base64.urlsafe_decode64(pad(input.fetch("signature")))
      raise Invalid, "source result signature is invalid" unless key.verify(nil, signature, CanonicalJson.dump(result))

      result.merge("_key_id" => input.fetch("key_id"))
    rescue KeyError, ArgumentError, OpenSSL::PKey::PKeyError
      raise Invalid, "signed source result is invalid"
    end

    private

    def validate_result!(result, expected_session:)
      expected_keys = %w[
        archive_ref archive_sha256 finalized_at manifest_ref manifest_sha256 organization_id
        policy_version project_id session_id size_bytes snapshot_sha256 version
      ]
      unless result.is_a?(Hash) && result.keys.sort == expected_keys && result.fetch("version") == 1 &&
          result.fetch("session_id") == expected_session.public_id &&
          result.fetch("organization_id") == expected_session.organization.public_id &&
          result.fetch("project_id") == expected_session.project.public_id &&
          result.fetch("archive_sha256") == expected_session.expected_archive_sha256 &&
          result.fetch("size_bytes") == expected_session.expected_archive_bytes &&
          %w[snapshot_sha256 manifest_sha256 archive_sha256].all? { |key| DIGEST_PATTERN.match?(result.fetch(key)) } &&
          result.fetch("manifest_ref").start_with?(@object_prefix) && result.fetch("archive_ref").start_with?(@object_prefix) &&
          Time.iso8601(result.fetch("finalized_at")) <= 5.minutes.from_now
        raise Invalid, "signed source result scope does not match the upload session"
      end
    end

    def decode_public_key(value)
      bytes = Base64.urlsafe_decode64(pad(value))
      raise Invalid, "source public key is invalid" unless bytes.bytesize == 32

      OpenSSL::PKey.read(ED25519_SPKI_PREFIX + bytes)
    rescue ArgumentError, OpenSSL::PKey::PKeyError
      raise Invalid, "source public key is invalid"
    end

    def pad(value)
      value.to_s + ("=" * ((4 - value.to_s.length % 4) % 4))
    end
  end
end
