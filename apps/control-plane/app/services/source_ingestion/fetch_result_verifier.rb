require "base64"
require "openssl"

module SourceIngestion
  class FetchResultVerifier
    Invalid = Class.new(StandardError)
    DIGEST_PATTERN = /\Asha256:[0-9a-f]{64}\z/
    COMMIT_PATTERN = /\A[0-9a-f]{40}(?:[0-9a-f]{24})?\z/
    ED25519_SPKI_PREFIX = [ "302a300506032b6570032100" ].pack("H*").freeze

    def initialize(keys:, object_prefix:, clock: Time)
      @keys = keys.transform_values { |value| decode_public_key(value) }.freeze
      @object_prefix = object_prefix.to_s
      @clock = clock
      unless @object_prefix.match?(%r{\As3://[a-z0-9][a-z0-9.-]{2,62}/(?:[^?#]*/)?\z})
        raise Invalid, "source object prefix must be a bounded s3 URI prefix"
      end
    end

    def verify!(payload, expected_fetch:)
      input = payload.deep_stringify_keys
      raise Invalid, "signed source fetch result fields are invalid" unless input.keys.sort == %w[key_id result signature]

      result = input.fetch("result")
      validate_result!(result, expected_fetch:)
      key = @keys.fetch(input.fetch("key_id")) { raise Invalid, "source signing key is unknown" }
      signature = Base64.urlsafe_decode64(pad(input.fetch("signature")))
      raise Invalid, "source fetch result signature is invalid" unless key.verify(nil, signature, CanonicalJson.dump(result))

      result.merge("_key_id" => input.fetch("key_id"))
    rescue KeyError, ArgumentError, OpenSSL::PKey::PKeyError
      raise Invalid, "signed source fetch result is invalid"
    end

    private

    def validate_result!(result, expected_fetch:)
      expected_keys = %w[
        archive_ref archive_sha256 author authored_at fetch_id finalized_at lfs_digests manifest_ref
        manifest_sha256 organization_id policy_version project_id provider repository requested_commit_sha
        resolved_commit_sha size_bytes snapshot_sha256 source_connection_id submodules token_expires_at tree_sha
        version warnings
      ]
      unless result.is_a?(Hash) && result.keys.sort == expected_keys
        raise Invalid, "signed source fetch result fields are invalid"
      end

      authored_at = Time.iso8601(result.fetch("authored_at"))
      token_expires_at = Time.iso8601(result.fetch("token_expires_at"))
      finalized_at = Time.iso8601(result.fetch("finalized_at"))
      warnings = result.fetch("warnings")
      now = @clock.current
      unless result.fetch("version") == 1 &&
          result.fetch("fetch_id") == expected_fetch.public_id &&
          result.fetch("organization_id") == expected_fetch.organization.public_id &&
          result.fetch("project_id") == expected_fetch.project.public_id &&
          result.fetch("source_connection_id") == expected_fetch.source_connection.public_id &&
          result.fetch("provider") == expected_fetch.source_connection.provider &&
          result.fetch("repository").casecmp?(expected_fetch.repository) &&
          result.fetch("requested_commit_sha") == expected_fetch.requested_commit_sha &&
          result.fetch("resolved_commit_sha") == expected_fetch.requested_commit_sha &&
          COMMIT_PATTERN.match?(result.fetch("tree_sha")) &&
          %w[snapshot_sha256 manifest_sha256 archive_sha256].all? { |key| DIGEST_PATTERN.match?(result.fetch(key)) } &&
          result.fetch("manifest_ref").start_with?(@object_prefix) && result.fetch("archive_ref").start_with?(@object_prefix) &&
          Integer(result.fetch("size_bytes")).positive? && result.fetch("submodules") == [] && result.fetch("lfs_digests") == [] &&
          result.fetch("author").is_a?(String) && result.fetch("author").bytesize <= 512 &&
          result.fetch("policy_version").is_a?(String) && result.fetch("policy_version").bytesize.between?(1, 128) &&
          warnings.is_a?(Array) && warnings.uniq == warnings && warnings == warnings.sort &&
          warnings.all? { |warning| warning.is_a?(String) && warning.bytesize <= 512 } &&
          authored_at <= now + 5.minutes && finalized_at.between?(expected_fetch.created_at - 5.minutes, now + 5.minutes) &&
          token_expires_at > finalized_at && token_expires_at <= finalized_at + 65.minutes
        raise Invalid, "signed source fetch result scope does not match the fetch request"
      end
    rescue TypeError, ArgumentError, NoMethodError
      raise Invalid, "signed source fetch result contains invalid values"
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
