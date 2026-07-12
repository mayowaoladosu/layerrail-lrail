module Idempotency
  class Execute
    Result = Data.define(:status, :body, :replayed)

    def self.call(key:, principal:, organization:, http_method:, route:, payload:)
      raise ArgumentError, "Idempotency-Key must contain 16 to 128 safe characters" unless key.to_s.match?(/\A[A-Za-z0-9._:-]{16,128}\z/)

      key_digest = Digest::SHA256.hexdigest(key)
      request_fingerprint = Digest::SHA256.hexdigest(canonical_json(payload))
      scope = {
        organization:,
        principal_public_id: principal.public_id,
        http_method: http_method.to_s.upcase,
        normalized_route: route,
        key_digest:
      }

      IdempotencyKey.transaction do
        record = IdempotencyKey.lock.find_by(scope)
        if record
          raise Mismatch, "idempotency key was used with different input" unless ActiveSupport::SecurityUtils.secure_compare(record.request_fingerprint, request_fingerprint)
          return Result.new(record.response_status, record.response_body, true) if record.response_status
        else
          record = create_record!(scope, request_fingerprint)
        end

        status, body = yield
        record.update!(response_status: status, response_body: body)
        Result.new(status, body, false)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    def self.create_record!(scope, request_fingerprint)
      IdempotencyKey.create!(
        **scope,
        request_fingerprint:,
        expires_at: 24.hours.from_now,
      )
    end

    def self.canonical_json(value)
      case value
      when Hash
        "{#{value.stringify_keys.sort.map { |key, item| "#{key.to_json}:#{canonical_json(item)}" }.join(",")}}"
      when Array
        "[#{value.map { |item| canonical_json(item) }.join(",")}]"
      else
        value.to_json
      end
    end

    private_class_method :create_record!, :canonical_json
  end
end
