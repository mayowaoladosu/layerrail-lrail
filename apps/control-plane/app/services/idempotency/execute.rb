module Idempotency
  class Execute
    Result = Data.define(:status, :body, :replayed)

    def self.call(key:, principal:, organization:, http_method:, route:, payload:, expires_in: 24.hours)
      raise ArgumentError, "Idempotency-Key must contain 16 to 128 safe characters" unless key.to_s.match?(/\A[A-Za-z0-9._:-]{16,128}\z/)

      key_digest = Digest::SHA256.hexdigest(key)
      request_fingerprint = Digest::SHA256.hexdigest(CanonicalJson.dump(payload))
      scope = {
        organization:,
        principal_public_id: principal.public_id,
        http_method: http_method.to_s.upcase,
        normalized_route: route,
        key_digest:
      }

      IdempotencyKey.transaction do
        record = IdempotencyKey.lock.find_by(scope)
        if record && record.expires_at <= Time.current
          record.destroy!
          record = nil
        end
        if record
          raise Mismatch, "idempotency key was used with different input" unless ActiveSupport::SecurityUtils.secure_compare(record.request_fingerprint, request_fingerprint)
          return Result.new(record.response_status, record.response_body, true) if record.response_status
        else
          record = create_record!(scope, request_fingerprint, expires_in:)
        end

        status, body = yield
        record.update!(response_status: status, response_body: body)
        Result.new(status, body, false)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    def self.create_record!(scope, request_fingerprint, expires_in:)
      raise ArgumentError, "idempotency expiry must be between one minute and one day" unless expires_in.between?(1.minute, 24.hours)

      IdempotencyKey.create!(
        **scope,
        request_fingerprint:,
        expires_at: Time.current + expires_in,
      )
    end

    private_class_method :create_record!
  end
end
