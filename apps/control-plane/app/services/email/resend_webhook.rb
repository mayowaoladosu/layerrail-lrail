require "svix"

module Email
  class ResendWebhook
    Invalid = Class.new(StandardError)
    SUPPORTED_TYPES = %w[
      email.sent
      email.delivered
      email.delivery_delayed
      email.bounced
      email.complained
      email.failed
      email.suppressed
    ].freeze

    Result = Data.define(:outcome, :event_type, :provider_message_id)

    def initialize(secret: ENV.fetch("RESEND_WEBHOOK_SECRET"), connection: ApplicationRecord.connection)
      @webhook = Svix::Webhook.new(secret)
      @connection = connection
    end

    def process(raw_body:, headers:)
      normalized_headers = normalize_headers(headers)
      payload = @webhook.verify(raw_body, normalized_headers)
      event_type = payload.fetch(:type).to_s
      raise Invalid, "unsupported Resend event type" unless SUPPORTED_TYPES.include?(event_type)

      provider_message_id = payload.dig(:data, :email_id) || payload.dig(:data, :id)
      raise Invalid, "Resend event is missing email id" if provider_message_id.blank?

      outcome = apply(
        delivery_id: normalized_headers.fetch("svix-id"),
        delivery_type: event_type,
        payload_sha256: "sha256:#{Digest::SHA256.hexdigest(raw_body)}",
        message_id: provider_message_id,
        event_time: payload[:created_at],
      )
      Result.new(outcome, event_type, provider_message_id)
    rescue Svix::WebhookVerificationError, JSON::ParserError, KeyError => error
      raise Invalid, error.message
    end

    private

    def normalize_headers(headers)
      values = headers.to_h.transform_keys { |key| key.to_s.downcase }
      {
        "svix-id" => values["svix-id"] || values["http_svix_id"],
        "svix-timestamp" => values["svix-timestamp"] || values["http_svix_timestamp"],
        "svix-signature" => values["svix-signature"] || values["http_svix_signature"]
      }
    end

    def apply(delivery_id:, delivery_type:, payload_sha256:, message_id:, event_time:)
      values = [
        @connection.quote(delivery_id),
        @connection.quote(delivery_type),
        @connection.quote(payload_sha256),
        @connection.quote(message_id),
        @connection.quote(event_time)
      ]
      @connection.select_value(<<~SQL.squish)
        SELECT lrail_apply_email_provider_event(#{values.join(", ")})
      SQL
    end
  end
end
