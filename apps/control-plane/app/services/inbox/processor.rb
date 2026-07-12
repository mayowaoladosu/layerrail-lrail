module Inbox
  class Processor
    Result = Data.define(:outcome, :message)
    MAX_ATTEMPTS = 8

    def initialize(consumer:, context_resolver:, handler:)
      @consumer = consumer
      @context_resolver = context_resolver
      @handler = handler
    end

    def process(envelope:, subject:, headers: {})
      Events::Envelope.validate!(envelope)
      payload_digest = "sha256:#{Digest::SHA256.hexdigest(JSON.generate(envelope))}"
      organization_id = envelope.fetch("organization_id")
      account, organization = @context_resolver.call(organization_id, envelope)
      raise OrganizationContext::MissingContext, "event organization does not match context" unless organization.public_id == organization_id

      OrganizationContext.with(account:, organization:) do
        process_in_context(organization:, envelope:, subject:, headers:, payload_digest:)
      end
    end

    private

    def process_in_context(organization:, envelope:, subject:, headers:, payload_digest:)
      event_id = envelope.fetch("event_id")
      message = InboxMessage.find_by(consumer: @consumer, event_public_id: event_id)
      if message&.state == "completed"
        return Result.new(:duplicate, message)
      end
      if message&.state == "dead_lettered"
        return Result.new(:dead_lettered, message)
      end

      message ||= InboxMessage.create!(
        organization:,
        consumer: @consumer,
        event_public_id: event_id,
        event_type: envelope.fetch("event_type"),
        schema_version: envelope.fetch("schema_version"),
        subject:,
        payload_digest:,
        state: "processing",
        attempt_count: 0,
        first_received_at: Time.current,
      )
      message.increment!(:attempt_count)
      ApplicationRecord.transaction(requires_new: true) do
        @handler.call(envelope)
        message.update!(state: "completed", processed_at: Time.current, last_error: nil)
      end
      Result.new(:processed, message)
    rescue StandardError => error
      dead_letter = record_failure!(
        organization:,
        message:,
        envelope:,
        subject:,
        headers:,
        error:,
      )
      Result.new(dead_letter ? :dead_lettered : :retry, message)
    end

    def record_failure!(organization:, message:, envelope:, subject:, headers:, error:)
      return false unless message

      dead_letter = message.attempt_count >= MAX_ATTEMPTS
      message.update!(
        state: dead_letter ? "dead_lettered" : "processing",
        last_error: "#{error.class}: #{error.message}".first(2048),
      )
      return false unless dead_letter

      DeadLetterMessage.find_or_create_by!(consumer: @consumer, event_public_id: message.event_public_id) do |letter|
        letter.organization = organization
        letter.event_type = message.event_type
        letter.subject = subject
        letter.reason = message.last_error
        letter.event_payload = envelope
        letter.message_headers = safe_headers(headers)
        letter.attempt_count = message.attempt_count
        letter.first_failed_at = message.first_received_at
        letter.last_failed_at = Time.current
      end
      true
    end

    def safe_headers(headers)
      headers.to_h.each_with_object({}) do |(key, value), sanitized|
        next if Events::NoSecrets::FORBIDDEN_KEY.match?(key.to_s)

        sanitized[key.to_s.first(128)] = value.to_s.first(512)
      end
    end
  end
end
