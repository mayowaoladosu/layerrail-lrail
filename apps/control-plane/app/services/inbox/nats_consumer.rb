require "nats/client"

module Inbox
  class NatsConsumer
    def initialize(
      subject:,
      durable:,
      processor:,
      deliver_policy: "all",
      url: ENV.fetch("LRAIL_NATS_URL", "nats://127.0.0.1:54222"),
      stream: ENV.fetch("LRAIL_NATS_STREAM", Outbox::NatsTransport::DEFAULT_STREAM),
      connection: nil
    )
      @processor = processor
      @stream = stream
      @connection = connection || NATS.connect(
        servers: [ url ],
        name: "lrail-consumer-#{durable}",
        reconnect: true,
        max_reconnect_attempts: 60,
        reconnect_time_wait: 1,
      )
      jetstream = @connection.jetstream(timeout: 5)
      ensure_consumer!(jetstream, subject:, durable:, deliver_policy:)
      @subscription = jetstream.pull_subscribe(
        subject,
        durable,
        stream: @stream,
      )
    end

    def consume_batch(limit: 25, timeout: 1)
      messages = @subscription.fetch(Integer(limit).clamp(1, 100), timeout:)
      messages.each { |message| process(message) }
      messages.length
    rescue NATS::Timeout
      0
    end

    def close
      @subscription.unsubscribe
      @connection.drain
      @connection.close
    end

    private

    def ensure_consumer!(jetstream, subject:, durable:, deliver_policy:)
      info = jetstream.consumer_info(@stream, durable)
      raise "NATS consumer #{durable} filter mismatch" unless info.config.filter_subject == subject
    rescue NATS::JetStream::Error::NotFound
      jetstream.add_consumer(
        @stream,
        durable_name: durable,
        ack_policy: "explicit",
        ack_wait: 30,
        max_deliver: Processor::MAX_ATTEMPTS,
        deliver_policy:,
        filter_subject: subject,
      )
    end

    def process(message)
      envelope = JSON.parse(message.data)
      result = @processor.process(envelope:, subject: message.subject, headers: message.header || {})
      case result.outcome
      when :retry
        message.nak(delay: 1_000_000_000)
      when :dead_lettered
        message.term
      else
        message.ack_sync(timeout: 1)
      end
    rescue JSON::ParserError, Events::Envelope::Invalid, Events::NoSecrets::ForbiddenKey
      message.term
    rescue StandardError
      message.nak(delay: 1_000_000_000)
    end
  end
end
