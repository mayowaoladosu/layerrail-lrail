require "nats/client"

module Outbox
  class NatsTransport
    DEFAULT_STREAM = "LRAIL_DOMAIN_V1"
    DEFAULT_SUBJECT_PREFIX = "lrail.domain.v1"

    attr_reader :stream, :subject_prefix

    def initialize(
      url: ENV.fetch("LRAIL_NATS_URL", "nats://127.0.0.1:54222"),
      stream: ENV.fetch("LRAIL_NATS_STREAM", DEFAULT_STREAM),
      subject_prefix: ENV.fetch("LRAIL_NATS_SUBJECT_PREFIX", DEFAULT_SUBJECT_PREFIX),
      connection: nil
    )
      @stream = stream
      @subject_prefix = subject_prefix
      @connection = connection || NATS.connect(
        servers: [ url ],
        name: "lrail-control-outbox",
        reconnect: true,
        max_reconnect_attempts: 60,
        reconnect_time_wait: 1,
      )
      @jetstream = @connection.jetstream(timeout: 5)
      ensure_stream!
    end

    def publish(subject:, payload:, message_id:)
      raise ArgumentError, "subject is outside the configured namespace" unless subject.start_with?("#{@subject_prefix}.")

      @jetstream.publish(
        subject,
        payload,
        stream: @stream,
        header: {
          "Nats-Msg-Id" => message_id,
          "Content-Type" => "application/json"
        },
      )
    end

    def subject_for(event_type)
      "#{@subject_prefix}.#{event_type}"
    end

    def close
      @connection.drain
      @connection.close
    end

    private

    def ensure_stream!
      info = @jetstream.stream_info(@stream)
      configured = Array(info.config.subjects).sort
      expected = [ "#{@subject_prefix}.>" ]
      raise "NATS stream #{@stream} subject mismatch" unless configured == expected
    rescue NATS::JetStream::Error::NotFound
      @jetstream.add_stream(
        name: @stream,
        subjects: [ "#{@subject_prefix}.>" ],
        storage: "file",
        retention: "limits",
        discard: "old",
        max_age: 30.days.to_i * 1_000_000_000,
        duplicate_window: 10.minutes.to_i * 1_000_000_000,
      )
    end
  end
end
