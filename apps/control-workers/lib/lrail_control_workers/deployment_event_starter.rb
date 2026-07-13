require "json"
require "nats/client"

module LrailControlWorkers
  class DeploymentEventStarter
    SUBJECT = "lrail.domain.v1.deployment.*".freeze
    DURABLE = "deployment-temporal-starter-v1".freeze

    def initialize(
      starter:,
      url: ENV.fetch("LRAIL_NATS_URL"),
      stream: ENV.fetch("LRAIL_NATS_STREAM", "LRAIL_DOMAIN_V1"),
      connection: nil
    )
      @starter = starter
      @stream = stream
      @connection = connection || NATS.connect(
        servers: [ url ],
        name: "lrail-deployment-temporal-starter",
        reconnect: true,
        max_reconnect_attempts: 60,
        reconnect_time_wait: 1
      )
      jetstream = @connection.jetstream(timeout: 5)
      ensure_consumer!(jetstream)
      @subscription = jetstream.pull_subscribe(SUBJECT, DURABLE, stream: @stream)
    end

    def run(cancellation:)
      until cancellation.canceled?
        begin
          messages = @subscription.fetch(25, timeout: 1)
          messages.each { |message| process_message(message) }
        rescue NATS::Timeout
          nil
        end
      end
    ensure
      close
    end

    def process(envelope)
      event = DeploymentEvent.parse(envelope)
      if event.created?
        @starter.start_deployment(event.workflow_input)
      else
        @starter.cancel_deployment(event.workflow_id, reason: event.reason)
      end
    end

    def close
      @subscription&.unsubscribe
      @connection&.drain
      @connection&.close
      @subscription = nil
      @connection = nil
    rescue NATS::Error
      nil
    end

    private

    def process_message(message)
      process(JSON.parse(message.data))
      message.ack_sync(timeout: 1)
    rescue JSON::ParserError, ArgumentError, KeyError
      message.term
    rescue StandardError
      message.nak(delay: 1_000_000_000)
    end

    def ensure_consumer!(jetstream)
      info = jetstream.consumer_info(@stream, DURABLE)
      raise "deployment starter NATS filter mismatch" unless info.config.filter_subject == SUBJECT
    rescue NATS::JetStream::Error::NotFound
      jetstream.add_consumer(
        @stream,
        durable_name: DURABLE,
        ack_policy: "explicit",
        ack_wait: 30,
        max_deliver: 20,
        deliver_policy: "all",
        filter_subject: SUBJECT
      )
    end
  end
end
