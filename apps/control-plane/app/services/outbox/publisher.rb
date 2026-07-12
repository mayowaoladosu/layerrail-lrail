require "socket"

module Outbox
  class Publisher
    Result = Data.define(:claimed, :published, :retried, :discarded)
    MAX_ATTEMPTS = 20

    def initialize(transport:, repository: Repository.new, worker_name: default_worker_name, clock: Time)
      @transport = transport
      @repository = repository
      @worker_name = worker_name
      @clock = clock
    end

    def publish_batch(limit: 25)
      events = @repository.claim(worker_name: @worker_name, limit:)
      counters = { published: 0, retried: 0, discarded: 0 }

      events.each do |event|
        publish(event)
        counters[:published] += 1
      rescue Events::Envelope::Invalid, Events::NoSecrets::ForbiddenKey => error
        finish_failure(event, error, dead_letter: true)
        counters[:discarded] += 1
      rescue StandardError => error
        dead_letter = event.publish_attempts >= MAX_ATTEMPTS
        finish_failure(event, error, dead_letter:)
        counters[dead_letter ? :discarded : :retried] += 1
      end

      Result.new(events.length, counters[:published], counters[:retried], counters[:discarded])
    end

    private

    def publish(event)
      envelope = Events::Envelope.from(event)
      @transport.publish(
        subject: @transport.subject_for(event.event_type),
        payload: JSON.generate(envelope),
        message_id: event.public_id,
      )
      @repository.finish(
        event:,
        worker_name: @worker_name,
        published: true,
      )
    end

    def finish_failure(event, error, dead_letter:)
      retry_at = dead_letter ? nil : @clock.current + retry_delay(event.publish_attempts)
      message = "#{error.class}: #{error.message}".first(2048)
      @repository.finish(
        event:,
        worker_name: @worker_name,
        published: false,
        error: message,
        retry_at:,
        dead_letter:,
      )
    end

    def retry_delay(attempt)
      [ 2**[ attempt, 8 ].min, 5.minutes.to_i ].min.seconds
    end

    def default_worker_name
      "#{Socket.gethostname}:#{Process.pid}:#{SecureRandom.hex(4)}"
    end
  end
end
