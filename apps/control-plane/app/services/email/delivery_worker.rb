require "socket"

module Email
  class DeliveryWorker
    Result = Data.define(:claimed, :delivered, :retried, :failed)
    MAX_ATTEMPTS = 12

    def initialize(adapter:, repository: Repository.new, worker_name: default_worker_name, clock: Time)
      @adapter = adapter
      @repository = repository
      @worker_name = worker_name
      @clock = clock
    end

    def deliver_batch(limit: 25)
      intents = @repository.claim(worker_name: @worker_name, limit:)
      counters = { delivered: 0, retried: 0, failed: 0 }

      intents.each do |intent|
        deliver(intent)
        counters[:delivered] += 1
      rescue TemplateRegistry::UnknownTemplate, KeyError, ArgumentError, ::Resend::Error::InvalidRequestError => error
        finish_failure(intent, error, retryable: false)
        counters[:failed] += 1
      rescue StandardError => error
        retryable = intent.attempt_count < MAX_ATTEMPTS
        finish_failure(intent, error, retryable:)
        counters[retryable ? :retried : :failed] += 1
      end

      Result.new(intents.length, counters[:delivered], counters[:retried], counters[:failed])
    end

    private

    def deliver(intent)
      rendered = TemplateRegistry.render(intent)
      message_id = @adapter.deliver(intent:, rendered:)
      @repository.finish(
        intent:,
        worker_name: @worker_name,
        state: @adapter.terminal_state,
        provider: @adapter.provider_name,
        message_id:,
      )
    end

    def finish_failure(intent, error, retryable:)
      state = retryable ? "retryable" : "failed"
      retry_at = retryable ? @clock.current + retry_delay(intent.attempt_count) : nil
      @repository.finish(
        intent:,
        worker_name: @worker_name,
        state:,
        provider: @adapter.provider_name,
        error: "#{error.class}: #{error.message}".first(2048),
        retry_at:,
      )
    end

    def retry_delay(attempt)
      [ 2**[ attempt, 10 ].min, 30.minutes.to_i ].min.seconds
    end

    def default_worker_name
      "#{Socket.gethostname}:#{Process.pid}:email:#{SecureRandom.hex(4)}"
    end
  end
end
