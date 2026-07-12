namespace :lrail do
  namespace :workers do
    desc "Publish one claimed batch from the transactional outbox"
    task outbox_once: :environment do
      WorkerDatabase.connect!
      transport = Outbox::NatsTransport.new
      result = Outbox::Publisher.new(transport:).publish_batch(limit: ENV.fetch("BATCH_SIZE", 25))
      puts JSON.generate(result.to_h)
    ensure
      transport&.close
    end

    desc "Continuously publish transactional outbox events"
    task outbox: :environment do
      WorkerDatabase.connect!
      transport = Outbox::NatsTransport.new
      publisher = Outbox::Publisher.new(transport:)
      run_worker_loop("outbox") do
        publisher.publish_batch(limit: ENV.fetch("BATCH_SIZE", 25))
      end
    ensure
      transport&.close
    end

    desc "Deliver one claimed batch of email intents"
    task email_once: :environment do
      WorkerDatabase.connect!
      adapter = Email::AdapterFactory.build
      result = Email::DeliveryWorker.new(adapter:).deliver_batch(limit: ENV.fetch("BATCH_SIZE", 25))
      puts JSON.generate(result.to_h)
    end

    desc "Continuously deliver email intents"
    task email: :environment do
      WorkerDatabase.connect!
      worker = Email::DeliveryWorker.new(adapter: Email::AdapterFactory.build)
      run_worker_loop("email") do
        worker.deliver_batch(limit: ENV.fetch("BATCH_SIZE", 25))
      end
    end

    desc "Consume one batch of project provisioning events"
    task project_events_once: :environment do
      consumer = project_event_consumer
      puts JSON.generate(consumed: consumer.consume_batch(limit: ENV.fetch("BATCH_SIZE", 25)))
    ensure
      consumer&.close
    end

    desc "Continuously consume project provisioning events"
    task project_events: :environment do
      consumer = project_event_consumer
      run_worker_loop("project-events") do
        Struct.new(:claimed).new(consumer.consume_batch(limit: ENV.fetch("BATCH_SIZE", 25)))
      end
    ensure
      consumer&.close
    end

    desc "Expire one bounded batch of abandoned source upload sessions"
    task source_expiry_once: :environment do
      WorkerDatabase.connect!
      limit = Integer(ENV.fetch("BATCH_SIZE", 100)).clamp(1, 500)
      expired = ApplicationRecord.connection.select_values(
        "SELECT * FROM lrail_expire_source_upload_sessions(#{limit})",
      )
      puts JSON.generate(expired: expired.length)
    end
  end
end

def project_event_consumer
  processor = Inbox::Processor.new(
    consumer: "project-provisioner-v1",
    context_resolver: Inbox::ActorContextResolver.method(:call),
    handler: Projects::ProvisioningEventHandler.method(:call),
  )
  Inbox::NatsConsumer.new(
    subject: "lrail.domain.v1.project.created",
    durable: "project-provisioner-v1",
    processor:,
  )
end

def run_worker_loop(name)
  stopping = false
  %w[INT TERM].each { |signal| Signal.trap(signal) { stopping = true } }
  idle_seconds = Float(ENV.fetch("IDLE_SECONDS", "0.5"))

  until stopping
    begin
      result = yield
      sleep idle_seconds if result.claimed.zero?
    rescue StandardError => error
      Rails.logger.error(
        event: "worker_iteration_failed",
        worker: name,
        error_class: error.class.name,
        error_message: error.message.first(512),
      )
      sleep idle_seconds
    end
  end
end
