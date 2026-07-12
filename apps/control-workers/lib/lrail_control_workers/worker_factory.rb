module LrailControlWorkers
  class WorkerFactory
    def self.build(client:, task_queue: Starter::TASK_QUEUE)
      Temporalio::Worker.new(
        client:,
        task_queue:,
        workflows: [ Workflows::ProjectProvisioning ],
        activities: [ Activities::IdempotentReceipt ]
      )
    end
  end
end
