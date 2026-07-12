module LrailControlWorkers
  class Starter
    TASK_QUEUE = "lrail-control-v1".freeze

    def initialize(client:, task_queue: TASK_QUEUE)
      @client = client
      @task_queue = task_queue
    end

    def start(input)
      workflow_id = input.fetch("idempotency_key")
      @client.start_workflow(
        Workflows::ProjectProvisioning,
        input,
        id: workflow_id,
        task_queue: @task_queue
      )
    rescue Temporalio::Error::WorkflowAlreadyStartedError
      @client.workflow_handle(workflow_id)
    end
  end
end
