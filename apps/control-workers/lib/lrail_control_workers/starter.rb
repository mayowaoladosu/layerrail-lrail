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

    def start_deployment(input)
      workflow_id = input.fetch("idempotency_key")
      @client.start_workflow(
        Workflows::DeploymentBuild,
        input,
        id: workflow_id,
        task_queue: @task_queue
      )
    rescue Temporalio::Error::WorkflowAlreadyStartedError
      @client.workflow_handle(workflow_id)
    end

    def cancel_deployment(workflow_id, reason: "user_requested")
      @client.workflow_handle(workflow_id).signal(
        Workflows::DeploymentBuild.request_cancel,
        reason.to_s[0, 512]
      )
    end
  end
end
