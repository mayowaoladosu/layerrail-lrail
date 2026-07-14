module LrailControlWorkers
  class WorkerFactory
    def self.build(client:, task_queue: Starter::TASK_QUEUE)
      Temporalio::Worker.new(
        client:,
        task_queue:,
        workflows: [ Workflows::ProjectProvisioning, Workflows::DeploymentBuild ],
        activities: [
          Activities::IdempotentReceipt,
          Activities::PrepareDeploymentBuild,
          Activities::ExecuteDeploymentBuild,
          Activities::CancelDeploymentBuild,
          Activities::FinalizeDeploymentBuildFailure
        ]
      )
    end
  end
end
