require "minitest/autorun"
require "securerandom"
require "timeout"
require "lrail_control_workers"
require "temporalio/worker/workflow_replayer"

class FakePrepareDeploymentBuild < Temporalio::Activity::Definition
  activity_name "lrail.deployment.prepare_build.v1"

  def execute(input)
    build_id = "bld_019b01da-7e31-7000-8000-000000000010"
    {
      "build_id" => build_id,
      "generation" => input.fetch("generation"),
      "after_sequence" => 0,
      "plan" => {
        "build_id" => build_id,
        "organization_id" => input.fetch("organization_id"),
        "deployment_id" => input.fetch("deployment_id"),
        "operation_id" => input.fetch("operation_id"),
        "generation" => input.fetch("generation")
      }
    }
  end
end

class FakeExecuteDeploymentBuild < Temporalio::Activity::Definition
  activity_name "lrail.deployment.execute_build.v1"

  def execute(input)
    if input["simulate_failure"]
      raise Temporalio::Error::ApplicationError.new("simulated build service loss", non_retryable: true)
    end

    context = Temporalio::Activity::Context.current
    200.times do |index|
      if FakeCancelDeploymentBuild.canceled?(input.fetch("build_id"))
        return { "build_id" => input.fetch("build_id"), "generation" => 1, "state" => "canceled" }
      end

      context.heartbeat({ "sequence" => index })
      sleep 0.025
    end
    { "build_id" => input.fetch("build_id"), "generation" => 1, "state" => "complete" }
  end
end

class FakeFinalizeDeploymentBuildFailure < Temporalio::Activity::Definition
  activity_name "lrail.deployment.finalize_build_failure.v1"

  def execute(input)
    {
      "build_id" => input.fetch("build_id"),
      "generation" => input.fetch("generation"),
      "state" => "failed"
    }
  end
end

class FakeCancelDeploymentBuild < Temporalio::Activity::Definition
  activity_name "lrail.deployment.cancel_build.v1"

  @mutex = Mutex.new
  @build_ids = Set.new

  class << self
    def cancel(build_id)
      @mutex.synchronize { @build_ids << build_id }
    end

    def canceled?(build_id)
      @mutex.synchronize { @build_ids.include?(build_id) }
    end

    def reset
      @mutex.synchronize { @build_ids.clear }
    end
  end

  def execute(input)
    self.class.cancel(input.fetch("build_id"))
    { "cancel_requested" => true }
  end
end

class DeploymentTemporalWorkflowTest < Minitest::Test
  TEMPORAL_ADDRESS = ENV.fetch("LRAIL_TEMPORAL_ADDRESS", "temporal:7233")
  TEMPORAL_NAMESPACE = ENV.fetch("LRAIL_TEMPORAL_NAMESPACE", "default")

  def setup
    FakeCancelDeploymentBuild.reset
    @client = Temporalio::Client.connect(TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE)
    @task_queue = "lrail-deployment-test-#{SecureRandom.hex(8)}"
    @starter = LrailControlWorkers::Starter.new(client: @client, task_queue: @task_queue)
  end

  def test_duplicate_start_completion_and_replay
    input = workflow_input
    handle = nil
    worker.run do
      handle = @starter.start_deployment(input)
      duplicate = @starter.start_deployment(input)
      assert_equal handle.id, duplicate.id
      result = handle.result
      assert_equal "complete", result.fetch("state")
      assert_equal input.fetch("deployment_id"), result.fetch("deployment_id")
      Temporalio::Worker::WorkflowReplayer.new(
        workflows: [ LrailControlWorkers::Workflows::DeploymentBuild ]
      ).replay_workflow(handle.fetch_history)
    end
  ensure
    terminate_if_running(handle)
  end

  def test_cancel_signal_reconciles_activity_before_workflow_completion
    input = workflow_input
    handle = nil
    worker.run do
      handle = @starter.start_deployment(input)
      wait_for_phase(handle, "building")
      sleep 0.2
      @starter.cancel_deployment(input.fetch("workflow_id"), reason: "user_requested")
      wait_for_phase(handle, "canceling")
      result = handle.result
      assert_equal "canceled", result.fetch("state")
      assert_equal input.fetch("workflow_id"), result.fetch("workflow_id")
    end
  ensure
    terminate_if_running(handle)
  end

  def test_activity_failure_converges_to_terminal_failed_result
    input = workflow_input.merge("simulate_failure" => true)
    handle = nil
    worker.run do
      handle = @starter.start_deployment(input)
      result = handle.result
      assert_equal "failed", result.fetch("state")
      assert_equal input.fetch("deployment_id"), result.fetch("deployment_id")
      Temporalio::Worker::WorkflowReplayer.new(
        workflows: [ LrailControlWorkers::Workflows::DeploymentBuild ]
      ).replay_workflow(handle.fetch_history)
    end
  ensure
    terminate_if_running(handle)
  end

  private

  def worker
    Temporalio::Worker.new(
      client: @client,
      task_queue: @task_queue,
      workflows: [ LrailControlWorkers::Workflows::DeploymentBuild ],
      activities: [
        FakePrepareDeploymentBuild,
        FakeExecuteDeploymentBuild,
        FakeCancelDeploymentBuild,
        FakeFinalizeDeploymentBuildFailure
      ]
    )
  end

  def workflow_input
    deployment_id = "dep_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}"
    workflow_id = "deployment/#{deployment_id}/build/1"
    {
      "actor_id" => "acct_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}",
      "organization_id" => "org_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}",
      "deployment_id" => deployment_id,
      "operation_id" => "op_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}",
      "workflow_id" => workflow_id,
      "idempotency_key" => workflow_id,
      "generation" => 1
    }
  end

  def wait_for_phase(handle, expected)
    Timeout.timeout(15) do
      loop do
        return if handle.query(LrailControlWorkers::Workflows::DeploymentBuild.phase) == expected
      rescue Temporalio::Error::RPCError
        sleep 0.05
      end
    end
  end

  def terminate_if_running(handle)
    handle&.terminate("test cleanup")
  rescue Temporalio::Error::RPCError, Temporalio::Error::WorkflowNotFoundError
    nil
  end
end
