require "minitest/autorun"
require "securerandom"
require "timeout"
require "lrail_control_workers"
require "temporalio/worker/workflow_replayer"

class TemporalWorkflowTest < Minitest::Test
  TEMPORAL_ADDRESS = ENV.fetch("LRAIL_TEMPORAL_ADDRESS", "temporal:7233")
  TEMPORAL_NAMESPACE = ENV.fetch("LRAIL_TEMPORAL_NAMESPACE", "default")

  def setup
    @client = Temporalio::Client.connect(TEMPORAL_ADDRESS, TEMPORAL_NAMESPACE)
    @task_queue = "lrail-test-#{SecureRandom.hex(8)}"
    @starter = LrailControlWorkers::Starter.new(client: @client, task_queue: @task_queue)
  end

  def test_duplicate_start_worker_restart_and_completion
    input = workflow_input
    first_handle = nil

    worker.run do
      first_handle = @starter.start(input)
      duplicate_handle = @starter.start(input)
      assert_equal first_handle.id, duplicate_handle.id
      wait_for_phase(first_handle, "waiting")
    end

    worker.run do
      resumed_handle = @client.workflow_handle(input.fetch("idempotency_key"))
      resumed_handle.signal(LrailControlWorkers::Workflows::ProjectProvisioning.complete)
      result = resumed_handle.result
      assert_equal "completed", result.fetch("status")
      assert_equal input.fetch("project_id"), result.fetch("project_id")
      assert_equal input.fetch("idempotency_key"), result.fetch("idempotency_key")
      Temporalio::Worker::WorkflowReplayer.new(
        workflows: [ LrailControlWorkers::Workflows::ProjectProvisioning ]
      ).replay_workflow(resumed_handle.fetch_history)
    end
  ensure
    terminate_if_running(first_handle)
  end

  def test_cancellation_reaches_a_terminal_failure
    handle = nil

    worker.run do
      handle = @starter.start(workflow_input)
      wait_for_phase(handle, "waiting")
      handle.cancel
      error = assert_raises(Temporalio::Error::WorkflowFailedError) { handle.result }
      assert_instance_of Temporalio::Error::CanceledError, error.cause
    end
  ensure
    terminate_if_running(handle)
  end

  private

  def worker
    LrailControlWorkers::WorkerFactory.build(client: @client, task_queue: @task_queue)
  end

  def workflow_input
    project_id = "prj_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}"
    {
      "project_id" => project_id,
      "operation_id" => "op_019b01da-7e31-7000-8000-#{SecureRandom.hex(6)}",
      "idempotency_key" => "project/#{project_id}/provision/1"
    }
  end

  def wait_for_phase(handle, expected)
    Timeout.timeout(15) do
      loop do
        begin
          return if handle.query(LrailControlWorkers::Workflows::ProjectProvisioning.phase) == expected
        rescue Temporalio::Error::RPCError
          nil
        end
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
