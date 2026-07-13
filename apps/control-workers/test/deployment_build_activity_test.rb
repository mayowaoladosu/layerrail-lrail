require "minitest/autorun"
require "lrail_control_workers"

class DeploymentBuildActivityTest < Minitest::Test
  FakeCancellation = Struct.new(:canceled, :reason) do
    def canceled?
      canceled
    end

    def canceled_reason
      reason
    end
  end

  class FakeContext
    attr_reader :cancellation, :heartbeats

    def initialize(cancellation)
      @cancellation = cancellation
      @heartbeats = []
    end

    def heartbeat(value)
      @heartbeats << value
    end
  end

  class FakeControlPlane
    attr_reader :events, :result

    def initialize(prepared = nil)
      @prepared = prepared
      @events = []
    end

    def prepare(_input)
      @prepared
    end

    def persist_events(_input, build_id:, events:)
      @events << [ build_id, events ]
    end

    def finalize(_input, build_id:, result:)
      @result = [ build_id, result ]
    end
  end

  class FakeBuildService
    attr_reader :submitted, :canceled

    def initialize(watches)
      @watches = watches
    end

    def submit(plan)
      @submitted = plan
      { "state" => "accepted" }
    end

    def watch(**)
      @watches.shift || raise("unexpected watch")
    end

    def cancel(**values)
      @canceled = values
      { "state" => "canceling" }
    end
  end

  def workflow_input
    {
      "actor_id" => "acct_019b01da-7e31-7000-8000-000000000001",
      "organization_id" => "org_019b01da-7e31-7000-8000-000000000002",
      "deployment_id" => "dep_019b01da-7e31-7000-8000-000000000003",
      "operation_id" => "op_019b01da-7e31-7000-8000-000000000004",
      "workflow_id" => "deployment/dep_019b01da-7e31-7000-8000-000000000003/build/1",
      "idempotency_key" => "deployment/dep_019b01da-7e31-7000-8000-000000000003/build/1",
      "generation" => 1
    }
  end

  def prepared_input
    build_id = "bld_019b01da-7e31-7000-8000-000000000005"
    workflow_input.merge(
      "build_id" => build_id,
      "after_sequence" => 0,
      "plan" => {
        "build_id" => build_id,
        "organization_id" => workflow_input.fetch("organization_id"),
        "deployment_id" => workflow_input.fetch("deployment_id"),
        "operation_id" => workflow_input.fetch("operation_id"),
        "generation" => 1
      }
    )
  end

  def test_prepares_then_streams_and_finalizes_terminal_build
    input = prepared_input
    build_id = input.fetch("build_id")
    event = { "sequence" => 1, "line" => "safe build output" }
    result = { "state" => "complete", "build_id" => build_id }
    build_service = FakeBuildService.new([
                                           { "events" => [ event ], "run" => { "state" => "running" } },
                                           { "events" => [], "run" => { "state" => "complete", "result" => result } }
                                         ])
    control_plane = FakeControlPlane.new
    context = FakeContext.new(FakeCancellation.new(false, nil))
    activity = LrailControlWorkers::Activities::ExecuteDeploymentBuild.new(
      control_plane:,
      build_service:,
      activity_context: context
    )

    value = activity.execute(input)

    assert_equal "complete", value.fetch("state")
    assert_equal input.fetch("plan"), build_service.submitted
    assert_equal [ [ build_id, [ event ] ] ], control_plane.events
    assert_equal [ build_id, result ], control_plane.result
    assert_equal 1, context.heartbeats.last.fetch("after_sequence")
  end

  def test_cancellation_calls_exact_generation_and_waits_for_terminal_result
    input = prepared_input
    build_id = input.fetch("build_id")
    result = { "state" => "canceled", "build_id" => build_id }
    build_service = FakeBuildService.new([
                                           { "events" => [], "run" => { "state" => "canceled", "result" => result } }
                                         ])
    control_plane = FakeControlPlane.new
    context = FakeContext.new(FakeCancellation.new(true, "user_requested"))
    activity = LrailControlWorkers::Activities::ExecuteDeploymentBuild.new(
      control_plane:,
      build_service:,
      activity_context: context
    )

    value = activity.execute(input)

    assert_equal "canceled", value.fetch("state")
    assert_equal({ build_id:, generation: 1, reason: "user_requested" }, build_service.canceled)
    assert_equal [ build_id, result ], control_plane.result
  end

  def test_rejects_cross_resource_plan_substitution_before_submission
    input = prepared_input
    input.fetch("plan")["organization_id"] = "org_019b01da-7e31-7000-8000-000000000099"
    build_service = FakeBuildService.new([])
    activity = LrailControlWorkers::Activities::ExecuteDeploymentBuild.new(
      control_plane: FakeControlPlane.new,
      build_service:,
      activity_context: FakeContext.new(FakeCancellation.new(false, nil))
    )

    assert_raises(ArgumentError) { activity.execute(input) }
    assert_nil build_service.submitted
  end
end
