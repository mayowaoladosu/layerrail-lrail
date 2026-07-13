require "minitest/autorun"
require "lrail_control_workers"

class DeploymentEventStarterTest < Minitest::Test
  class FakeStarter
    attr_reader :started, :canceled

    def start_deployment(input)
      @started = input
    end

    def cancel_deployment(workflow_id, reason:)
      @canceled = [ workflow_id, reason ]
    end
  end

  def setup
    @temporal = FakeStarter.new
    @starter = LrailControlWorkers::DeploymentEventStarter.allocate
    @starter.instance_variable_set(:@starter, @temporal)
  end

  def envelope(event_type: "deployment.created", data: nil)
    workflow_id = "deployment/dep_019b01da-7e31-7000-8000-000000000003/build/1"
    {
      "event_id" => "evt_019b01da-7e31-7000-8000-000000000009",
      "event_type" => event_type,
      "schema_version" => 1,
      "organization_id" => "org_019b01da-7e31-7000-8000-000000000002",
      "resource" => { "type" => "deployment", "id" => "dep_019b01da-7e31-7000-8000-000000000003" },
      "actor" => { "type" => "account", "id" => "acct_019b01da-7e31-7000-8000-000000000001" },
      "data" => data || {
        "environment_id" => "env_019b01da-7e31-7000-8000-000000000006",
        "operation_id" => "op_019b01da-7e31-7000-8000-000000000004",
        "source_snapshot_id" => "snp_019b01da-7e31-7000-8000-000000000007",
        "workflow_id" => workflow_id
      }
    }
  end

  def test_starts_one_generation_bound_workflow_from_created_event
    @starter.process(envelope)

    assert_equal "dep_019b01da-7e31-7000-8000-000000000003", @temporal.started.fetch("deployment_id")
    assert_equal "op_019b01da-7e31-7000-8000-000000000004", @temporal.started.fetch("operation_id")
    assert_equal 1, @temporal.started.fetch("generation")
    assert_equal @temporal.started.fetch("workflow_id"), @temporal.started.fetch("idempotency_key")
  end

  def test_signals_exact_workflow_from_canceling_event
    workflow_id = "deployment/dep_019b01da-7e31-7000-8000-000000000003/build/1"
    @starter.process(envelope(
                       event_type: "deployment.canceling",
                       data: {
                         "from" => "building",
                         "to" => "canceling",
                         "reason" => "user_requested",
                         "workflow_id" => workflow_id
                       }
                     ))

    assert_equal [ workflow_id, "user_requested" ], @temporal.canceled
  end

  def test_rejects_unknown_fields_and_non_account_actor
    injected = envelope
    injected.fetch("data")["secret"] = "must-not-enter-workflow-history"
    assert_raises(ArgumentError) { @starter.process(injected) }

    forged = envelope
    forged["actor"] = { "type" => "system", "id" => nil }
    assert_raises(ArgumentError) { @starter.process(forged) }
    assert_nil @temporal.started
  end
end
