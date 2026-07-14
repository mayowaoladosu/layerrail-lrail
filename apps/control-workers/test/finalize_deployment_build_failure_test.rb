require "minitest/autorun"
require "lrail_control_workers"

class FinalizeDeploymentBuildFailureTest < Minitest::Test
  class FakeControlPlane
    attr_reader :result

    def finalize(_input, build_id:, result:)
      @result = [ build_id, result ]
    end
  end

  def test_records_bounded_fail_closed_result
    control_plane = FakeControlPlane.new
    activity = LrailControlWorkers::Activities::FinalizeDeploymentBuildFailure.new(
      control_plane:,
      clock: -> { Time.utc(2026, 7, 14, 0, 0, 0) }
    )

    value = activity.execute(input)

    assert_equal "failed", value.fetch("state")
    build_id, result = control_plane.result
    assert_equal input.fetch("build_id"), build_id
    assert_equal "build_activity_exhausted", result.fetch("failure_code")
    assert_equal "unknown", result.dig("cleanup", "status")
    assert_equal input.dig("plan", "source", "snapshot_id"), result.fetch("source_snapshot_id")
    assert_equal input.dig("plan", "source", "snapshot_digest"), result.fetch("source_digest")
  end

  private

  def input
    build_id = "bld_019b01da-7e31-7000-8000-000000000005"
    {
      "organization_id" => "org_019b01da-7e31-7000-8000-000000000002",
      "deployment_id" => "dep_019b01da-7e31-7000-8000-000000000003",
      "operation_id" => "op_019b01da-7e31-7000-8000-000000000004",
      "generation" => 1,
      "build_id" => build_id,
      "plan" => {
        "build_id" => build_id,
        "organization_id" => "org_019b01da-7e31-7000-8000-000000000002",
        "deployment_id" => "dep_019b01da-7e31-7000-8000-000000000003",
        "operation_id" => "op_019b01da-7e31-7000-8000-000000000004",
        "generation" => 1,
        "source" => {
          "snapshot_id" => "snp_019b01da-7e31-7000-8000-000000000006",
          "snapshot_digest" => "sha256:#{'a' * 64}"
        }
      }
    }
  end
end
