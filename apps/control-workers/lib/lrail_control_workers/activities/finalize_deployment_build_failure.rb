require "time"
require "temporalio/activity"

module LrailControlWorkers
  module Activities
    class FinalizeDeploymentBuildFailure < Temporalio::Activity::Definition
      activity_name "lrail.deployment.finalize_build_failure.v1"

      def initialize(control_plane: nil, clock: nil)
        super()
        @control_plane = control_plane
        @clock = clock || Time.method(:now)
      end

      def execute(input)
        build_id = input.fetch("build_id")
        generation = Integer(input.fetch("generation"))
        plan = input.fetch("plan")
        source = plan.fetch("source")
        validate_identity!(input:, plan:, source:, build_id:, generation:)
        result = {
          "build_id" => build_id,
          "generation" => generation,
          "source_snapshot_id" => source.fetch("snapshot_id"),
          "source_digest" => source.fetch("snapshot_digest"),
          "state" => "failed",
          "failure_code" => "build_activity_exhausted",
          "failure_message" => "Build control became unavailable before a terminal result was persisted.",
          "finished_at" => @clock.call.utc.iso8601(6),
          "cleanup" => { "status" => "unknown" }
        }
        control_plane.finalize(input, build_id:, result:)
        { "build_id" => build_id, "generation" => generation, "state" => "failed" }
      end

      private

      def control_plane
        @control_plane ||= ControlPlaneClient.new
      end

      def validate_identity!(input:, plan:, source:, build_id:, generation:)
        expected = {
          "build_id" => build_id,
          "organization_id" => input.fetch("organization_id"),
          "deployment_id" => input.fetch("deployment_id"),
          "operation_id" => input.fetch("operation_id"),
          "generation" => generation
        }
        actual = expected.keys.to_h do |key|
          [ key, key == "generation" ? Integer(plan.fetch(key)) : plan.fetch(key) ]
        end
        raise ArgumentError, "failed build identity is inconsistent" unless
          valid_build_identity?(build_id, generation) && actual == expected && valid_source_identity?(source)
      rescue KeyError, TypeError, ArgumentError
        raise ArgumentError, "failed build identity is inconsistent"
      end

      def valid_build_identity?(build_id, generation)
        build_id.match?(/\Abld_[0-9a-f-]{36}\z/) && generation.positive?
      end

      def valid_source_identity?(source)
        source.fetch("snapshot_id").match?(/\Asnp_[0-9a-f-]{36}\z/) &&
          source.fetch("snapshot_digest").match?(/\Asha256:[0-9a-f]{64}\z/)
      end
    end
  end
end
