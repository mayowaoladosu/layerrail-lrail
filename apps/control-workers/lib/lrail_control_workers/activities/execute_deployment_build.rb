require "temporalio/activity"

module LrailControlWorkers
  module Activities
    class ExecuteDeploymentBuild < Temporalio::Activity::Definition
      activity_name "lrail.deployment.execute_build.v1"
      TERMINAL_STATES = %w[complete failed canceled waiting].freeze

      def initialize(
        control_plane: nil,
        build_service: nil,
        activity_context: nil
      )
        super()
        @control_plane = control_plane
        @build_service = build_service
        @activity_context = activity_context
      end

      def execute(input)
        plan = input.fetch("plan")
        build_id = input.fetch("build_id")
        generation = Integer(input.fetch("generation"))
        after = Integer(input.fetch("after_sequence", 0))
        validate_identity!(input:, plan:, build_id:, generation:, after:)
        build_service.submit(plan)
        cancellation_sent = false

        loop do
          context = @activity_context || Temporalio::Activity::Context.current
          cancellation_sent = reconcile_cancellation(
            context:, build_id:, generation:, cancellation_sent:
          )
          watched = build_service.watch(build_id:, generation:, after:)
          after = persist_events(input:, build_id:, watched:, after:)
          context.heartbeat({ "after_sequence" => after, "cancellation_sent" => cancellation_sent })
          run = watched.fetch("run")
          next unless TERMINAL_STATES.include?(run.fetch("state"))

          return finalize(input:, build_id:, generation:, after:, run:)
        end
      end

      private

      def control_plane
        @control_plane ||= ControlPlaneClient.new
      end

      def build_service
        @build_service ||= BuildServiceClient.new
      end

      def reconcile_cancellation(context:, build_id:, generation:, cancellation_sent:)
        return cancellation_sent unless context.cancellation.canceled? && !cancellation_sent

        build_service.cancel(
          build_id:,
          generation:,
          reason: context.cancellation.canceled_reason || "workflow_requested"
        )
        true
      end

      def persist_events(input:, build_id:, watched:, after:)
        events = Array(watched.fetch("events"))
        return after if events.empty?

        control_plane.persist_events(input, build_id:, events:)
        next_sequence = Integer(events.last.fetch("sequence"))
        raise ArgumentError, "build event cursor did not advance" unless next_sequence > after

        next_sequence
      end

      def finalize(input:, build_id:, generation:, after:, run:)
        result = run.fetch("result")
        control_plane.finalize(input, build_id:, result:)
        {
          "build_id" => build_id,
          "generation" => generation,
          "state" => result.fetch("state"),
          "after_sequence" => after
        }
      end

      def validate_identity!(input:, plan:, build_id:, generation:, after:)
        expected = {
          "build_id" => build_id,
          "generation" => generation,
          "deployment_id" => input.fetch("deployment_id"),
          "operation_id" => input.fetch("operation_id"),
          "organization_id" => input.fetch("organization_id")
        }
        actual = expected.keys.to_h { |key| [ key, key == "generation" ? Integer(plan.fetch(key)) : plan.fetch(key) ] }
        valid = build_id.match?(/\Abld_[0-9a-f-]{36}\z/) && generation.positive? && after >= 0
        raise ArgumentError, "prepared build identity is inconsistent" unless valid && actual == expected
      end
    end
  end
end
