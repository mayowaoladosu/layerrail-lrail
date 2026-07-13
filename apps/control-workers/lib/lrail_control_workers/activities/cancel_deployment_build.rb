require "temporalio/activity"

module LrailControlWorkers
  module Activities
    class CancelDeploymentBuild < Temporalio::Activity::Definition
      activity_name "lrail.deployment.cancel_build.v1"

      def initialize(build_service: nil)
        super()
        @build_service = build_service
      end

      def execute(input)
        build_id = input.fetch("build_id")
        generation = Integer(input.fetch("generation"))
        reason = input.fetch("cancel_reason").to_s[0, 512]
        raise ArgumentError, "build cancellation identity is invalid" unless
          build_id.match?(/\Abld_[0-9a-f-]{36}\z/) && generation.positive? && !reason.empty?

        build_service.cancel(build_id:, generation:, reason:)
        { "build_id" => build_id, "generation" => generation, "cancel_requested" => true }
      end

      private

      def build_service
        @build_service ||= BuildServiceClient.new
      end
    end
  end
end
