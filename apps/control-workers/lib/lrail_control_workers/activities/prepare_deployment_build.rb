require "temporalio/activity"

module LrailControlWorkers
  module Activities
    class PrepareDeploymentBuild < Temporalio::Activity::Definition
      activity_name "lrail.deployment.prepare_build.v1"

      def initialize(control_plane: nil)
        super()
        @control_plane = control_plane
      end

      def execute(input)
        validate_input!(input)
        (@control_plane ||= ControlPlaneClient.new).prepare(input)
      end

      private

      def validate_input!(input)
        required = %w[actor_id deployment_id generation idempotency_key operation_id organization_id workflow_id]
        missing = required.reject { |key| input.key?(key) && !input[key].to_s.empty? }
        raise ArgumentError, "deployment build input is incomplete" unless missing.empty?
        raise ArgumentError, "workflow identity mismatch" unless input["idempotency_key"] == input["workflow_id"]
      end
    end
  end
end
