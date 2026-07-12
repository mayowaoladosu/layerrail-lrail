require "temporalio/retry_policy"
require "temporalio/workflow"

module LrailControlWorkers
  module Workflows
    class ProjectProvisioning < Temporalio::Workflow::Definition
      workflow_name "lrail.project.provisioning.v1"
      workflow_query_attr_reader :phase

      def execute(input)
        validate_input!(input)
        Temporalio::Workflow.patched("project-provisioning-receipt-v1")
        @phase = "recording"
        receipt = Temporalio::Workflow.execute_activity(
          Activities::IdempotentReceipt,
          input,
          start_to_close_timeout: 10,
          retry_policy: Temporalio::RetryPolicy.new(
            initial_interval: 1,
            backoff_coefficient: 2.0,
            max_interval: 10,
            max_attempts: 3
          )
        )
        @phase = "waiting"
        Temporalio::Workflow.wait_condition { @complete }
        @phase = "completed"
        receipt.merge("workflow_id" => Temporalio::Workflow.info.workflow_id, "status" => "completed")
      end

      workflow_signal
      def complete
        @complete = true
      end

      private

      def validate_input!(input)
        required = %w[idempotency_key operation_id project_id]
        missing = required.reject { |key| input[key].is_a?(String) && !input[key].empty? }
        return if missing.empty?

        raise Temporalio::Error::ApplicationError.new(
          "workflow input is missing required fields: #{missing.join(', ')}",
          non_retryable: true
        )
      end
    end
  end
end
