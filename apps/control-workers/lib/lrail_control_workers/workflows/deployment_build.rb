require "temporalio/retry_policy"
require "temporalio/workflow"

module LrailControlWorkers
  module Workflows
    class DeploymentBuild < Temporalio::Workflow::Definition
      workflow_name "lrail.deployment.build.v1"
      workflow_query_attr_reader :phase

      def execute(input)
        validate_input!(input)
        Temporalio::Workflow.patched("deployment-build-v1")
        @phase = "preparing"
        prepared = prepare(input)
        @build_input = input.merge(prepared)
        cancel_build if @cancel_reason
        @phase = @cancel_reason ? "canceling" : "building"
        result = build(@build_input)
        @phase = result.fetch("state")
        Temporalio::Workflow.wait_condition { Temporalio::Workflow.all_handlers_finished? }
        result.merge(
          "workflow_id" => Temporalio::Workflow.info.workflow_id,
          "deployment_id" => input.fetch("deployment_id")
        )
      rescue Temporalio::Error::CanceledError
        @phase = "canceled"
        {
          "workflow_id" => Temporalio::Workflow.info.workflow_id,
          "deployment_id" => input.fetch("deployment_id"),
          "state" => "canceled"
        }
      end

      workflow_signal
      def request_cancel(reason = "user_requested")
        @cancel_reason ||= reason.to_s[0, 512]
        @phase = "canceling"
        cancel_build if @build_input
      end

      private

      def prepare(input)
        Temporalio::Workflow.execute_activity(
          Activities::PrepareDeploymentBuild,
          input,
          start_to_close_timeout: 30,
          retry_policy: retry_policy(max_attempts: 5)
        )
      end

      def build(input)
        Temporalio::Workflow.execute_activity(
          Activities::ExecuteDeploymentBuild,
          input,
          schedule_to_close_timeout: 7_200,
          start_to_close_timeout: 7_200,
          heartbeat_timeout: 60,
          retry_policy: retry_policy(max_attempts: 5)
        )
      end

      def cancel_build
        return if @cancel_started

        @cancel_started = true
        Temporalio::Workflow.execute_activity(
          Activities::CancelDeploymentBuild,
          @build_input.merge("cancel_reason" => @cancel_reason),
          start_to_close_timeout: 30,
          retry_policy: retry_policy(max_attempts: 10)
        )
      end

      def retry_policy(max_attempts:)
        Temporalio::RetryPolicy.new(
          initial_interval: 1,
          backoff_coefficient: 2.0,
          max_interval: 30,
          max_attempts:
        )
      end

      def validate_input!(input)
        return if valid_strings?(input) && valid_workflow_identity?(input) &&
                  Integer(input["generation"]).positive?

        raise Temporalio::Error::ApplicationError.new(
          "deployment workflow input is invalid",
          non_retryable: true
        )
      rescue ArgumentError, TypeError
        raise Temporalio::Error::ApplicationError.new(
          "deployment workflow input is invalid",
          non_retryable: true
        )
      end

      def valid_strings?(input)
        required = %w[actor_id deployment_id idempotency_key operation_id organization_id workflow_id]
        required.all? { |key| input[key].is_a?(String) && !input[key].empty? }
      end

      def valid_workflow_identity?(input)
        input["idempotency_key"] == input["workflow_id"] &&
          input["workflow_id"].match?(%r{\Adeployment/dep_[0-9a-f-]{36}/build/[1-9][0-9]*\z})
      end
    end
  end
end
