module Internal
  module V1
    class DeploymentBuildsController < BaseController
      CONTEXT_FIELDS = %w[actor_id organization_id operation_id workflow_id generation].freeze

      def prepare
        payload = strict_body!(*CONTEXT_FIELDS)
        deployment = scoped_deployment(payload)
        prepared = BuildOrchestration::Prepare.call(
          deployment:,
          generation: Integer(payload.fetch("generation")),
        )
        workflow = WorkflowRun.find_or_initialize_by(workflow_id: payload.fetch("workflow_id"))
        workflow.assign_attributes(
          organization: current_organization,
          workflow_type: "deployment.build.v1",
          resource_public_id: deployment.public_id,
          state: "running",
          started_at: workflow.started_at || Time.current,
        )
        workflow.save!
        render json: {
          plan: prepared.plan,
          build_id: prepared.build.public_id,
          generation: prepared.build.generation,
          after_sequence: deployment.operation.operation_events
            .where(generation: prepared.build.generation).maximum(:sequence).to_i
        }
      end

      def events
        payload = strict_body!(*CONTEXT_FIELDS, "build_id", "events")
        deployment = scoped_deployment(payload)
        build = scoped_build(deployment, payload)
        values = Array(payload.fetch("events"))
        raise ArgumentError, "event batch is outside bounds" unless values.length.between?(1, 250)

        values.each do |event|
          BuildOrchestration::PersistEvent.call(deployment:, build:, event:)
        end
        render json: {
          persisted_through: deployment.operation.operation_events
            .where(generation: build.generation).maximum(:sequence).to_i,
          operation: ApiResource.operation(deployment.operation.reload)
        }
      end

      def result
        payload = strict_body!(*CONTEXT_FIELDS, "build_id", "result")
        deployment = scoped_deployment(payload)
        build = scoped_build(deployment, payload)
        BuildOrchestration::Finalize.call(deployment:, build:, result: payload.fetch("result"))
        finish_workflow!(payload:, deployment:, build: build.reload)
        render json: {
          build_state: build.state,
          deployment: ApiResource.deployment(deployment.reload),
          operation: ApiResource.operation(deployment.operation.reload)
        }
      end

      private

      def scoped_deployment(payload)
        deployment = current_organization.deployments.find_by_public_id!(params[:id])
        raise ActiveRecord::RecordNotFound unless deployment.operation.public_id == payload.fetch("operation_id")

        deployment
      end

      def scoped_build(deployment, payload)
        deployment.builds.find_by!(
          public_id: payload.fetch("build_id"),
          generation: Integer(payload.fetch("generation")),
        )
      end

      def finish_workflow!(payload:, deployment:, build:)
        workflow = WorkflowRun.find_by!(workflow_id: payload.fetch("workflow_id"))
        raise ActiveRecord::RecordNotFound unless workflow.resource_public_id == deployment.public_id

        workflow.update!(
          state: build.state.in?(%w[complete waiting]) ? "completed" : build.state,
          completed_at: Time.current,
        )
      end
    end
  end
end
