module Api
  module V1
    class DeploymentsController < BaseController
      def index
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        deployments = project.deployments.includes(:environment, :operation, :revision)
          .order(created_at: :desc, id: :desc).limit(page_limit)
        deployments = deployments.where(environment: environment_filter(project)) if params[:environment_id].present?
        deployments = deployments.where(state: params[:state]) if params[:state].present?
        render_page(deployments.map { |deployment| ApiResource.deployment(deployment) }, limit: page_limit)
      end

      def show
        deployment = current_organization!.deployments.includes(:project, :environment, :operation, :revision)
          .find_by_public_id!(params[:id])
        render_resource(ApiResource.deployment(deployment))
      end

      def create
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        payload = deployment_params.to_h.deep_symbolize_keys
        idempotent(payload:) do
          result = create_deployment(project:, payload:)
          [ 202, { data: ApiResource.deployment(result.deployment), operation: ApiResource.operation(result.operation) } ]
        end
      end

      def destroy
        deployment = current_organization!.deployments.find_by_public_id!(params[:id])
        Authorization.authorize!(account: current_account, organization: current_organization!, action: "deployment.cancel", resource: deployment)
        reason = params.permit(:reason).fetch(:reason, "user_requested").to_s.first(512)
        raise ActionController::BadRequest, "reason is invalid" unless reason.length.between?(3, 512)

        idempotent(payload: { id: deployment.public_id, reason: }) do
          Deployments::Transition.call(deployment:, to: "canceling", reason:)
          deployment.operation.update!(state: "canceling", stage: "canceling")
          [ 202, { data: ApiResource.operation(deployment.operation) } ]
        end
      end

      private

      def deployment_params
        params.permit(
          :environment_id,
          :manifest_revision,
          :reason,
          :build_mode,
          :build_file,
          :accept_detected,
          source: {},
        )
      end

      def create_deployment(project:, payload:)
        if payload.dig(:source, :kind) == "git"
          return Deployments::CreateFromGit.new.call(
            account: current_account,
            organization: current_organization!,
            project:,
            attributes: payload,
          )
        end

        Deployments::Create.call(
          account: current_account,
          organization: current_organization!,
          project:,
          attributes: payload,
        )
      end

      def environment_filter(project)
        project.environments.find_by_public_id!(params[:environment_id])
      end

      def page_limit
        params.fetch(:limit, 50).to_i.clamp(1, 100)
      end
    end
  end
end
