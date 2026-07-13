module Console
  class DeploymentsController < BaseController
    before_action :set_project

    def index
      @deployments = @project.deployments.includes(:environment, :operation, :revision)
        .order(created_at: :desc)
    end

    def show
      @deployment = @project.deployments.includes(:environment, :operation, :revision, :deployment_transitions)
        .find_by_public_id!(params[:id])
      @timeline = @deployment.deployment_transitions.order(:created_at)
    end

    def create
      environment = @project.environments.find_by_public_id!(params.fetch(:environment_id))
      binding = @project.project_source_binding
      raise ActiveRecord::RecordNotFound unless binding&.repository == params.fetch(:repository).to_s.downcase

      result = Deployments::CreateFromGit.new.call(
        account: current_account,
        organization: @organization,
        project: @project,
        attributes: {
          environment_id: environment.public_id,
          manifest_revision: @project.manifest_revision,
          reason: params.fetch(:reason, "Manual deployment"),
          build_mode: "auto",
          accept_detected: true,
          source: {
            kind: "git",
            connection_id: binding.source_connection.public_id,
            repository: binding.repository,
            commit: params.fetch(:commit).to_s.downcase,
            root_directory: binding.root_directory
          }
        },
      )
      redirect_to console_organization_project_deployment_path(
        @organization.public_id,
        @project.public_id,
        result.deployment.public_id,
      )
    end

    private

    def set_project
      @project = @organization.projects.find_by_public_id!(params[:project_id])
    end
  end
end
