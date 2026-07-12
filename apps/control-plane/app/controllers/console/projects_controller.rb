module Console
  class ProjectsController < BaseController
    def index
      @projects = @organization.projects.includes(:services, :environments).order(updated_at: :desc)
    end

    def new
      @project = Project.new
    end

    def create
      result = Projects::Create.call(
        account: current_account,
        organization: @organization,
        attributes: project_params.to_h.symbolize_keys,
      )
      redirect_to console_organization_project_path(@organization.public_id, result.project.public_id),
        notice: "Project created. Connect a source to start the first deployment."
    rescue ActiveRecord::RecordInvalid => error
      @project = error.record
      render :new, status: :unprocessable_content
    end

    def show
      @project = @organization.projects.find_by_public_id!(params[:id])
      @environments = @project.environments.order(protected: :desc, id: :asc)
      @environment = @environments.find { |environment| environment.public_id == params[:environment] } || @environments.first
      @services = @project.services.includes(:current_release).order(:name)
      @deployments = @project.deployments.includes(:operation, :environment, :revision)
        .where(environment: @environment).order(created_at: :desc).limit(12)
      @domains = @project.domains.where(environment: @environment).order(:hostname)
      @addons = @project.addons.where(environment: @environment).order(:name)
    end

    private

    def project_params
      params.expect(project: %i[name slug description])
    end
  end
end
