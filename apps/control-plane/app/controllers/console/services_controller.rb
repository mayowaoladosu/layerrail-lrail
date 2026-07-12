module Console
  class ServicesController < BaseController
    def show
      @project = @organization.projects.find_by_public_id!(params[:project_id])
      @service = @project.services.includes(:current_release).find_by_public_id!(params[:id])
      @releases = @service.releases.includes(:environment, :revision).order(created_at: :desc).limit(20)
      @revisions = @service.revisions.order(created_at: :desc).limit(20)
    end
  end
end
