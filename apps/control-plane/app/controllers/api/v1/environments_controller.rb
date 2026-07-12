module Api
  module V1
    class EnvironmentsController < BaseController
      def index
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        render_resource(project.environments.order(:id).map { |environment| ApiResource.environment(environment) })
      end
    end
  end
end
