module Api
  module V1
    class ServicesController < BaseController
      def index
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        services = project.services.includes(:current_release).order(:id)
        render_resource(services.map { |service| ApiResource.service(service) })
      end
    end
  end
end
