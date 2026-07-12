module Api
  module V1
    class AddonsController < BaseController
      def index
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        render_resource(project.addons.order(:name).map { |addon| ApiResource.addon(addon) })
      end
    end
  end
end
