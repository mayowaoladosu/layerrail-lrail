module Api
  module V1
    class DomainsController < BaseController
      def index
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        render_resource(project.domains.order(:hostname).map { |domain| ApiResource.domain(domain) })
      end
    end
  end
end
