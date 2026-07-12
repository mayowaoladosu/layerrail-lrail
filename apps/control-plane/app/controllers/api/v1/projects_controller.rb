module Api
  module V1
    class ProjectsController < BaseController
      def index
        projects = current_organization!.projects.order(created_at: :desc, id: :desc).limit(page_limit)
        projects = projects.where(status: params[:status]) if params[:status].present?
        render_page(projects.map { |project| ApiResource.project(project) }, limit: page_limit)
      end

      def show
        project = current_organization!.projects.find_by_public_id!(params[:id])
        render_resource(ApiResource.project(project))
      end

      def create
        payload = project_params.to_h.deep_symbolize_keys
        idempotent(payload:) do
          result = Projects::Create.call(
            account: current_account,
            organization: current_organization!,
            attributes: payload,
          )
          [ 202, { data: ApiResource.project(result.project), operation: ApiResource.operation(result.operation) } ]
        end
      end

      def destroy
        project = current_organization!.projects.find_by_public_id!(params[:id])
        Authorization.authorize!(account: current_account, organization: current_organization!, action: "project.delete", resource: project)
        idempotent(payload: { id: project.public_id, version: project.lock_version }) do
          Project.transaction do
            project.update!(deletion_requested_at: Time.current, retention_until: 7.days.from_now)
            operation = Operation.create!(
              organization: current_organization!,
              resource_type: "project",
              resource_public_id: project.public_id,
              state: "accepted",
              stage: "inventorying_dependencies",
              total_steps: 8,
              workflow_id: "project/#{project.public_id}/delete/#{project.lock_version}",
            )
            DomainRecorder.record!(resource: project, event_type: "project.deletion_requested", action: "project.delete")
            [ 202, { data: ApiResource.operation(operation) } ]
          end
        end
      end

      private

      def project_params
        params.permit(:slug, :name, :description, source: {}, manifest: {})
      end

      def page_limit
        params.fetch(:limit, 50).to_i.clamp(1, 100)
      end
    end
  end
end
