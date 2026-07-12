module Api
  module V1
    class OrganizationsController < BaseController
      def index
        organizations = Organization.joins(:memberships)
          .merge(Membership.active.where(account: current_account))
          .order(created_at: :desc, id: :desc)
          .limit(page_limit)
        render_page(organizations.map { |organization| ApiResource.organization(organization) }, limit: page_limit)
      end

      def show
        render_resource(ApiResource.organization(current_organization!))
      end

      def create
        payload = organization_params.to_h
        personal = Membership.active.includes(:organization).where(account: current_account)
          .map(&:organization).find(&:personal?)
        raise ActiveRecord::RecordNotFound unless personal

        OrganizationContext.with(account: current_account, organization: personal) do
          idempotent(payload:) do
            organization = Organization.create!(payload.merge(personal: false, created_by_account: current_account))
            OrganizationContext.bind_organization!(organization)
            Membership.create!(account: current_account, organization:, role: "owner", status: "active")
            OrganizationContext.bind_organization!(personal)
            [ 201, { data: ApiResource.organization(organization) } ]
          end
        end
      end

      def update
        organization = current_organization!
        Authorization.authorize!(account: current_account, organization:, action: "organization.update", resource: organization)
        payload = organization_params.except(:plan).to_h
        idempotent(payload:) do
          organization.update!(payload)
          [ 200, { data: ApiResource.organization(organization) } ]
        end
      end

      private

      def organization_params
        params.permit(:slug, :name, :plan)
      end

      def page_limit
        params.fetch(:limit, 50).to_i.clamp(1, 100)
      end
    end
  end
end
