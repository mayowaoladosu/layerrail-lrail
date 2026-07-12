module Api
  module V1
    class MeController < BaseController
      def show
        memberships = Membership.active.includes(:organization).where(account: current_account)
        render_resource(
          id: current_account.public_id,
          email: current_account.email,
          display_name: current_account.display_name,
          memberships: memberships.map do |membership|
            { organization_id: membership.organization.public_id, role: membership.role }
          end,
        )
      end
    end
  end
end
