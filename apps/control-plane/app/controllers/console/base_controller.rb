module Console
  class BaseController < ApplicationController
    before_action :require_account
    around_action :with_console_context

    private

    def with_console_context
      OrganizationContext.with(account: current_account) do
        @memberships = Membership.active.includes(:organization).where(account: current_account).order(:id).to_a
        @organizations = @memberships.map(&:organization)
        identifier = params[:organization_id].presence || session[:organization_public_id]
        @organization = @organizations.find { |organization| organization.public_id == identifier || organization.slug == identifier }
        @organization ||= @organizations.first
        raise ActiveRecord::RecordNotFound unless @organization

        session[:organization_public_id] = @organization.public_id
        OrganizationContext.with(account: current_account, organization: @organization) { yield }
      end
    end

    def current_membership
      @current_membership ||= @memberships.find { |membership| membership.organization_id == @organization.id }
    end
    helper_method :current_membership
  end
end
