module Console
  class OrganizationsController < BaseController
    def members
      @organization_memberships = @organization.memberships.includes(:account).order(:role, :id)
    end

    def usage
      @usage = @organization.usage_ledger.order(period_start: :desc).limit(100)
    end

    def audit
      @events = @organization.audit_events.order(occurred_at: :desc).limit(100)
    end

    def settings
    end
  end
end
