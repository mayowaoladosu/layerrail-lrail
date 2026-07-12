module Console
  class DashboardController < BaseController
    def show
      if @organization.projects.none? && params[:organization_id].blank?
        redirect_to new_console_project_path and return
      end

      @projects = @organization.projects.includes(:services, :environments).order(updated_at: :desc).limit(8)
      @recent_deployments = @organization.deployments.includes(:project, :environment, :operation)
        .order(created_at: :desc).limit(8)
      @active_services = @organization.services.where(health: %w[healthy deploying]).count
      @open_incidents = @organization.services.where(health: "degraded").count
      @monthly_usage = @organization.usage_ledger.where(period_start: Time.current.beginning_of_month..).sum(:quantity)
    end
  end
end
