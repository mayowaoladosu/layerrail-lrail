module Api
  module V1
    class BaseController < ApplicationController
      protect_from_forgery with: :null_session
      before_action :require_account
      around_action :with_account_context

      private

      def with_account_context(&action)
        OrganizationContext.with(account: current_account) do
          identifier = params[:organization_id].presence || request.headers["X-Lrail-Organization"].presence
          if identifier
            organization = Organization.where(public_id: identifier).or(Organization.where(slug: identifier)).first!
            OrganizationContext.with(account: current_account, organization:, &action)
          else
            action.call
          end
        end
      end

      def current_organization!
        Current.organization || raise(OrganizationContext::MissingContext, "organization context is required")
      end

      def render_resource(data, status: :ok, location: nil)
        response.set_header("Location", location) if location
        render json: { data: }, status:
      end

      def render_page(data, next_cursor: nil, limit: 50)
        render json: { data:, page: { next_cursor:, limit: } }
      end

      def idempotent(payload:, expires_in: 24.hours)
        result = Idempotency::Execute.call(
          key: request.headers["Idempotency-Key"],
          principal: current_account,
          organization: current_organization!,
          http_method: request.method,
          route: request.path,
          payload:,
          expires_in:,
        ) { yield }
        response.set_header("Idempotency-Replayed", "true") if result.replayed
        render json: result.body, status: result.status
      rescue ArgumentError => error
        render_error(
          status: :bad_request,
          code: "invalid_idempotency_key",
          message: error.message,
          details: [ { field: "Idempotency-Key", reason: "invalid" } ],
        )
      end
    end
  end
end
