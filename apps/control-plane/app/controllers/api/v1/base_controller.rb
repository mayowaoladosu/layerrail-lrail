module Api
  module V1
    class BaseController < ApplicationController
      SCOPE_REQUIREMENTS = {
        "me#show" => "organization.read",
        "organizations#index" => "organization.read",
        "organizations#show" => "organization.read",
        "organizations#create" => "organization.write",
        "organizations#update" => "organization.write",
        "projects#index" => "project.read",
        "projects#show" => "project.read",
        "projects#create" => "project.write",
        "projects#destroy" => "project.write",
        "environments#index" => "project.read",
        "services#index" => "project.read",
        "deployments#index" => "deployment.read",
        "deployments#show" => "deployment.read",
        "deployments#create" => "deployment.write",
        "deployments#destroy" => "deployment.write",
        "operations#show" => "operation.read",
        "domains#index" => "domain.read",
        "addons#index" => "addon.read",
        "source_uploads#create" => "source.write",
        "source_uploads#finalize" => "source.write",
        "api_keys#index" => "api_key.read",
        "api_keys#create" => "api_key.write",
        "api_keys#destroy" => "api_key.write"
      }.freeze

      protect_from_forgery with: :null_session
      before_action :authenticate_principal
      around_action :with_account_context
      before_action :authorize_api_key_scope

      private

      def current_account
        @api_key_authentication&.account || super
      end

      def current_api_key
        @api_key_authentication&.api_key
      end

      def authenticate_principal
        token = request.authorization.to_s.delete_prefix("Bearer ")
        if request.authorization.to_s.start_with?("Bearer lrail_key_")
          @api_key_authentication = ApiKeys::Authenticate.call(token:, remote_ip: request.remote_ip)
          unless @api_key_authentication
            render_error(
              status: :unauthorized,
              code: "unauthenticated",
              message: "API key authentication failed.",
            )
          end
        else
          require_account
        end
      end

      def with_account_context(&action)
        if @api_key_authentication
          return with_api_key_context(&action)
        end

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

      def with_api_key_context(&action)
        organization = @api_key_authentication.organization
        identifier = params[:organization_id].presence || request.headers["X-Lrail-Organization"].presence
        if identifier && !identifier.in?([ organization.public_id, organization.slug ])
          raise ActiveRecord::RecordNotFound
        end

        OrganizationContext.with(account: current_account, organization:) do
          Current.api_key = current_api_key
          Current.authentication_method = "api_key"
          if current_api_key.last_used_at.nil? || current_api_key.last_used_at < 5.minutes.ago
            current_api_key.update_columns(last_used_at: Time.current)
          end
          action.call
        end
      end

      def authorize_api_key_scope
        return unless current_api_key

        required = SCOPE_REQUIREMENTS["#{controller_name}##{action_name}"]
        unless required && current_api_key.allows_scope?(required)
          raise Authorization::Denied.new(action: required || "api.unknown", reason: "api_key_scope_missing")
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

      def idempotent(payload:, expires_in: 24.hours, sensitive: false)
        result = Idempotency::Execute.call(
          key: request.headers["Idempotency-Key"],
          principal: current_account,
          organization: current_organization!,
          http_method: request.method,
          route: request.path,
          payload:,
          expires_in:,
          sensitive:,
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
