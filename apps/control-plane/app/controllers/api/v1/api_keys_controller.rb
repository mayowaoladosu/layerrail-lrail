module Api
  module V1
    class ApiKeysController < BaseController
      def index
        Authorization.authorize!(account: current_account, organization: current_organization!, action: "api_key.read")
        keys = current_organization!.api_keys.order(created_at: :desc, id: :desc).limit(page_limit)
        render_page(keys.map { |api_key| ApiResource.api_key(api_key) }, limit: page_limit)
      end

      def create
        payload = api_key_params.to_h.deep_symbolize_keys
        payload[:expires_at] = Time.iso8601(payload[:expires_at]) if payload[:expires_at].present?
        idempotent(payload:, sensitive: true) do
          result = ApiKeys::Issue.call(
            account: current_account,
            organization: current_organization!,
            attributes: payload,
          )
          [
            201,
            {
              data: ApiResource.api_key(result.api_key),
              secret: result.token
            }
          ]
        end
      rescue ArgumentError
        render_error(
          status: :unprocessable_content,
          code: "validation_failed",
          message: "The API key request failed validation.",
        )
      end

      def destroy
        api_key = current_organization!.api_keys.find_by_public_id!(params[:id])
        idempotent(payload: { id: api_key.public_id }) do
          ApiKeys::Revoke.call(account: current_account, organization: current_organization!, api_key:)
          [ 200, { data: ApiResource.api_key(api_key) } ]
        end
      end

      private

      def api_key_params
        params.require(:api_key).permit(:name, :expires_at, scopes: [], constraints: { ip_cidrs: [] })
      end

      def page_limit
        params.fetch(:limit, 50).to_i.clamp(1, 100)
      end
    end
  end
end
