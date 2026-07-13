module Webhooks
  class GithubController < ActionController::API
    def create
      result = SourceProviders::GithubWebhook.new.process(raw_body: request.raw_post, headers: request.headers)
      if result.work_pending
        ProcessGithubDeliveryJob.perform_later(
          result.delivery_public_id,
          result.organization_public_id,
          result.actor_public_id,
        )
      end
      status = result.outcome == "unknown_installation" ? :accepted : :ok
      render json: { received: true, outcome: result.outcome }, status:
    rescue SourceProviders::DuplicateMismatch
      render json: { error: { code: "delivery_mismatch", message: "Webhook delivery identity conflicts." } },
        status: :conflict
    rescue SourceProviders::InvalidWebhook
      render json: { error: { code: "invalid_webhook", message: "Webhook signature, headers, or payload are invalid." } },
        status: :unauthorized
    end
  end
end
