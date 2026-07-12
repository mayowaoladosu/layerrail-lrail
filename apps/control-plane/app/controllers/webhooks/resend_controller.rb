module Webhooks
  class ResendController < ActionController::API
    MAX_BODY_BYTES = 256.kilobytes

    def create
      raw_body = request.raw_post
      return head :payload_too_large if raw_body.bytesize > MAX_BODY_BYTES

      result = Email::ResendWebhook.new.process(raw_body:, headers: request.headers)
      render json: { received: true, outcome: result.outcome }, status: :ok
    rescue Email::ResendWebhook::Invalid
      render json: { error: { code: "invalid_webhook", message: "Webhook signature or payload is invalid." } },
        status: :bad_request
    end
  end
end
