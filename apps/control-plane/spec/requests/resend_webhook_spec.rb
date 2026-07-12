require "rails_helper"
require "base64"

RSpec.describe "Resend webhook", type: :request do
  let(:secret) { "whsec_#{Base64.strict_encode64("local-webhook-secret")}" }

  around do |example|
    previous = ENV["RESEND_WEBHOOK_SECRET"]
    ENV["RESEND_WEBHOOK_SECRET"] = secret
    example.run
  ensure
    ENV["RESEND_WEBHOOK_SECRET"] = previous
  end

  it "verifies, applies, and deduplicates a delivery event" do
    account = create_account
    organization = create_organization(account:)
    intent = within_organization(account, organization) do
      EmailIntent.create!(
        organization:,
        account:,
        template: "rodauth_message",
        template_version: 1,
        recipient: account.email,
        data: { "subject" => "Verify", "text" => "Body" },
        idempotency_key: "webhook-test",
        state: "sent",
        provider: "resend",
        provider_message_id: "email_123",
      )
    end
    body = JSON.generate(type: "email.delivered", created_at: Time.current.iso8601, data: { email_id: "email_123" })
    headers = signed_headers(body, "delivery_123")

    post "/webhooks/resend", params: body, headers: headers
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("outcome")).to eq("processed")
    expect(intent.reload.state).to eq("delivered")

    post "/webhooks/resend", params: body, headers: headers
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("outcome")).to eq("duplicate")
    expect(EmailProviderEvent.where(provider_event_id: "delivery_123").count).to eq(1)
  end

  it "rejects a tampered body" do
    body = JSON.generate(type: "email.sent", data: { email_id: "email_123" })
    headers = signed_headers(body, "delivery_tampered")

    post "/webhooks/resend", params: "#{body} ", headers: headers

    expect(response).to have_http_status(:bad_request)
    expect(response.parsed_body.dig("error", "code")).to eq("invalid_webhook")
  end

  def signed_headers(body, delivery_id)
    timestamp = Time.current.to_i.to_s
    {
      "CONTENT_TYPE" => "application/json",
      "HTTP_SVIX_ID" => delivery_id,
      "HTTP_SVIX_TIMESTAMP" => timestamp,
      "HTTP_SVIX_SIGNATURE" => Svix::Webhook.new(secret).sign(delivery_id, timestamp, body)
    }
  end
end
