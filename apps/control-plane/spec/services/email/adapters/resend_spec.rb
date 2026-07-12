require "rails_helper"

RSpec.describe Email::Adapters::Resend do
  it "uses the intent idempotency key for provider retries" do
    intent = EmailIntent.new(
      public_id: "evt_019b01da-7e31-7000-8000-000000000001",
      recipient: "owner@example.test",
      idempotency_key: "email:#{"a" * 64}",
    )
    rendered = Email::TemplateRegistry::Rendered.new("Verify", "Text body", nil)
    request = stub_request(:post, "https://api.resend.com/emails")
      .with(
        headers: {
          "Authorization" => "Bearer provider-test-key",
          "Idempotency-Key" => intent.idempotency_key
        },
      )
      .to_return(
        status: 200,
        body: JSON.generate(id: "email_provider_123"),
        headers: { "Content-Type" => "application/json" },
      )

    message_id = described_class.new(
      api_key: "provider-test-key",
      sender: "Lrail <security@example.test>",
    ).deliver(intent:, rendered:)

    expect(message_id).to eq("email_provider_123")
    expect(request).to have_been_requested.once
  end
end
