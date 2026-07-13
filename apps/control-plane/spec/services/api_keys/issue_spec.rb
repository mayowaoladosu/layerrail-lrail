require "rails_helper"

RSpec.describe ApiKeys::Issue do
  it "returns a one-time high-entropy token and persists only its Argon digest" do
    account = create_account
    organization = create_organization(account:)

    result = within_organization(account, organization) do
      described_class.call(
        account:,
        organization:,
        attributes: {
          name: "Deploy CLI",
          scopes: %w[project.read source.write],
          constraints: { ip_cidrs: [ "127.0.0.0/8" ] },
          expires_at: 30.days.from_now
        },
      )
    end

    expect(result.token).to match(/\Alrail_key_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}\z/)
    expect(result.api_key.secret_digest).to start_with("$argon2id$")
    expect(result.api_key.attributes.values).not_to include(result.token, result.token.split("_").last)
    expect(OutboxEvent.find_by!(event_type: "api_key.created").data).not_to include("secret", "token")
  end

  it "rolls key creation back when durable evidence cannot be recorded" do
    account = create_account
    organization = create_organization(account:)
    allow(DomainRecorder).to receive(:record!).and_raise("audit unavailable")

    expect do
      within_organization(account, organization) do
        described_class.call(account:, organization:, attributes: { name: "Rolled back", scopes: %w[project.read] })
      end
    end.to raise_error("audit unavailable")

    expect(ApiKey.count).to eq(0)
  end

  it "rejects duplicate scopes and duplicate IP constraints" do
    account = create_account
    organization = create_organization(account:)

    expect do
      within_organization(account, organization) do
        described_class.call(account:, organization:, attributes: { name: "Duplicate", scopes: %w[project.read project.read] })
      end
    end.to raise_error(ActiveRecord::RecordInvalid, /Scopes/)

    expect do
      within_organization(account, organization) do
        described_class.call(
          account:,
          organization:,
          attributes: {
            name: "Duplicate CIDR",
            scopes: %w[project.read],
            constraints: { ip_cidrs: [ "192.0.2.0/24", "192.0.2.0/24" ] }
          },
        )
      end
    end.to raise_error(ActiveRecord::RecordInvalid, /Constraints/)
  end
end
