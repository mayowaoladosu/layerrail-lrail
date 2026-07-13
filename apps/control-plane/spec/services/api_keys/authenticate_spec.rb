require "rails_helper"

RSpec.describe ApiKeys::Authenticate do
  it "authenticates the exact token and enforces IP constraints, expiry, and revocation" do
    account = create_account
    organization = create_organization(account:)
    issued = within_organization(account, organization) do
      ApiKeys::Issue.call(
        account:,
        organization:,
        attributes: {
          name: "CI",
          scopes: %w[project.read],
          constraints: { ip_cidrs: [ "192.0.2.0/24" ] },
          expires_at: 1.day.from_now
        },
      )
    end

    authenticated = described_class.call(token: issued.token, remote_ip: "192.0.2.10")
    expect(authenticated).to have_attributes(account:, organization:, api_key: issued.api_key)
    expect(described_class.call(token: "#{issued.token}x", remote_ip: "192.0.2.10")).to be_nil
    expect(described_class.call(token: issued.token, remote_ip: "198.51.100.1")).to be_nil

    within_organization(account, organization) { issued.api_key.update_columns(expires_at: 1.second.ago) }
    expect(described_class.call(token: issued.token, remote_ip: "192.0.2.10")).to be_nil

    within_organization(account, organization) { issued.api_key.update_columns(expires_at: 1.day.from_now) }
    within_organization(account, organization) { issued.api_key.update!(revoked_at: Time.current) }
    expect(described_class.call(token: issued.token, remote_ip: "192.0.2.10")).to be_nil
  end

  it "does not authenticate a key after its account loses membership" do
    account = create_account
    organization = create_organization(account:)
    issued = within_organization(account, organization) do
      ApiKeys::Issue.call(account:, organization:, attributes: { name: "Old", scopes: %w[project.read] })
    end
    replacement = create_account(email: "replacement@example.test")
    within_organization(account, organization) do
      Membership.create!(account: replacement, organization:, role: "owner", status: "active")
      organization.memberships.find_by!(account:).destroy!
    end

    expect(described_class.call(token: issued.token, remote_ip: "127.0.0.1")).to be_nil
  end
end
