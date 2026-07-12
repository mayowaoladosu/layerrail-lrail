require "rails_helper"

RSpec.describe "account authentication", type: :request do
  it "creates an unverified account and mandatory personal organization" do
    expect do
      post "/auth/create-account", params: {
        email: "new-user@example.test",
        "email-confirm": "new-user@example.test",
        password: DomainHelpers::TEST_PASSWORD,
        "password-confirm": DomainHelpers::TEST_PASSWORD
      }
    end.to change(Account, :count).by(1)

    account = Account.find_by!(email: "new-user@example.test")
    expect(account).to be_unverified
    expect(account.public_id).to start_with("acct_")
    expect(account.memberships.first).to have_attributes(role: "owner", status: "active")
    expect(account.organizations.first).to be_personal
    expect(account.email_intents).to contain_exactly(
      have_attributes(template: "rodauth_message", template_version: 1, state: "pending"),
    )
  end

  it "authenticates a verified account and renders the operational shell" do
    account = create_account
    organization = create_organization(account:)
    within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Console App", slug: "console-app" })
    end

    login(account)
    expect(response).to have_http_status(:redirect)
    follow_redirect!

    expect(response).to have_http_status(:ok)
    expect(response.body).to include("Lrail", "Projects", "Deploy project", "Console App")
    expect(response.body).to include("Search resources", "Data services", "Observability")
  end

  it "uses a generic failure response for an unknown login" do
    post "/auth/login", params: { email: "unknown@example.test", password: "definitely-wrong" }
    expect(response.body).to include("Unable to authenticate with those credentials")
    expect(response.body).not_to include("no matching login", "account does not exist")
  end
end
