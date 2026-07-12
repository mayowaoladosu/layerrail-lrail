module DomainHelpers
  TEST_PASSWORD = "local-test-password".freeze

  def create_account(email: "owner@example.test", name: "Test Owner")
    Account.create!(email:, display_name: name, status: "verified", password: TEST_PASSWORD)
  end

  def create_organization(account:, slug: "test-workspace", name: "Test Workspace", personal: false)
    OrganizationContext.with(account:) do
      organization = Organization.create!(
        created_by_account: account,
        slug:,
        name:,
        plan: "pro",
        personal:,
      )
      OrganizationContext.bind_organization!(organization)
      Membership.create!(account:, organization:, role: "owner", status: "active")
      organization
    end
  end

  def within_organization(account, organization, &)
    OrganizationContext.with(account:, organization:, &)
  end

  def login(account, password: TEST_PASSWORD)
    post "/auth/login", params: { email: account.email, password: }
  end
end

RSpec.configure do |config|
  config.include DomainHelpers
end
