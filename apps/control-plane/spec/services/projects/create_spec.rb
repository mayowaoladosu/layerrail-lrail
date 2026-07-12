require "rails_helper"

RSpec.describe Projects::Create do
  it "commits project, environments, operation, audit, and outbox atomically" do
    account = create_account
    organization = create_organization(account:)

    result = within_organization(account, organization) do
      Current.request_id = "req_#{"a" * 32}"
      described_class.call(
        account:,
        organization:,
        attributes: { name: "Payments", slug: "payments", description: "Payment services" },
      )
    end

    expect(result.project).to be_persisted
    expect(result.project.environments.pluck(:slug, :protected)).to contain_exactly(
      [ "production", true ],
      [ "preview", false ],
    )
    expect(result.operation.workflow_id).to eq("project/#{result.project.public_id}/provision/1")
    within_organization(account, organization) do
      expect(OutboxEvent.where(event_type: "project.created", resource_public_id: result.project.public_id)).to exist
      expect(AuditEvent.where(action: "project.create", resource_public_id: result.project.public_id)).to exist
    end
  end

  it "rejects a role without project creation permission" do
    owner = create_account
    auditor = create_account(email: "auditor@example.test", name: "Auditor")
    organization = create_organization(account: owner)
    within_organization(owner, organization) do
      Membership.create!(account: auditor, organization:, role: "auditor", status: "active")
    end

    expect do
      within_organization(auditor, organization) do
        described_class.call(account: auditor, organization:, attributes: { name: "Denied", slug: "denied" })
      end
    end.to raise_error(Authorization::Denied, /role_missing_action/)
  end
end
