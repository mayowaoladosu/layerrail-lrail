require "rails_helper"

RSpec.describe Events::Envelope do
  it "produces a contract-valid, self-contained domain event" do
    account = create_account
    organization = create_organization(account:)

    event = within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Events", slug: "events" },
      )
      OutboxEvent.order(:id).last
    end

    envelope = described_class.from(event)

    expect(envelope).to include(
      "event_id" => event.public_id,
      "event_type" => "project.created",
      "organization_id" => organization.public_id,
      "correlation_id" => a_string_matching(/\Areq_[0-9a-f]{32}\z/),
    )
    expect(envelope.dig("data", "operation_id")).to start_with("op_")
  end

  it "rejects secret-shaped event fields before persistence" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Safe", slug: "safe" }).project
    end

    expect do
      within_organization(account, organization) do
        DomainRecorder.record!(
          resource: project,
          event_type: "project.unsafe",
          action: "project.unsafe",
          data: { access_token: "must-not-enter-the-outbox" },
        )
      end
    end.to raise_error(Events::NoSecrets::ForbiddenKey)
  end
end
