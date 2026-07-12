require "rails_helper"

RSpec.describe Inbox::Processor do
  def event_fixture(account, organization)
    event = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Inbox", slug: "inbox" })
      OutboxEvent.order(:id).last
    end
    Events::Envelope.from(event)
  end

  it "processes one effect for redelivery of the same event" do
    account = create_account
    organization = create_organization(account:)
    envelope = event_fixture(account, organization)
    effects = 0
    processor = described_class.new(
      consumer: "provisioner-v1",
      context_resolver: ->(_organization_id, _event) { [ account, organization ] },
      handler: ->(_event) { effects += 1 },
    )

    first = processor.process(envelope:, subject: "lrail.domain.v1.project.created")
    second = processor.process(envelope:, subject: "lrail.domain.v1.project.created")

    expect(first.outcome).to eq(:processed)
    expect(second.outcome).to eq(:duplicate)
    expect(effects).to eq(1)
    expect(first.message.reload).to have_attributes(state: "completed", attempt_count: 1)
  end

  it "dead-letters a poison message after bounded retries" do
    account = create_account
    organization = create_organization(account:)
    envelope = event_fixture(account, organization)
    processor = described_class.new(
      consumer: "poison-v1",
      context_resolver: ->(_organization_id, _event) { [ account, organization ] },
      handler: ->(_event) { raise "invalid payload semantics" },
    )

    outcomes = 8.times.map do
      processor.process(envelope:, subject: "lrail.domain.v1.project.created", headers: { "Nats-Stream" => "domain" }).outcome
    end

    expect(outcomes.first(7)).to all(eq(:retry))
    expect(outcomes.last).to eq(:dead_lettered)
    expect(DeadLetterMessage.find_by!(consumer: "poison-v1")).to have_attributes(
      event_public_id: envelope.fetch("event_id"),
      attempt_count: 8,
    )
  end

  it "rejects a resolver context from another organization" do
    account = create_account
    organization = create_organization(account:)
    other = create_account(email: "other@example.test")
    other_organization = create_organization(account: other, slug: "other")
    envelope = event_fixture(account, organization)
    processor = described_class.new(
      consumer: "isolated-v1",
      context_resolver: ->(_organization_id, _event) { [ other, other_organization ] },
      handler: ->(_event) { },
    )

    expect do
      processor.process(envelope:, subject: "lrail.domain.v1.project.created")
    end.to raise_error(OrganizationContext::MissingContext)
  end
end
