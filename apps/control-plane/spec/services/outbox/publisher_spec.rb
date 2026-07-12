require "rails_helper"

RSpec.describe Outbox::Publisher do
  class RecordingTransport
    attr_reader :messages

    def initialize
      @messages = []
    end

    def publish(**message)
      @messages << message
    end

    def subject_for(event_type)
      "lrail.domain.v1.#{event_type}"
    end
  end

  class RecordingOutboxRepository
    attr_reader :finishes

    def initialize(events)
      @events = events
      @finishes = []
    end

    def claim(**)
      @events.shift(25)
    end

    def finish(**attributes)
      @finishes << attributes
      true
    end
  end

  it "publishes a canonical event with its public ID as the broker dedupe key" do
    account = create_account
    organization = create_organization(account:)
    event = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Outbox", slug: "outbox" })
      OutboxEvent.order(:id).last
    end
    transport = RecordingTransport.new
    repository = RecordingOutboxRepository.new([ event ])

    result = described_class.new(transport:, repository:, worker_name: "test-worker").publish_batch

    expect(result).to have_attributes(claimed: 1, published: 1, retried: 0, discarded: 0)
    expect(transport.messages.first).to include(
      subject: "lrail.domain.v1.project.created",
      message_id: event.public_id,
    )
    expect(JSON.parse(transport.messages.first.fetch(:payload))).to include("event_id" => event.public_id)
    expect(repository.finishes.first).to include(event:, published: true, worker_name: "test-worker")
  end

  it "schedules retry after a transient transport failure" do
    account = create_account
    organization = create_organization(account:)
    event = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Retry", slug: "retry" })
      OutboxEvent.order(:id).last
    end
    event.publish_attempts = 1
    repository = RecordingOutboxRepository.new([ event ])
    transport = Object.new
    transport.define_singleton_method(:publish) { |**| raise NATS::Timeout, "temporarily unavailable" }

    result = described_class.new(transport:, repository:, worker_name: "test-worker").publish_batch

    expect(result).to have_attributes(retried: 1, discarded: 0)
    expect(repository.finishes.first).to include(published: false, dead_letter: false)
    expect(repository.finishes.first.fetch(:retry_at)).to be > Time.current
  end
end
