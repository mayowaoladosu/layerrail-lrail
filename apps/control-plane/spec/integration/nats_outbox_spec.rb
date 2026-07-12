require "rails_helper"

RSpec.describe "NATS JetStream event delivery" do
  before do
    skip "set LRAIL_NATS_INTEGRATION=1 to run the broker test" unless ENV["LRAIL_NATS_INTEGRATION"] == "1"
  end

  it "persists, deduplicates, consumes, and acknowledges project events" do
    account = create_account
    organization = create_organization(account:)
    result = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "JetStream", slug: "jetstream" })
    end
    event = within_organization(account, organization) { OutboxEvent.find_by!(event_type: "project.created") }
    envelope = Events::Envelope.from(event)
    stream = "LRAIL_TEST_#{SecureRandom.hex(6).upcase}"
    subject_prefix = "lrail.test.#{SecureRandom.hex(6)}"
    subject = "#{subject_prefix}.project.created"
    transport = Outbox::NatsTransport.new(stream:, subject_prefix:)
    processor = Inbox::Processor.new(
      consumer: "integration-#{event.public_id}",
      context_resolver: Inbox::ActorContextResolver.method(:call),
      handler: Projects::ProvisioningEventHandler.method(:call),
    )
    consumer = Inbox::NatsConsumer.new(
      subject:,
      durable: "integration-#{event.public_id.delete("_").first(48)}",
      processor:,
      deliver_policy: "new",
      stream:,
    )

    first_ack = transport.publish(
      subject:,
      payload: JSON.generate(envelope),
      message_id: event.public_id,
    )
    duplicate_ack = transport.publish(
      subject:,
      payload: JSON.generate(envelope),
      message_id: event.public_id,
    )

    expect(first_ack.duplicate).to be(false).or be_nil
    expect(duplicate_ack.duplicate).to be(true)
    expect(consumer.consume_batch(limit: 1, timeout: 2)).to eq(1)
    expect(result.project.reload.status).to eq("healthy")
    expect(InboxMessage.find_by!(event_public_id: event.public_id).state).to eq("completed")
  ensure
    consumer&.close
    transport&.close
    if stream
      cleanup = NATS.connect(ENV.fetch("LRAIL_NATS_URL", "nats://127.0.0.1:54222"))
      begin
        cleanup.jetstream.delete_stream(stream)
      rescue NATS::JetStream::Error::NotFound
        nil
      ensure
        cleanup.close
      end
    end
  end
end
