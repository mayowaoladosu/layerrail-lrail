require "rails_helper"

RSpec.describe Email::DeliveryWorker do
  it "deduplicates equivalent intents and delivers a claimed intent once" do
    account = create_account
    create_organization(account:)
    message = Mail.new(to: account.email, subject: "Verify account", body: "Follow the signed link")

    first = Email::Enqueue.from_mail(account:, message:).first
    second = Email::Enqueue.from_mail(account:, message:).first
    adapter = Email::Adapters::Fake.new

    result = described_class.new(adapter:, worker_name: "email-test").deliver_batch

    expect(second).to eq(first)
    expect(result).to have_attributes(claimed: 1, delivered: 1, retried: 0, failed: 0)
    expect(first.reload).to have_attributes(
      state: "delivered",
      provider: "fake",
      attempt_count: 1,
      provider_message_id: "fake_#{first.public_id}",
    )
    expect(adapter.deliveries.one?).to be(true)
    expect(described_class.new(adapter:, worker_name: "email-test-2").deliver_batch.claimed).to eq(0)
  end

  it "backs off a transient provider failure without losing the intent" do
    account = create_account
    create_organization(account:)
    intent = Email::Enqueue.from_mail(
      account:,
      message: Mail.new(to: account.email, subject: "Reset", body: "Reset body"),
    ).first
    adapter = Class.new do
      def provider_name = "unavailable"
      def terminal_state = "sent"
      def deliver(**) = raise(Timeout::Error, "provider timeout")
    end.new

    result = described_class.new(adapter:, worker_name: "email-retry").deliver_batch

    expect(result).to have_attributes(retried: 1, failed: 0)
    expect(intent.reload).to have_attributes(state: "retryable", attempt_count: 1)
    expect(intent.next_attempt_at).to be > Time.current
  end
end
