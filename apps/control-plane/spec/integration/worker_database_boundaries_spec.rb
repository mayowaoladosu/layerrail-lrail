require "rails_helper"

RSpec.describe "worker database boundaries" do
  it "claims and completes outbox rows without granting direct table reads" do
    account = create_account
    organization = create_organization(account:)
    event = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Worker", slug: "worker" })
      OutboxEvent.order(:id).last
    end
    connection = ApplicationRecord.connection

    expect do
      ApplicationRecord.transaction(requires_new: true) do
        connection.execute("SET LOCAL ROLE lrail_worker")
        connection.select_all("SELECT * FROM outbox_events")
      end
    end.to raise_error(ActiveRecord::StatementInvalid, /permission denied/)
    connection.execute("RESET ROLE")

    ApplicationRecord.transaction(requires_new: true) do
      connection.execute("SET LOCAL ROLE lrail_worker")
      claimed = connection.select_one("SELECT * FROM lrail_claim_outbox('boundary-worker', 1)")
      expect(claimed.fetch("public_id")).to eq(event.public_id)
      expect(connection.select_value("SELECT lrail_finish_outbox(#{claimed.fetch("id")}, 'boundary-worker', true, NULL, NULL, false)")).to be(true)
      connection.execute("RESET ROLE")
    end

    expect(event.reload.published_at).to be_present
  end

  it "delivers email state without granting direct email table reads" do
    account = create_account
    organization = create_organization(account:)
    intent = within_organization(account, organization) do
      EmailIntent.create!(
        organization:,
        account:,
        template: "rodauth_message",
        template_version: 1,
        recipient: account.email,
        data: { "subject" => "Boundary", "text" => "Body" },
        idempotency_key: "worker-boundary",
        state: "pending",
      )
    end
    connection = ApplicationRecord.connection

    expect do
      ApplicationRecord.transaction(requires_new: true) do
        connection.execute("SET LOCAL ROLE lrail_worker")
        connection.select_all("SELECT * FROM email_intents")
      end
    end.to raise_error(ActiveRecord::StatementInvalid, /permission denied/)
    connection.execute("RESET ROLE")

    ApplicationRecord.transaction(requires_new: true) do
      connection.execute("SET LOCAL ROLE lrail_worker")
      claimed = connection.select_one("SELECT * FROM lrail_claim_email('email-boundary', 1)")
      expect(claimed.fetch("public_id")).to eq(intent.public_id)
      expect(
        connection.select_value(
          "SELECT lrail_finish_email(#{claimed.fetch("id")}, 'email-boundary', 'delivered', 'fake', 'fake-boundary', NULL, NULL)",
        ),
      ).to be(true)
      connection.execute("RESET ROLE")
    end

    expect(intent.reload).to have_attributes(state: "delivered", provider_message_id: "fake-boundary")
  end
end
