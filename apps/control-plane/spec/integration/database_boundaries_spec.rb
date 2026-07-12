require "rails_helper"

RSpec.describe "database security boundaries" do
  it "shows only the selected organization when account membership matches" do
    demo = create_account
    foreign = create_account(email: "foreign@example.test", name: "Foreign")
    demo_org = create_organization(account: demo, slug: "demo")
    foreign_org = create_organization(account: foreign, slug: "foreign")
    within_organization(demo, demo_org) do
      Projects::Create.call(account: demo, organization: demo_org, attributes: { name: "Visible", slug: "visible" })
    end
    within_organization(foreign, foreign_org) do
      Projects::Create.call(account: foreign, organization: foreign_org, attributes: { name: "Hidden", slug: "hidden" })
    end

    connection = ApplicationRecord.connection
    connection.execute("SET LOCAL ROLE lrail_web")
    connection.execute("SELECT set_config('lrail.account_id', '#{demo.id}', true)")
    connection.execute("SELECT set_config('lrail.organization_id', '#{demo_org.id}', true)")
    expect(connection.select_value("SELECT count(*) FROM projects")).to eq(1)

    connection.execute("SELECT set_config('lrail.organization_id', '#{foreign_org.id}', true)")
    expect(connection.select_value("SELECT count(*) FROM projects")).to eq(0)
    expect(connection.select_value("SELECT count(*) FROM organizations WHERE id = #{foreign_org.id}")).to eq(0)
  ensure
    ApplicationRecord.connection.execute("RESET ROLE")
  end

  it "denies direct password hash reads to the web role" do
    create_account

    expect do
      ApplicationRecord.transaction(requires_new: true) do
        ApplicationRecord.connection.execute("SET LOCAL ROLE lrail_web")
        ApplicationRecord.connection.select_all("SELECT password_hash FROM account_password_hashes")
      end
    end.to raise_error(ActiveRecord::StatementInvalid, /permission denied/)
  end

  it "prevents removal of the last active owner" do
    account = create_account
    organization = create_organization(account:)

    expect do
      ApplicationRecord.transaction(requires_new: true) do
        organization.memberships.first.destroy!
      end
    end.to raise_error(ActiveRecord::StatementInvalid, /retain an active owner/)
  end
end
