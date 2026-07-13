require "rails_helper"

RSpec.describe "GitHub provider database boundaries" do
  let(:secret) { "github-provider-boundary-secret-32" }

  it "allows function ingress but denies direct delivery mutation to the web role" do
    account = create_account
    organization = create_organization(account:)
    connection = create_connection(account:, organization:, installation_id: "7000001")
    payload = push_payload(installation_id: 7_000_001, commit: "a" * 40)
    body = JSON.generate(payload)
    headers = signed_headers(body, delivery_id: "aaaaaaaa-7000-4000-8000-000000000001")
    database = ApplicationRecord.connection

    ApplicationRecord.transaction(requires_new: true) do
      database.execute("SET LOCAL ROLE lrail_web")
      result = SourceProviders::GithubWebhook.new(secret:).process(raw_body: body, headers:)
      expect(result.outcome).to eq("received")

      database.execute("SELECT set_config('lrail.account_id', '#{account.id}', true)")
      database.execute("SELECT set_config('lrail.organization_id', '#{organization.id}', true)")
      expect(database.select_value("SELECT count(*) FROM source_provider_deliveries")).to eq(1)
      expect(database.select_value("SELECT source_connection_id FROM source_provider_deliveries")).to eq(connection.id)
      database.execute("RESET ROLE")
    end

    expect do
      ApplicationRecord.transaction(requires_new: true) do
        database.execute("SET LOCAL ROLE lrail_web")
        database.execute("DELETE FROM source_provider_deliveries")
      end
    end.to raise_error(ActiveRecord::StatementInvalid, /permission denied/)
    database.execute("RESET ROLE")
  end

  it "filters delivery evidence by membership and organization context" do
    account = create_account(email: "provider-owner@example.test")
    foreign = create_account(email: "provider-foreign@example.test")
    organization = create_organization(account:, slug: "provider-owner")
    foreign_organization = create_organization(account: foreign, slug: "provider-foreign")
    create_connection(account:, organization:, installation_id: "7000002")
    create_connection(account: foreign, organization: foreign_organization, installation_id: "7000003")
    deliver(installation_id: 7_000_002, delivery_id: "bbbbbbbb-7000-4000-8000-000000000002")
    deliver(installation_id: 7_000_003, delivery_id: "cccccccc-7000-4000-8000-000000000003")
    database = ApplicationRecord.connection

    ApplicationRecord.transaction(requires_new: true) do
      database.execute("SET LOCAL ROLE lrail_web")
      database.execute("SELECT set_config('lrail.account_id', '#{account.id}', true)")
      database.execute("SELECT set_config('lrail.organization_id', '#{organization.id}', true)")
      expect(database.select_value("SELECT count(*) FROM source_provider_deliveries")).to eq(1)

      database.execute("SELECT set_config('lrail.organization_id', '#{foreign_organization.id}', true)")
      expect(database.select_value("SELECT count(*) FROM source_provider_deliveries")).to eq(0)
    ensure
      database.execute("RESET ROLE")
    end
  end

  it "prevents one GitHub installation from being substituted into a second tenant" do
    account = create_account(email: "provider-first@example.test")
    foreign = create_account(email: "provider-second@example.test")
    organization = create_organization(account:, slug: "provider-first")
    foreign_organization = create_organization(account: foreign, slug: "provider-second")
    create_connection(account:, organization:, installation_id: "7000004")

    expect do
      create_connection(account: foreign, organization: foreign_organization, installation_id: "7000004")
    end.to raise_error(ActiveRecord::RecordInvalid, /Installation external has already been taken/)
  end

  it "does not lease a foreign delivery or grant provider ingress to the generic worker" do
    account = create_account(email: "provider-lease-owner@example.test")
    foreign = create_account(email: "provider-lease-foreign@example.test")
    organization = create_organization(account:, slug: "provider-lease-owner")
    foreign_organization = create_organization(account: foreign, slug: "provider-lease-foreign")
    create_connection(account:, organization:, installation_id: "7000005")
    create_connection(account: foreign, organization: foreign_organization, installation_id: "7000006")
    foreign_result = deliver(
      installation_id: 7_000_006,
      delivery_id: "dddddddd-7000-4000-8000-000000000004",
    )
    database = ApplicationRecord.connection

    ApplicationRecord.transaction(requires_new: true) do
      database.execute("SET LOCAL ROLE lrail_web")
      database.execute("SELECT set_config('lrail.account_id', '#{account.id}', true)")
      database.execute("SELECT set_config('lrail.organization_id', '#{organization.id}', true)")
      outcome = database.select_value(<<~SQL.squish)
        SELECT lrail_claim_github_provider_delivery(
          #{database.quote(foreign_result.delivery_public_id)},
          'lease-test-00000001'
        )
      SQL
      expect(outcome).to eq("unknown")
      database.execute("RESET ROLE")
    end

    apply_signature = "lrail_apply_github_provider_delivery(text,text,text,text,text,text,text,text,text,integer,boolean,boolean,text,text,text,bigint,text,text,jsonb,text,text,text,text)"
    expect(database.select_value("SELECT has_function_privilege('lrail_worker', #{database.quote(apply_signature)}, 'EXECUTE')"))
      .to be(false)
    expect(SourceProviderDelivery.find_by!(public_id: foreign_result.delivery_public_id).state).to eq("received")
  end

  def create_connection(account:, organization:, installation_id:)
    within_organization(account, organization) do
      SourceConnection.create!(
        organization:,
        connected_by_account: account,
        provider: "github",
        installation_external_id: installation_id,
        status: "active",
        scopes: %w[contents:read metadata:read],
        provider_account_login: "provider-#{installation_id}",
        repository_selection: "selected",
        selected_repositories: [ "northstar/checkout" ],
      )
    end
  end

  def deliver(installation_id:, delivery_id:)
    payload = push_payload(installation_id:, commit: delivery_id.delete("-").first(40).ljust(40, "a"))
    body = JSON.generate(payload)
    SourceProviders::GithubWebhook.new(secret:).process(
      raw_body: body,
      headers: signed_headers(body, delivery_id:),
    )
  end

  def push_payload(installation_id:, commit:)
    {
      "installation" => { "id" => installation_id },
      "repository" => { "full_name" => "northstar/checkout" },
      "ref" => "refs/heads/main",
      "before" => "0" * 40,
      "after" => commit,
      "forced" => false,
      "deleted" => false
    }
  end

  def signed_headers(body, delivery_id:)
    {
      "x-hub-signature-256" => "sha256=#{OpenSSL::HMAC.hexdigest("SHA256", secret, body)}",
      "x-github-delivery" => delivery_id,
      "x-github-event" => "push"
    }
  end
end
