require "rails_helper"

RSpec.describe "GitHub webhook", type: :request do
  let(:secret) { "github-webhook-test-secret-32-bytes" }
  let(:account) { create_account }
  let(:organization) { create_organization(account:) }
  let!(:connection) do
    within_organization(account, organization) do
      SourceConnection.create!(
        organization:,
        connected_by_account: account,
        provider: "github",
        installation_external_id: "4240374",
        status: "active",
        scopes: %w[contents:read metadata:read],
        provider_account_login: "northstar",
        provider_account_id: 101,
        repository_selection: "selected",
        selected_repositories: [ "northstar/checkout" ],
      )
    end
  end

  around do |example|
    previous = ENV["LRAIL_GITHUB_WEBHOOK_SECRET"]
    ENV["LRAIL_GITHUB_WEBHOOK_SECRET"] = secret
    example.run
  ensure
    ENV["LRAIL_GITHUB_WEBHOOK_SECRET"] = previous
  end

  it "records one exact push effect and deduplicates an identical replay" do
    body = JSON.generate(push_payload)
    delivery_id = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"
    queued_before = ActiveJob::Base.queue_adapter.enqueued_jobs.length

    expect { deliver(body:, event: "push", delivery_id:) }
      .to change(SourceProviderDelivery, :count).by(1)
      .and change(OutboxEvent, :count).by(1)
      .and change(AuditEvent, :count).by(1)
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("outcome")).to eq("received")
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs.length).to eq(queued_before + 1)

    delivery = SourceProviderDelivery.find_by!(external_delivery_id: delivery_id)
    expect(delivery).to have_attributes(
      organization_id: organization.id,
      source_connection_id: connection.id,
      event_type: "push",
      state: "received",
      repository: "northstar/checkout",
      ref: "refs/heads/main",
      commit_sha: "a" * 40,
      base_commit_sha: nil,
      forced: false,
      deleted: false,
    )
    event = OutboxEvent.find_by!(event_type: "source.provider.push")
    expect(event.data).to include(
      "delivery_id" => delivery_id,
      "repository" => "northstar/checkout",
      "commit_sha" => "a" * 40,
    )
    expect(event.organization_public_id).to eq(organization.public_id)

    expect { deliver(body:, event: "push", delivery_id:) }
      .to change(SourceProviderDelivery, :count).by(0)
      .and change(OutboxEvent, :count).by(0)
      .and change(AuditEvent, :count).by(0)
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("outcome")).to eq("duplicate")
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs.length).to eq(queued_before + 2)
  end

  it "rejects delivery identity reuse with different content" do
    delivery_id = "cccccccc-1111-4222-8333-dddddddddddd"
    deliver(body: JSON.generate(push_payload), event: "push", delivery_id:)

    changed = push_payload.merge("after" => "b" * 40)
    expect { deliver(body: JSON.generate(changed), event: "push", delivery_id:) }
      .to change(SourceProviderDelivery, :count).by(0)
      .and change(OutboxEvent, :count).by(0)
    expect(response).to have_http_status(:conflict)
    expect(response.parsed_body.dig("error", "code")).to eq("delivery_mismatch")
  end

  it "re-enqueues an identical provider retry after a processing lease goes stale" do
    body = JSON.generate(push_payload)
    delivery_id = "abababab-1111-4222-8333-cdcdcdcdcdcd"
    deliver(body:, event: "push", delivery_id:)
    delivery = SourceProviderDelivery.find_by!(external_delivery_id: delivery_id)
    delivery.update_columns(
      state: "processing",
      processing_token: "abandoned-lease-0001",
      processing_started_at: 21.minutes.ago,
    )
    queued_before = ActiveJob::Base.queue_adapter.enqueued_jobs.length

    deliver(body:, event: "push", delivery_id:)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("outcome")).to eq("duplicate")
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs.length).to eq(queued_before + 1)
  end

  it "normalizes a pull-request synchronize delivery to its exact head and base commits" do
    payload = {
      "action" => "synchronize",
      "installation" => { "id" => 4_240_374 },
      "repository" => { "full_name" => "NorthStar/Checkout" },
      "number" => 27,
      "pull_request" => {
        "head" => { "sha" => "b" * 40, "ref" => "feature/provider" },
        "base" => { "sha" => "c" * 40 }
      }
    }

    deliver(
      body: JSON.generate(payload),
      event: "pull_request",
      delivery_id: "eeeeeeee-1111-4222-8333-ffffffffffff",
    )

    expect(response).to have_http_status(:ok)
    expect(SourceProviderDelivery.last).to have_attributes(
      event_type: "pull_request",
      action: "synchronize",
      repository: "northstar/checkout",
      ref: "feature/provider",
      commit_sha: "b" * 40,
      base_commit_sha: "c" * 40,
      pull_request_number: 27,
    )
  end

  it "applies installation suspension and repository add/remove deltas" do
    project = within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Webhook Binding", slug: "webhook-binding" },
      ).project
    end
    binding = within_organization(account, organization) do
      SourceProviders::ConnectProject.call(
        account:,
        organization:,
        project:,
        source_connection: connection,
        repository: "northstar/checkout",
      ).binding
    end
    installation = {
      "action" => "suspend",
      "installation" => {
        "id" => 4_240_374,
        "account" => { "login" => "NorthStar", "id" => 202 },
        "repository_selection" => "selected"
      }
    }
    deliver(
      body: JSON.generate(installation),
      event: "installation",
      delivery_id: "11111111-2222-4333-8444-555555555555",
    )
    expect(response).to have_http_status(:ok)
    expect(connection.reload).to have_attributes(
      status: "suspended",
      provider_account_login: "NorthStar",
      provider_account_id: 202,
    )
    expect(binding.reload).to have_attributes(automatic_deployments: false, generation: 2)

    suspended_push = push_payload.merge("after" => "b" * 40)
    queued_before = ActiveJob::Base.queue_adapter.enqueued_jobs.length
    deliver(
      body: JSON.generate(suspended_push),
      event: "push",
      delivery_id: "16161616-2222-4333-8444-555555555555",
    )
    expect(response.parsed_body.fetch("outcome")).to eq("ignored")
    expect(ActiveJob::Base.queue_adapter.enqueued_jobs.length).to eq(queued_before)

    within_organization(account, organization) { binding.update!(automatic_deployments: true) }

    added = {
      "action" => "added",
      "installation" => { "id" => 4_240_374 },
      "repository_selection" => "selected",
      "repositories_added" => [
        { "full_name" => "NorthStar/API" },
        { "full_name" => "NorthStar/Checkout" }
      ],
      "repositories_removed" => []
    }
    deliver(
      body: JSON.generate(added),
      event: "installation_repositories",
      delivery_id: "22222222-3333-4444-8555-666666666666",
    )
    expect(connection.reload.selected_repositories).to eq(%w[northstar/api northstar/checkout])

    removed = added.merge(
      "action" => "removed",
      "repositories_added" => [],
      "repositories_removed" => [ { "full_name" => "northstar/checkout" } ],
    )
    deliver(
      body: JSON.generate(removed),
      event: "installation_repositories",
      delivery_id: "33333333-4444-4555-8666-777777777777",
    )
    expect(connection.reload.selected_repositories).to eq([ "northstar/api" ])
    expect(binding.reload).to have_attributes(automatic_deployments: false, generation: 3)
  end

  it "rejects a tampered raw body and accepts a stale installation without persistence" do
    body = JSON.generate(push_payload)
    headers = signed_headers(body, event: "push", delivery_id: "44444444-5555-4666-8777-888888888888")
    post "/webhooks/github", params: "#{body} ", headers: headers
    expect(response).to have_http_status(:unauthorized)

    unknown = push_payload.merge("installation" => { "id" => 9_999_999 })
    expect do
      deliver(
        body: JSON.generate(unknown),
        event: "push",
        delivery_id: "55555555-6666-4777-8888-999999999999",
      )
    end.to change(SourceProviderDelivery, :count).by(0)
    expect(response).to have_http_status(:accepted)
    expect(response.parsed_body.fetch("outcome")).to eq("unknown_installation")
  end

  def push_payload
    {
      "installation" => { "id" => 4_240_374 },
      "repository" => { "full_name" => "NorthStar/Checkout" },
      "ref" => "refs/heads/main",
      "before" => "0" * 40,
      "after" => "a" * 40,
      "forced" => false,
      "deleted" => false
    }
  end

  def deliver(body:, event:, delivery_id:)
    post "/webhooks/github", params: body, headers: signed_headers(body, event:, delivery_id:)
  end

  def signed_headers(body, event:, delivery_id:)
    signature = OpenSSL::HMAC.hexdigest("SHA256", secret, body)
    {
      "CONTENT_TYPE" => "application/json",
      "HTTP_X_HUB_SIGNATURE_256" => "sha256=#{signature}",
      "HTTP_X_GITHUB_DELIVERY" => delivery_id,
      "HTTP_X_GITHUB_EVENT" => event
    }
  end
end
