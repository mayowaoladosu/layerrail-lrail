require "rails_helper"

RSpec.describe ProcessGithubDeliveryJob do
  let(:secret) { "provider-workflow-test-secret-32-bytes" }
  let(:account) { create_account(email: "provider-workflow@example.test") }
  let(:organization) { create_organization(account:, slug: "provider-workflow") }
  let(:project) do
    within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Provider Workflow", slug: "provider-workflow" },
      ).project
    end
  end
  let(:source_connection) do
    within_organization(account, organization) do
      SourceProviders::ConnectGithubInstallation.call(
        account:,
        organization:,
        installation_id: "9100001",
        account_login: "northstar",
        account_id: 910,
        repository_selection: "selected",
        repositories: [ "northstar/checkout" ],
      ).source_connection
    end
  end
  let!(:binding) do
    within_organization(account, organization) do
      SourceProviders::ConnectProject.call(
        account:,
        organization:,
        project:,
        source_connection:,
        repository: "northstar/checkout",
        production_branch: "main",
        root_directory: "apps/web",
      ).binding
    end
  end

  it "acquires the exact push, gives replay one effect, and supersedes on force push" do
    allow(SourceIngestion).to receive(:gateway_client).and_return(gateway)
    first = receive_push(commit: "a" * 40, before: "0" * 40, delivery_id: "aaaaaaaa-9100-4000-8000-000000000001")

    described_class.new.perform(
      first.delivery_public_id,
      first.organization_public_id,
      first.actor_public_id,
    )

    first_delivery = SourceProviderDelivery.find_by!(public_id: first.delivery_public_id)
    first_fetch = SourceFetch.find_by!(source_provider_delivery: first_delivery)
    expect(first_delivery).to have_attributes(state: "processed", attempt_count: 1)
    expect(first_fetch).to have_attributes(
      state: "complete",
      requested_commit_sha: "a" * 40,
      resolved_commit_sha: "a" * 40,
      root_directory: "apps/web",
    )
    expect(first_fetch.source_snapshot.commit_sha).to eq("a" * 40)
    first_deployment = first_fetch.deployment
    expect(first_deployment).to have_attributes(
      source_snapshot: first_fetch.source_snapshot,
      environment: project.environments.find_by!(slug: "production"),
      build_mode: "auto",
      accept_detected: true,
    )
    expect(first_deployment.source.fetch("commit")).to eq("a" * 40)

    replay = receive_push(commit: "a" * 40, before: "0" * 40, delivery_id: "aaaaaaaa-9100-4000-8000-000000000001")
    expect(replay.outcome).to eq("duplicate")
    expect do
      described_class.new.perform(
        replay.delivery_public_id,
        replay.organization_public_id,
        replay.actor_public_id,
      )
    end.to change(SourceFetch, :count).by(0)
      .and change(SourceSnapshot, :count).by(0)
      .and change(Deployment, :count).by(0)

    branch = receive_push(
      commit: "f" * 40,
      before: "a" * 40,
      delivery_id: "dddddddd-9100-4000-8000-000000000004",
      ref: "refs/heads/feature/preview",
    )
    expect do
      described_class.new.perform(
        branch.delivery_public_id,
        branch.organization_public_id,
        branch.actor_public_id,
      )
    end.to change(SourceFetch, :count).by(0)
      .and change(SourceSnapshot, :count).by(0)
      .and change(Deployment, :count).by(0)
    expect(SourceProviderDelivery.find_by!(public_id: branch.delivery_public_id).state).to eq("processed")

    forced = receive_push(
      commit: "b" * 40,
      before: "a" * 40,
      delivery_id: "bbbbbbbb-9100-4000-8000-000000000002",
      forced: true,
    )
    described_class.new.perform(
      forced.delivery_public_id,
      forced.organization_public_id,
      forced.actor_public_id,
    )

    second_fetch = SourceFetch.find_by!(source_provider_delivery: SourceProviderDelivery.find_by!(public_id: forced.delivery_public_id))
    expect(second_fetch).to have_attributes(
      state: "complete",
      requested_commit_sha: "b" * 40,
      resolved_commit_sha: "b" * 40,
    )
    expect(first_fetch.reload).to have_attributes(
      superseded_by_source_fetch_id: second_fetch.id,
    )
    expect(first_fetch.superseded_at).to be_present
    expect(binding.reload).to have_attributes(
      current_source_fetch_id: second_fetch.id,
      last_provider_delivery_id: second_fetch.source_provider_delivery_id,
      requested_commit_sha: "b" * 40,
      generation: 3,
    )
    expect(SourceFetch.where(project_source_binding: binding).count).to eq(2)
    expect(SourceSnapshot.where(project:).count).to eq(2)
    expect(Deployment.where(project:).count).to eq(2)
    expect(second_fetch.deployment).to have_attributes(
      source_snapshot: second_fetch.source_snapshot,
      environment: project.environments.find_by!(slug: "production"),
    )
  end

  it "records a failed lease and retries the same fetch identity to completion" do
    attempts = 0
    flaky_gateway = gateway do |fetch, result|
      attempts += 1
      raise SourceIngestion::GatewayClient::Error, "inert provider failure" if attempts == 1

      result
    end
    allow(SourceIngestion).to receive(:gateway_client).and_return(flaky_gateway)
    delivery_result = receive_push(
      commit: "c" * 40,
      before: "0" * 40,
      delivery_id: "cccccccc-9100-4000-8000-000000000003",
    )

    expect do
      described_class.new.perform(
        delivery_result.delivery_public_id,
        delivery_result.organization_public_id,
        delivery_result.actor_public_id,
      )
    end.to raise_error(described_class::Retryable, /GatewayClient::Error/)

    delivery = SourceProviderDelivery.find_by!(public_id: delivery_result.delivery_public_id)
    fetch = SourceFetch.find_by!(source_provider_delivery: delivery)
    expect(delivery.reload).to have_attributes(state: "failed", attempt_count: 1)
    expect(fetch.reload).to have_attributes(state: "failed", attempt_count: 1)

    described_class.new.perform(
      delivery_result.delivery_public_id,
      delivery_result.organization_public_id,
      delivery_result.actor_public_id,
    )

    expect(delivery.reload).to have_attributes(state: "processed", attempt_count: 2, last_error: nil)
    expect(fetch.reload).to have_attributes(state: "complete", attempt_count: 2)
    expect(SourceFetch.where(source_provider_delivery: delivery).count).to eq(1)
    expect(fetch.deployment).to be_present
    expect(Deployment.where(source_fetch: fetch).count).to eq(1)
  end

  it "supersedes only the same pull-request preview without replacing production" do
    allow(SourceIngestion).to receive(:gateway_client).and_return(gateway)
    production = receive_push(
      commit: "a" * 40,
      before: "0" * 40,
      delivery_id: "eeeeeeee-9100-4000-8000-000000000005",
    )
    described_class.new.perform(
      production.delivery_public_id,
      production.organization_public_id,
      production.actor_public_id,
    )
    production_fetch = binding.reload.current_source_fetch

    opened = receive_pull_request(
      action: "opened",
      number: 42,
      commit: "d" * 40,
      base: "a" * 40,
      delivery_id: "ffffffff-9100-4000-8000-000000000006",
    )
    described_class.new.perform(opened.delivery_public_id, opened.organization_public_id, opened.actor_public_id)
    first_preview = SourceFetch.find_by!(
      source_provider_delivery: SourceProviderDelivery.find_by!(public_id: opened.delivery_public_id),
    )

    synchronize = receive_pull_request(
      action: "synchronize",
      number: 42,
      commit: "e" * 40,
      base: "a" * 40,
      delivery_id: "12121212-9100-4000-8000-000000000007",
    )
    described_class.new.perform(
      synchronize.delivery_public_id,
      synchronize.organization_public_id,
      synchronize.actor_public_id,
    )
    second_preview = SourceFetch.find_by!(
      source_provider_delivery: SourceProviderDelivery.find_by!(public_id: synchronize.delivery_public_id),
    )

    expect(binding.reload.current_source_fetch_id).to eq(production_fetch.id)
    expect(production_fetch.reload.superseded_at).to be_nil
    expect(first_preview.reload).to have_attributes(superseded_by_source_fetch_id: second_preview.id)
    expect(first_preview.superseded_at).to be_present
    expect(second_preview).to have_attributes(state: "complete", requested_commit_sha: "e" * 40)
    expect(production_fetch.deployment.environment.slug).to eq("production")
    expect(first_preview.deployment.environment.slug).to eq("preview")
    expect(second_preview.deployment.environment.slug).to eq("preview")
  end

  it "routes new work through an active owner after the original connector leaves" do
    allow(SourceIngestion).to receive(:gateway_client).and_return(gateway)
    fallback = create_account(email: "provider-fallback@example.test")
    within_organization(account, organization) do
      Membership.create!(account: fallback, organization:, role: "owner", status: "active")
      Membership.find_by!(account:, organization:).update!(status: "revoked", revoked_at: Time.current)
    end

    delivery = receive_push(
      commit: "a" * 40,
      before: "0" * 40,
      delivery_id: "34343434-9100-4000-8000-000000000008",
    )

    expect(delivery.actor_public_id).to eq(fallback.public_id)
    described_class.new.perform(
      delivery.delivery_public_id,
      delivery.organization_public_id,
      delivery.actor_public_id,
    )
    expect(SourceProviderDelivery.find_by!(public_id: delivery.delivery_public_id).state).to eq("processed")
    expect(
      SourceFetch.find_by!(
        source_provider_delivery: SourceProviderDelivery.find_by!(public_id: delivery.delivery_public_id),
      ).state,
    ).to eq("complete")
  end

  def receive_push(commit:, before:, delivery_id:, forced: false, ref: "refs/heads/main")
    payload = {
      "installation" => { "id" => 9_100_001 },
      "repository" => { "full_name" => "northstar/checkout" },
      "ref" => ref,
      "before" => before,
      "after" => commit,
      "forced" => forced,
      "deleted" => false
    }
    body = JSON.generate(payload)
    SourceProviders::GithubWebhook.new(secret:).process(
      raw_body: body,
      headers: {
        "x-hub-signature-256" => "sha256=#{OpenSSL::HMAC.hexdigest("SHA256", secret, body)}",
        "x-github-delivery" => delivery_id,
        "x-github-event" => "push"
      },
    )
  end

  def receive_pull_request(action:, number:, commit:, base:, delivery_id:)
    payload = {
      "action" => action,
      "installation" => { "id" => 9_100_001 },
      "repository" => { "full_name" => "northstar/checkout" },
      "number" => number,
      "pull_request" => {
        "head" => { "sha" => commit, "ref" => "feature/provider" },
        "base" => { "sha" => base }
      }
    }
    body = JSON.generate(payload)
    SourceProviders::GithubWebhook.new(secret:).process(
      raw_body: body,
      headers: {
        "x-hub-signature-256" => "sha256=#{OpenSSL::HMAC.hexdigest("SHA256", secret, body)}",
        "x-github-delivery" => delivery_id,
        "x-github-event" => "pull_request"
      },
    )
  end

  def gateway(&transform)
    transform ||= ->(_fetch, result) { result }
    object = Object.new
    object.define_singleton_method(:fetch) do |fetch|
      digest_character = { "a" => "d", "b" => "e", "c" => "f", "d" => "3", "e" => "4" }
        .fetch(fetch.requested_commit_sha.first, "c")
      result = {
        "repository" => fetch.repository,
        "requested_commit_sha" => fetch.requested_commit_sha,
        "resolved_commit_sha" => fetch.requested_commit_sha,
        "tree_sha" => digest_character * 40,
        "snapshot_sha256" => "sha256:#{digest_character * 64}",
        "manifest_sha256" => "sha256:#{"1" * 64}",
        "archive_sha256" => "sha256:#{"2" * 64}",
        "manifest_ref" => "s3://lrail-source/snapshots/#{digest_character}/manifest.json",
        "archive_ref" => "s3://lrail-source/snapshots/#{digest_character}/source.tar.gz",
        "size_bytes" => 1_024,
        "policy_version" => "source-v1",
        "author" => "Example Author",
        "authored_at" => 1.day.ago.iso8601,
        "warnings" => [],
        "submodules" => [],
        "lfs_digests" => [],
        "token_expires_at" => 30.minutes.from_now.iso8601,
        "finalized_at" => Time.current.iso8601,
        "_key_id" => "source-finalizer-test-v1"
      }
      transform.call(fetch, result)
    end
    object
  end
end
