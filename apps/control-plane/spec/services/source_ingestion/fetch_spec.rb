require "rails_helper"

RSpec.describe SourceIngestion::Fetch do
  let(:account) { create_account(email: "fetch-owner@example.test") }
  let(:organization) { create_organization(account:, slug: "fetch-owner") }
  let(:project) do
    within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Provider Source", slug: "provider-source" },
      ).project
    end
  end
  let(:source_connection) do
    within_organization(account, organization) do
      SourceConnection.create!(
        organization:,
        connected_by_account: account,
        provider: "github",
        installation_external_id: "8100001",
        status: "active",
        scopes: %w[contents:read metadata:read],
        provider_account_login: "northstar",
        repository_selection: "selected",
        selected_repositories: [ "northstar/checkout" ],
      )
    end
  end

  it "persists an exact signed result and immutably reuses identical content" do
    service = described_class.new(gateway: gateway)

    first = within_organization(account, organization) do
      service.call(
        account:,
        organization:,
        project:,
        source_connection:,
        repository: "NorthStar/Checkout",
        commit_sha: "A" * 40,
        root_directory: "apps/web",
      )
    end
    original = first.snapshot.attributes.slice("repository", "commit_sha", "object_ref", "size_bytes")

    second = within_organization(account, organization) do
      service.call(
        account:,
        organization:,
        project:,
        source_connection:,
        repository: "northstar/checkout",
        commit_sha: "a" * 40,
        root_directory: "apps/web",
      )
    end

    expect(first.fetch).to have_attributes(
      state: "complete",
      requested_commit_sha: "a" * 40,
      resolved_commit_sha: "a" * 40,
      tree_sha: "b" * 40,
      signing_key_id: "source-finalizer-test-v1",
      author: "Example Author",
      policy_version: "source-v1",
      warnings: [],
      submodules: [],
      lfs_digests: [],
    )
    expect(second.snapshot.id).to eq(first.snapshot.id)
    expect(second.snapshot.reload.attributes.slice(*original.keys)).to eq(original)
    expect(SourceSnapshot.where(project:).count).to eq(1)
    expect(SourceFetch.where(project:).count).to eq(2)
    expect(OutboxEvent.where(event_type: "source.snapshot.created").count).to eq(1)
    expect(OutboxEvent.where(event_type: "source.snapshot.reused").count).to eq(1)
  end

  it "records a terminally visible failure when the gateway rejects acquisition" do
    failed_gateway = Object.new
    failed_gateway.define_singleton_method(:fetch) { |_fetch| raise SourceIngestion::GatewayClient::Error, "provider unavailable" }

    result = within_organization(account, organization) do
      described_class.new(gateway: failed_gateway).call(
        account:,
        organization:,
        project:,
        source_connection:,
        repository: "northstar/checkout",
        commit_sha: "a" * 40,
      )
    end

    expect(result).not_to be_success
    expect(result.error).to be_a(SourceIngestion::GatewayClient::Error)
    expect(SourceFetch.last).to have_attributes(state: "failed", attempt_count: 1)
    expect(SourceFetch.last.last_error).to include("GatewayClient::Error")
    expect(SourceSnapshot.where(project:)).to be_empty
  end

  it "fails closed when a gateway result substitutes another commit" do
    substituted = gateway { |result| result.merge("resolved_commit_sha" => "f" * 40) }

    result = within_organization(account, organization) do
      described_class.new(gateway: substituted).call(
        account:,
        organization:,
        project:,
        source_connection:,
        repository: "northstar/checkout",
        commit_sha: "a" * 40,
      )
    end

    expect(result).not_to be_success
    expect(result.error).to be_a(SourceIngestion::FetchResultVerifier::Invalid)
    expect(SourceFetch.last.state).to eq("failed")
    expect(SourceSnapshot.where(project:)).to be_empty
  end

  it "rejects a foreign installation and an unselected repository before gateway access" do
    foreign = create_account(email: "fetch-foreign@example.test")
    foreign_organization = create_organization(account: foreign, slug: "fetch-foreign")
    foreign_connection = within_organization(foreign, foreign_organization) do
      SourceConnection.create!(
        organization: foreign_organization,
        connected_by_account: foreign,
        provider: "github",
        installation_external_id: "8100002",
        status: "active",
        scopes: %w[contents:read metadata:read],
        provider_account_login: "foreign",
        repository_selection: "all",
        selected_repositories: [],
      )
    end
    never_called = Object.new
    never_called.define_singleton_method(:fetch) { |_fetch| raise "gateway must not be called" }
    service = described_class.new(gateway: never_called)

    expect do
      within_organization(account, organization) do
        service.call(
          account:,
          organization:,
          project:,
          source_connection: foreign_connection,
          repository: "northstar/checkout",
          commit_sha: "a" * 40,
        )
      end
    end.to raise_error(ActiveRecord::RecordNotFound)

    expect do
      within_organization(account, organization) do
        service.call(
          account:,
          organization:,
          project:,
          source_connection:,
          repository: "northstar/not-selected",
          commit_sha: "a" * 40,
        )
      end
    end.to raise_error(ActiveRecord::RecordNotFound)
    expect(SourceFetch.where(organization:)).to be_empty
  end

  def gateway(&transform)
    transform ||= ->(result) { result }
    object = Object.new
    object.define_singleton_method(:fetch) do |fetch|
      result = {
        "repository" => fetch.repository,
        "requested_commit_sha" => fetch.requested_commit_sha,
        "resolved_commit_sha" => fetch.requested_commit_sha,
        "tree_sha" => "b" * 40,
        "snapshot_sha256" => "sha256:#{"c" * 64}",
        "manifest_sha256" => "sha256:#{"d" * 64}",
        "archive_sha256" => "sha256:#{"e" * 64}",
        "manifest_ref" => "s3://lrail-source/snapshots/c/manifest.json",
        "archive_ref" => "s3://lrail-source/snapshots/c/source.tar.gz",
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
      transform.call(result)
    end
    object
  end
end
