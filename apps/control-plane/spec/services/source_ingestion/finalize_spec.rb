require "rails_helper"

RSpec.describe SourceIngestion::Finalize do
  class SuccessfulSourceGateway
    attr_reader :calls

    def initialize
      @calls = 0
    end

    def finalize(session, parts:)
      @calls += 1
      {
        "version" => 1,
        "session_id" => session.public_id,
        "organization_id" => session.organization.public_id,
        "project_id" => session.project.public_id,
        "snapshot_sha256" => "sha256:#{"b" * 64}",
        "manifest_sha256" => "sha256:#{"c" * 64}",
        "archive_sha256" => session.expected_archive_sha256,
        "manifest_ref" => "s3://source/snapshots/b/manifest.json",
        "archive_ref" => "s3://source/snapshots/b/source.tar.gz",
        "size_bytes" => session.expected_archive_bytes,
        "policy_version" => "source-v1",
        "finalized_at" => Time.current.utc.iso8601(6),
        "_key_id" => "source-finalizer-test",
        "parts_seen" => parts.length
      }
    end
  end

  it "persists one immutable snapshot and replays completion without another gateway call" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Finalize", slug: "finalize" }).project
    end
    session = within_organization(account, organization) do
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        state: "uploading",
        expected_archive_bytes: 10,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1,
        expires_at: 15.minutes.from_now,
      )
    end
    gateway = SuccessfulSourceGateway.new
    service = described_class.new(gateway:)
    parts = [ { number: 1, size: 10, sha256: "sha256:#{"d" * 64}" } ]

    first = within_organization(account, organization) do
      service.call(account:, organization:, session:, parts:)
    end
    second = within_organization(account, organization) do
      service.call(account:, organization:, session: session.reload, parts:)
    end

    expect(gateway.calls).to eq(1)
    expect(first.snapshot).to eq(second.snapshot)
    expect(session.reload).to have_attributes(
      state: "complete",
      source_snapshot: first.snapshot,
      signing_key_id: "source-finalizer-test",
    )
    expect(OutboxEvent.where(event_type: "source.snapshot.created").count).to eq(1)
  end

  it "rejects a concurrent finalization without changing its lease state" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Concurrent", slug: "concurrent" }).project
    end
    session = within_organization(account, organization) do
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        state: "finalizing",
        expected_archive_bytes: 1,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1,
        expires_at: 15.minutes.from_now,
      )
    end

    expect do
      within_organization(account, organization) do
        described_class.new(gateway: SuccessfulSourceGateway.new).call(
          account:,
          organization:,
          session:,
          parts: [ { number: 1, size: 1, sha256: "sha256:#{"d" * 64}" } ],
        )
      end
    end.to raise_error(SourceIngestion::InProgress)
    expect(session.reload.state).to eq("finalizing")
  end

  it "rejects duplicate part numbers before calling the gateway" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Parts", slug: "parts" }).project
    end
    session = within_organization(account, organization) do
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        state: "uploading",
        expected_archive_bytes: 2,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 2,
        expires_at: 15.minutes.from_now,
      )
    end
    gateway = SuccessfulSourceGateway.new

    expect do
      within_organization(account, organization) do
        described_class.new(gateway:).call(
          account:,
          organization:,
          session:,
          parts: [
            { number: 1, size: 1, sha256: "sha256:#{"d" * 64}" },
            { number: 1, size: 1, sha256: "sha256:#{"e" * 64}" }
          ],
        )
      end
    end.to raise_error(SourceIngestion::InvalidInput)
    expect(gateway.calls).to eq(0)
    expect(session.reload.state).to eq("uploading")
  end
end
