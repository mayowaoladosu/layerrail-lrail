require "rails_helper"

RSpec.describe "source uploads API", type: :request do
  class RequestSourceGateway
    def create_session(session)
      {
        "session_id" => session.public_id,
        "parts" => session.expected_parts.times.map do |index|
          {
            "number" => index + 1,
            "url" => "https://objects.example.test/#{session.public_id}/#{index + 1}",
            "expires_at" => session.expires_at.iso8601(6)
          }
        end
      }
    end

    def finalize(session, parts:)
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
        "part_count" => parts.length
      }
    end
  end

  it "authorizes a bounded direct upload and replays the idempotent response" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Upload", slug: "upload" }).project
    end
    allow(SourceIngestion).to receive(:gateway_client).and_return(RequestSourceGateway.new)
    login(account)
    headers = {
      "X-Lrail-Organization" => organization.public_id,
      "Idempotency-Key" => "source-upload-request-1",
      "Content-Type" => "application/json"
    }
    body = {
      source_upload: {
        expected_archive_bytes: 20,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 2,
        root_directory: "app",
        excluded_count: 3
      }
    }

    post "/v1/projects/#{project.public_id}/source_uploads", params: JSON.generate(body), headers: headers
    expect(response).to have_http_status(:created)
    first = response.parsed_body
    expect(first.dig("data", "id")).to start_with("upl_")
    expect(first.fetch("parts").length).to eq(2)

    post "/v1/projects/#{project.public_id}/source_uploads", params: JSON.generate(body), headers: headers
    expect(response).to have_http_status(:created)
    expect(response.headers["Idempotency-Replayed"]).to eq("true")
    expect(response.parsed_body).to eq(first)
    expect(SourceUploadSession.count).to eq(1)
  end

  it "does not reveal another organization's project" do
    account = create_account
    organization = create_organization(account:)
    foreign = create_account(email: "source-foreign@example.test")
    foreign_organization = create_organization(account: foreign, slug: "source-foreign")
    foreign_project = within_organization(foreign, foreign_organization) do
      Projects::Create.call(account: foreign, organization: foreign_organization, attributes: { name: "Hidden", slug: "hidden" }).project
    end
    allow(SourceIngestion).to receive(:gateway_client).and_return(RequestSourceGateway.new)
    login(account)

    post "/v1/projects/#{foreign_project.public_id}/source_uploads",
      params: JSON.generate(source_upload: {
        expected_archive_bytes: 1,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1
      }),
      headers: {
        "X-Lrail-Organization" => organization.public_id,
        "Idempotency-Key" => "source-foreign-request",
        "Content-Type" => "application/json"
      }

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body.dig("error", "code")).to eq("not_found")
  end

  it "rejects an archive larger than its declared part capacity" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Bounded", slug: "bounded" }).project
    end
    allow(SourceIngestion).to receive(:gateway_client).and_return(RequestSourceGateway.new)
    login(account)

    post "/v1/projects/#{project.public_id}/source_uploads",
      params: JSON.generate(source_upload: {
        expected_archive_bytes: SourceUploadSession::MAX_PART_BYTES + 1,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1
      }),
      headers: {
        "X-Lrail-Organization" => organization.public_id,
        "Idempotency-Key" => "source-capacity-request",
        "Content-Type" => "application/json"
      }

    expect(response).to have_http_status(:unprocessable_content)
    expect(response.parsed_body.dig("error", "code")).to eq("validation_failed")
    expect(SourceUploadSession.count).to eq(0)
  end

  it "finalizes an upload into an immutable snapshot" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Snapshot", slug: "snapshot" }).project
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
    allow(SourceIngestion).to receive(:gateway_client).and_return(RequestSourceGateway.new)
    login(account)
    body = { source_upload: { parts: [ { number: 1, size: 10, sha256: "sha256:#{"d" * 64}" } ] } }

    post "/v1/source_uploads/#{session.public_id}/finalize",
      params: JSON.generate(body),
      headers: {
        "X-Lrail-Organization" => organization.public_id,
        "Idempotency-Key" => "source-finalize-request-1",
        "Content-Type" => "application/json"
      }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.dig("data", "state")).to eq("complete")
    expect(response.parsed_body.dig("snapshot", "id")).to start_with("snp_")
    expect(session.reload.source_snapshot).to be_present
  end
end
