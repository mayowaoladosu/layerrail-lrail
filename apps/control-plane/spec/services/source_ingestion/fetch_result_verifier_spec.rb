require "rails_helper"

RSpec.describe SourceIngestion::FetchResultVerifier do
  it "verifies the shared Go-signed exact-commit receipt fixture" do
    fixture = JSON.parse(
      Rails.root.join("../..", "contracts", "fixtures", "source-fetch-result.valid.json").read,
    )
    result = fixture.fetch("result")
    resource = Struct.new(:public_id, keyword_init: true)
    connection = Struct.new(:public_id, :provider, keyword_init: true)
    fetch_type = Struct.new(
      :public_id, :organization, :project, :source_connection, :repository,
      :requested_commit_sha, :created_at,
      keyword_init: true,
    )
    fetch = fetch_type.new(
      public_id: result.fetch("fetch_id"),
      organization: resource.new(public_id: result.fetch("organization_id")),
      project: resource.new(public_id: result.fetch("project_id")),
      source_connection: connection.new(
        public_id: result.fetch("source_connection_id"),
        provider: result.fetch("provider"),
      ),
      repository: result.fetch("repository"),
      requested_commit_sha: result.fetch("requested_commit_sha"),
      created_at: Time.iso8601("2026-07-13T00:59:00Z"),
    )
    clock = Struct.new(:current).new(Time.iso8601("2026-07-13T01:00:30Z"))
    verifier = described_class.new(
      keys: { fixture.fetch("key_id") => fixture.fetch("public_key_base64url") },
      object_prefix: "s3://lrail-source/",
      clock:,
    )
    payload = fixture.slice("key_id", "result", "signature")

    verified = verifier.verify!(payload, expected_fetch: fetch)

    expect(verified).to include(result)
    expect(verified.fetch("_key_id")).to eq("source-finalizer-fixture-v1")
    tampered = payload.deep_dup
    tampered["result"]["resolved_commit_sha"] = "f" * 40
    expect { verifier.verify!(tampered, expected_fetch: fetch) }.to raise_error(described_class::Invalid)
  end
end
