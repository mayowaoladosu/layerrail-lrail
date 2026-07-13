require "rails_helper"
require "base64"

RSpec.describe SourceIngestion::FetchGrantSigner do
  it "matches the shared Ruby-Go exact-commit grant fixture" do
    fixture = JSON.parse(
      Rails.root.join("../..", "contracts", "fixtures", "source-fetch-grant.valid.json").read,
    )
    grant = fixture.fetch("grant")
    resource = Struct.new(:public_id, keyword_init: true)
    connection = Struct.new(:public_id, :provider, :installation_external_id, keyword_init: true)
    fetch_type = Struct.new(
      :public_id, :organization, :project, :created_by_account, :source_connection,
      :repository, :requested_commit_sha, :root_directory, :expires_at,
      keyword_init: true,
    )
    fetch = fetch_type.new(
      public_id: grant.fetch("fetch_id"),
      organization: resource.new(public_id: grant.fetch("organization_id")),
      project: resource.new(public_id: grant.fetch("project_id")),
      created_by_account: resource.new(public_id: grant.fetch("creator_id")),
      source_connection: connection.new(
        public_id: grant.fetch("source_connection_id"),
        provider: grant.fetch("provider"),
        installation_external_id: grant.fetch("installation_id"),
      ),
      repository: grant.fetch("repository"),
      requested_commit_sha: grant.fetch("commit_sha"),
      root_directory: grant.fetch("root_directory"),
      expires_at: Time.iso8601(grant.fetch("expires_at")),
    )

    token = described_class.new(key: fixture.fetch("key_base64url")).sign(fetch)

    expect(token).to eq(fixture.fetch("token_chunks").join)
  end
end
