require "rails_helper"
require "base64"

RSpec.describe SourceIngestion::GrantSigner do
  it "creates a bounded HMAC-authenticated grant without leaking the key" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Source", slug: "source" }).project
    end
    session = within_organization(account, organization) do
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        expected_archive_bytes: 1024,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1,
        root_directory: "app",
        excluded_count: 2,
        expires_at: 15.minutes.from_now,
      )
    end
    key = "k" * 32
    token = described_class.new(key: Base64.urlsafe_encode64(key, padding: false)).sign(session)
    version, encoded, signature = token.split(".")
    payload = JSON.parse(Base64.urlsafe_decode64("#{encoded}#{"=" * ((4 - encoded.length % 4) % 4)}"))

    expect(version).to eq("v1")
    expect(payload).to include(
      "audience" => "lrail-source-gateway",
      "session_id" => session.public_id,
      "organization_id" => organization.public_id,
      "project_id" => project.public_id,
      "creator_id" => account.public_id,
      "expected_archive_bytes" => 1024,
    )
    expect(signature).to be_present
    expect(token).not_to include(key)
  end
end
