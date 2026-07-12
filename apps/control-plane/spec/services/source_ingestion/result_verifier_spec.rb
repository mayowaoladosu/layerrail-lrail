require "rails_helper"
require "base64"
require "openssl"

RSpec.describe SourceIngestion::ResultVerifier do
  it "verifies an Ed25519 result scoped to the exact upload session" do
    session = source_session
    signing_key = OpenSSL::PKey.generate_key("ED25519")
    result = finalization_result(session)
    signature = signing_key.sign(nil, CanonicalJson.dump(result))
    payload = {
      key_id: "source-finalizer-test",
      result:,
      signature: Base64.urlsafe_encode64(signature, padding: false)
    }
    verifier = described_class.new(
      keys: {
        "source-finalizer-test" => Base64.urlsafe_encode64(signing_key.public_to_der.last(32), padding: false)
      },
      object_prefix: "s3://source/",
    )

    verified = verifier.verify!(payload, expected_session: session)

    expect(verified).to include(result)
    expect(verified.fetch("_key_id")).to eq("source-finalizer-test")
  end

  it "rejects signature and tenant-scope tampering" do
    session = source_session
    signing_key = OpenSSL::PKey.generate_key("ED25519")
    result = finalization_result(session)
    signature = signing_key.sign(nil, CanonicalJson.dump(result))
    verifier = described_class.new(
      keys: { "key" => Base64.urlsafe_encode64(signing_key.public_to_der.last(32), padding: false) },
      object_prefix: "s3://source/",
    )
    payload = { key_id: "key", result:, signature: Base64.urlsafe_encode64(signature, padding: false) }

    payload[:result] = result.merge("project_id" => "prj_019b01da-7e31-7000-8000-000000000099")
    expect { verifier.verify!(payload, expected_session: session) }.to raise_error(described_class::Invalid)
  end

  def source_session
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Signer", slug: "signer" }).project
    end
    within_organization(account, organization) do
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        expected_archive_bytes: 512,
        expected_archive_sha256: "sha256:#{"a" * 64}",
        expected_parts: 1,
        expires_at: 15.minutes.from_now,
      )
    end
  end

  def finalization_result(session)
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
      "finalized_at" => Time.current.utc.iso8601(6)
    }
  end
end
