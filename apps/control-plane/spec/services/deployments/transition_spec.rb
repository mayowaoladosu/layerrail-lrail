require "rails_helper"

RSpec.describe Deployments::Transition do
  def deployment_fixture
    account = create_account
    organization = create_organization(account:)
    within_organization(account, organization) do
      project = Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "App", slug: "app" },
      ).project
      snapshot = SourceSnapshot.create!(
        organization:,
        project:,
        kind: "local",
        digest: "sha256:#{"a" * 64}",
        object_ref: "s3://lrail-source/transition/source.tar.gz",
        size_bytes: 1_024,
        retention_until: 30.days.from_now,
      )
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        source_snapshot: snapshot,
        state: "complete",
        expected_archive_bytes: 1_024,
        expected_archive_sha256: "sha256:#{"c" * 64}",
        expected_parts: 1,
        snapshot_sha256: snapshot.digest,
        manifest_sha256: "sha256:#{"b" * 64}",
        archive_sha256: "sha256:#{"c" * 64}",
        manifest_ref: "s3://lrail-source/transition/manifest.json",
        archive_ref: snapshot.object_ref,
        signing_key_id: "source-test-v1",
        expires_at: 15.minutes.from_now,
        finalized_at: Time.current,
      )
      result = Deployments::Create.call(
        account:,
        organization:,
        project:,
        attributes: {
          environment_id: project.environments.find_by!(slug: "preview").public_id,
          source: { kind: "local", source_snapshot_id: snapshot.public_id },
          manifest_revision: 1,
          reason: "Test deployment"
        },
      )
      [ account, organization, result.deployment ]
    end
  end

  it "accepts legal transitions and appends evidence" do
    account, organization, deployment = deployment_fixture
    within_organization(account, organization) do
      Current.request_id = "req_#{"b" * 32}"
      described_class.call(deployment:, to: "sourcing", reason: "source accepted")
      expect(deployment.reload.state).to eq("sourcing")
      expect(deployment.deployment_transitions.pluck(:to_state)).to eq(%w[created sourcing])
      expect(OutboxEvent.where(event_type: "deployment.sourcing")).to exist
    end
  end

  it "rejects illegal state jumps" do
    account, organization, deployment = deployment_fixture
    expect do
      within_organization(account, organization) do
        described_class.call(deployment:, to: "promoted", reason: "skip guards")
      end
    end.to raise_error(Deployments::Transition::InvalidTransition)
  end

  it "makes persisted transition rows immutable" do
    account, organization, deployment = deployment_fixture
    within_organization(account, organization) do
      transition = deployment.deployment_transitions.first
      expect { transition.update!(reason: "rewrite") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    end
  end
end
