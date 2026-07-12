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
      result = Deployments::Create.call(
        account:,
        organization:,
        project:,
        attributes: {
          environment_id: project.environments.find_by!(slug: "preview").public_id,
          source: { kind: "git", repository: "owner/app", commit: "a" * 40 },
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
