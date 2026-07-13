require "rails_helper"

RSpec.describe "deployments API", type: :request do
  REQUEST_DIGEST = ->(character) { "sha256:#{character * 64}" }

  def source_fixture(account:, organization:, project:)
    snapshot = within_organization(account, organization) do
      value = SourceSnapshot.create!(
        organization:,
        project:,
        kind: "local",
        digest: REQUEST_DIGEST.call("a"),
        object_ref: "s3://lrail-source/request.tar.gz",
        size_bytes: 1_024,
        retention_until: 30.days.from_now,
      )
      SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        source_snapshot: value,
        state: "complete",
        expected_archive_bytes: 1_024,
        expected_archive_sha256: REQUEST_DIGEST.call("c"),
        expected_parts: 1,
        snapshot_sha256: value.digest,
        manifest_sha256: REQUEST_DIGEST.call("b"),
        archive_sha256: REQUEST_DIGEST.call("c"),
        manifest_ref: "s3://lrail-source/request.json",
        archive_ref: value.object_ref,
        signing_key_id: "source-test-v1",
        expires_at: 15.minutes.from_now,
        finalized_at: Time.current,
      )
      value
    end
    snapshot
  end

  it "accepts explicit detector intent and preserves a cancellation reason" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "CLI API", slug: "cli-api" },
      ).project
    end
    snapshot = source_fixture(account:, organization:, project:)
    login(account)
    headers = {
      "X-Lrail-Organization" => organization.public_id,
      "Idempotency-Key" => "cli-api-deploy-0001",
      "Content-Type" => "application/json"
    }
    body = {
      environment_id: project.environments.find_by!(slug: "preview").public_id,
      source: { kind: "local", source_snapshot_id: snapshot.public_id },
      build_mode: "auto",
      accept_detected: true,
      manifest_revision: 1,
      reason: "cli_local_deploy"
    }

    post "/v1/projects/#{project.public_id}/deployments", params: body.to_json, headers: headers
    expect(response).to have_http_status(:accepted)
    deployment_id = response.parsed_body.dig("data", "id")
    expect(response.parsed_body.dig("data", "accept_detected")).to be(true)
    expect(response.parsed_body.dig("data", "source_snapshot_id")).to eq(snapshot.public_id)

    delete "/v1/deployments/#{deployment_id}",
      params: { reason: "operator requested through CLI" }.to_json,
      headers: headers.merge("Idempotency-Key" => "cli-api-cancel-0001")

    expect(response).to have_http_status(:accepted)
    within_organization(account, organization) do
      deployment = Deployment.find_by!(public_id: deployment_id)
      expect(deployment.state).to eq("canceling")
      transition = deployment.deployment_transitions.order(:id).last
      expect(transition.reason).to eq("operator requested through CLI")
      event = OutboxEvent.where(resource_public_id: deployment_id, event_type: "deployment.canceling").last
      expect(event.data).to include(
        "reason" => "operator requested through CLI",
        "workflow_id" => deployment.operation.workflow_id,
      )
    end
  end
end
