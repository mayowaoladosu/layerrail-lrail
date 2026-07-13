require "rails_helper"

RSpec.describe "internal deployment build callbacks", type: :request do
  INTERNAL_DIGEST = ->(character) { "sha256:#{character * 64}" }

  def worker_certificate(uri: "spiffe://lrail.internal/control-worker")
    key = OpenSSL::PKey::EC.generate("prime256v1")
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = OpenSSL::X509::Name.parse("/CN=lrail-control-worker")
    certificate.issuer = certificate.subject
    certificate.public_key = key
    certificate.not_before = 1.minute.ago
    certificate.not_after = 1.hour.from_now
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = certificate
    factory.issuer_certificate = certificate
    certificate.add_extension(factory.create_extension("basicConstraints", "CA:FALSE", true))
    certificate.add_extension(factory.create_extension("keyUsage", "digitalSignature", true))
    certificate.add_extension(factory.create_extension("extendedKeyUsage", "clientAuth", false))
    certificate.add_extension(factory.create_extension("subjectAltName", "URI:#{uri}", false))
    certificate.sign(key, OpenSSL::Digest::SHA256.new)
    certificate
  end

  def deployment_fixture(email: "owner@example.test", organization_slug: "test-workspace")
    account = create_account(email:)
    organization = create_organization(account:, slug: organization_slug)
    values = within_organization(account, organization) do
      project = Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Internal App", slug: "internal-app" },
      ).project
      snapshot = SourceSnapshot.create!(
        organization:,
        project:,
        kind: "local",
        digest: INTERNAL_DIGEST.call("a"),
        object_ref: "s3://lrail-source/internal.tar.gz",
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
        expected_archive_sha256: INTERNAL_DIGEST.call("c"),
        expected_parts: 1,
        snapshot_sha256: snapshot.digest,
        manifest_sha256: INTERNAL_DIGEST.call("b"),
        archive_sha256: INTERNAL_DIGEST.call("c"),
        manifest_ref: "s3://lrail-source/internal.json",
        archive_ref: snapshot.object_ref,
        signing_key_id: "source-test-v1",
        expires_at: 15.minutes.from_now,
        finalized_at: Time.current,
      )
      deployment = Deployments::Create.call(
        account:,
        organization:,
        project:,
        attributes: {
          environment_id: project.environments.find_by!(slug: "preview").public_id,
          source: { kind: "local", source_snapshot_id: snapshot.public_id },
          build_mode: "auto",
          accept_detected: true,
          manifest_revision: 1,
          reason: "Internal callback test"
        },
      ).deployment
      [ project, deployment ]
    end
    [ account, organization, *values ]
  end

  def context_body(account:, organization:, deployment:)
    {
      actor_id: account.public_id,
      organization_id: organization.public_id,
      operation_id: deployment.operation.public_id,
      workflow_id: deployment.operation.workflow_id,
      generation: 1
    }
  end

  def post_internal(path, body, certificate: worker_certificate)
    post path,
      params: body.to_json,
      headers: { "Content-Type" => "application/json" },
      env: { "puma.peercert" => certificate }
  end

  it "prepares one plan and persists an idempotent ordered event batch" do
    account, organization, _project, deployment = deployment_fixture
    context = context_body(account:, organization:, deployment:)

    post_internal "/internal/v1/deployments/#{deployment.public_id}/builds:prepare", context
    expect(response).to have_http_status(:ok)
    prepared = response.parsed_body
    expect(prepared.fetch("build_id")).to match(/\Abld_/)
    expect(prepared.dig("plan", "configuration")).to eq("mode" => "auto", "accept_detected" => true)

    event = {
      version: 1,
      build_id: prepared.fetch("build_id"),
      generation: 1,
      sequence: 1,
      attempt: 1,
      stage: "detecting",
      kind: "progress",
      message: "Detecting source",
      occurred_at: Time.current.iso8601(9)
    }
    body = context.merge(build_id: prepared.fetch("build_id"), events: [ event ])
    post_internal "/internal/v1/deployments/#{deployment.public_id}/build-events", body
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("persisted_through")).to eq(1)

    post_internal "/internal/v1/deployments/#{deployment.public_id}/build-events", body
    expect(response).to have_http_status(:ok)
    within_organization(account, organization) do
      expect(deployment.operation.operation_events.count).to eq(1)
      expect(WorkflowRun.find_by!(workflow_id: deployment.operation.workflow_id).state).to eq("running")
    end
  end

  it "hides every route without the exact worker URI certificate" do
    account, organization, _project, deployment = deployment_fixture
    path = "/internal/v1/deployments/#{deployment.public_id}/builds:prepare"
    body = context_body(account:, organization:, deployment:)

    post path, params: body.to_json, headers: { "Content-Type" => "application/json" }
    expect(response).to have_http_status(:not_found)

    post_internal path, body, certificate: worker_certificate(uri: "spiffe://lrail.internal/foreign")
    expect(response).to have_http_status(:not_found)
  end

  it "finalizes a terminal build result and its workflow through the internal callback" do
    account, organization, _project, deployment = deployment_fixture
    context = context_body(account:, organization:, deployment:)
    prepare_path = "/internal/v1/deployments/#{deployment.public_id}/builds:prepare"
    post_internal prepare_path, context
    prepared = response.parsed_body
    build_id = prepared.fetch("build_id")
    result = {
      version: 1,
      build_id:,
      generation: 1,
      state: "failed",
      source_snapshot_id: deployment.source_snapshot.public_id,
      source_digest: deployment.source_snapshot.digest,
      outputs: [],
      services: [],
      failure_code: "solve_command_exit",
      failure_message: "Build command exited unsuccessfully",
      started_at: Time.current.iso8601(9),
      finished_at: 1.second.from_now.iso8601(9),
      cleanup: { status: "clean", residue_count: 0 },
      cache_hits: 0,
      cache_misses: 0
    }

    post_internal "/internal/v1/deployments/#{deployment.public_id}/build-result",
      context.merge(build_id:, result:)

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("build_state")).to eq("failed")
    within_organization(account, organization) do
      expect(deployment.reload.state).to eq("failed")
      expect(deployment.operation.reload.state).to eq("failed")
      expect(WorkflowRun.find_by!(workflow_id: deployment.operation.workflow_id).state).to eq("failed")
    end
  end

  it "denies a foreign deployment even with a valid worker identity" do
    account, organization, _project, _deployment = deployment_fixture
    _foreign_account, _foreign_organization, _foreign_project, foreign_deployment = deployment_fixture(
      email: "foreign-internal@example.test",
      organization_slug: "foreign-internal",
    )
    body = context_body(account:, organization:, deployment: foreign_deployment)
    body[:operation_id] = foreign_deployment.operation.public_id
    body[:workflow_id] = foreign_deployment.operation.workflow_id

    post_internal "/internal/v1/deployments/#{foreign_deployment.public_id}/builds:prepare", body
    expect(response).to have_http_status(:not_found)
  end

  it "rejects callbacks outside the deployment's exact workflow generation" do
    account, organization, _project, deployment = deployment_fixture
    path = "/internal/v1/deployments/#{deployment.public_id}/builds:prepare"
    context = context_body(account:, organization:, deployment:)

    post_internal path, context.merge(workflow_id: "deployment/#{deployment.public_id}/build/2", generation: 2)
    expect(response).to have_http_status(:not_found)

    post_internal path, context.merge(generation: 2)
    expect(response).to have_http_status(:not_found)

    within_organization(account, organization) do
      expect(deployment.builds).to be_empty
      expect(WorkflowRun.where(resource_public_id: deployment.public_id)).to be_empty
    end
  end
end
