require "rails_helper"

RSpec.describe "deployment build orchestration persistence" do
  DIGEST = ->(character) { "sha256:#{character * 64}" }

  def local_deployment_fixture(accept_detected: true)
    account = create_account
    organization = create_organization(account:)
    values = nil
    within_organization(account, organization) do
      project = Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Build App", slug: "build-app" },
      ).project
      snapshot = SourceSnapshot.create!(
        organization:,
        project:,
        kind: "local",
        digest: DIGEST.call("a"),
        object_ref: "s3://lrail-source/snapshots/source.tar.gz",
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
        expected_archive_sha256: DIGEST.call("c"),
        expected_parts: 1,
        root_directory: "",
        snapshot_sha256: snapshot.digest,
        manifest_sha256: DIGEST.call("b"),
        archive_sha256: DIGEST.call("c"),
        manifest_ref: "s3://lrail-source/manifests/source.json",
        archive_ref: snapshot.object_ref,
        signing_key_id: "source-test-v1",
        expires_at: 15.minutes.from_now,
        finalized_at: Time.current,
      )
      created = Deployments::Create.call(
        account:,
        organization:,
        project:,
        attributes: {
          environment_id: project.environments.find_by!(slug: "preview").public_id,
          source: { kind: "local", source_snapshot_id: snapshot.public_id },
          build_mode: "auto",
          accept_detected:,
          manifest_revision: 1,
          reason: "Build orchestration test"
        },
      )
      values = [ account, organization, project, snapshot, created.deployment ]
    end
    values
  end

  def complete_result(build:, snapshot:)
    manifest_digest = DIGEST.call("d")
    repository = "registry.example.test/lrail/api"
    evidence = Attestation::KINDS.each_with_index.map do |kind, index|
      digest = "sha256:#{format("%064x", index + 1)}"
      {
        kind:,
        reference: "#{repository}@#{digest}",
        manifest_digest: digest,
        payload_digest: "sha256:#{format("%064x", index + 11)}"
      }
    end
    {
      version: 1,
      build_id: build.public_id,
      generation: build.generation,
      state: "complete",
      source_snapshot_id: snapshot.public_id,
      source_digest: snapshot.digest,
      detection_digest: DIGEST.call("1"),
      manifest_digest: DIGEST.call("2"),
      build_ir_digest: DIGEST.call("3"),
      definition_digest: DIGEST.call("4"),
      assignment_digest: DIGEST.call("5"),
      logs_digest: DIGEST.call("6"),
      detector_result_ref: "s3://lrail-build/detector.json",
      manifest_ref: "s3://lrail-build/manifest.json",
      generated_build_ref: "s3://lrail-build/Lrailfile.star",
      build_ir_ref: "s3://lrail-build/build-ir.json",
      definition_lock_ref: "s3://lrail-build/definition-lock.json",
      outputs: [
        {
          name: "api",
          kind: "oci_image",
          artifact_ref: "#{repository}@#{manifest_digest}",
          artifact_digest: DIGEST.call("e"),
          artifact_size: 4_096,
          config_digest: DIGEST.call("7"),
          manifest_digest:,
          layer_digests: [ DIGEST.call("f") ],
          supply_chain: {
            policy_state: "accepted",
            scan_state: "passed",
            policy_digest: DIGEST.call("8"),
            signer_key_id: "lrail-build-evidence",
            signer_key_version: 1,
            signer_public_key_digest: DIGEST.call("9"),
            evidence:
          }
        }
      ],
      services: [
        {
          name: "api",
          root: ".",
          kind: "web",
          language: "go",
          framework: "Go net/http",
          runtime_version: "1.26",
          build: {
            strategy: "auto",
            install_command: [ "go", "mod", "download" ],
            build_command: [ "go", "build", "-o", "out/api", "." ],
            cache_paths: [ ".cache/go-build" ]
          },
          processes: [
            { name: "web", kind: "web", command: [ "/workspace/out/api" ], port: 8080, protocol: "http", health_path: "/healthz" }
          ]
        }
      ],
      started_at: Time.current.iso8601(9),
      finished_at: 1.minute.from_now.iso8601(9),
      worker_identity: "spiffe://lrail.internal/build-worker/test",
      cleanup: { status: "clean", residue_count: 0 },
      cache_hits: 1,
      cache_misses: 1
    }
  end

  it "binds a finalized local snapshot and prepares one immutable generation" do
    account, organization, project, snapshot, deployment = local_deployment_fixture
    within_organization(account, organization) do
      expect(deployment.source_snapshot).to eq(snapshot)
      prepared = BuildOrchestration::Prepare.call(deployment:)
      expect(prepared.build).to have_attributes(
        deployment:,
        source_snapshot: snapshot,
        generation: 1,
        state: "accepted",
      )
      expect(prepared.plan).to include(
        build_id: prepared.build.public_id,
        organization_id: organization.public_id,
        project_id: project.public_id,
        deployment_id: deployment.public_id,
        operation_id: deployment.operation.public_id,
        generation: 1,
      )
      expect(prepared.plan.dig(:source, :manifest_digest)).to eq(DIGEST.call("b"))
      expect(prepared.plan.dig(:source, :archive_digest)).to eq(DIGEST.call("c"))
      expect(prepared.plan.fetch(:configuration)).to eq(mode: "auto", accept_detected: true)
      expect(BuildOrchestration::Prepare.call(deployment:).build).to eq(prepared.build)
    end
  end

  it "persists only contiguous idempotent events and advances product state" do
    account, organization, _project, _snapshot, deployment = local_deployment_fixture
    within_organization(account, organization) do
      build = BuildOrchestration::Prepare.call(deployment:).build
      event = {
        build_id: build.public_id,
        generation: 1,
        sequence: 1,
        attempt: 1,
        stage: "detecting",
        kind: "progress",
        message: "Detecting service configuration",
        occurred_at: Time.current.iso8601(9)
      }
      persisted = BuildOrchestration::PersistEvent.call(deployment:, build:, event:)
      expect(persisted.sequence).to eq(1)
      expect(deployment.reload.state).to eq("detecting")
      expect(deployment.operation.reload).to have_attributes(state: "running", stage: "detecting")
      expect { BuildOrchestration::PersistEvent.call(deployment:, build:, event:) }
        .not_to change(OperationEvent, :count)
      expect do
        BuildOrchestration::PersistEvent.call(
          deployment:,
          build:,
          event: event.merge(sequence: 3, stage: "building"),
        )
      end.to raise_error(ArgumentError, /contract is invalid/)
    end
  end

  it "atomically persists revisions and all evidence then stops at artifact_ready" do
    account, organization, _project, snapshot, deployment = local_deployment_fixture
    within_organization(account, organization) do
      build = BuildOrchestration::Prepare.call(deployment:).build
      result = complete_result(build:, snapshot:)
      expect { BuildOrchestration::Finalize.call(deployment:, build:, result:) }
        .to change(Revision, :count).by(1)
        .and change(Attestation, :count).by(5)
      expect(build.reload).to have_attributes(
        state: "complete",
        definition_digest: DIGEST.call("4"),
        logs_digest: DIGEST.call("6"),
        cleanup_state: "clean",
      )
      expect(deployment.reload).to have_attributes(state: "artifact_ready")
      expect(deployment.operation.reload).to have_attributes(state: "succeeded", stage: "artifact_ready")
      expect(deployment.artifact_ready_at).to be_present
      expect(deployment.revision.attestations.order(:kind).pluck(:kind)).to eq(Attestation::KINDS.sort)
      expect { BuildOrchestration::Finalize.call(deployment:, build:, result:) }
        .not_to change(Attestation, :count)
      expect(Release.where(deployment:)).to be_empty
    end
  end

  it "rejects incomplete evidence without partial product truth" do
    account, organization, _project, snapshot, deployment = local_deployment_fixture
    within_organization(account, organization) do
      build = BuildOrchestration::Prepare.call(deployment:).build
      result = complete_result(build:, snapshot:)
      result.dig(:outputs, 0, :supply_chain, :evidence).pop
      expect do
        BuildOrchestration::Finalize.call(deployment:, build:, result:)
      end.to raise_error(ArgumentError, /evidence/)
      expect(build.reload.state).to eq("accepted")
      expect(Revision.where(build:)).to be_empty
      expect(deployment.reload.state).to eq("created")
    end
  end

  it "denies a foreign organization snapshot during deployment creation" do
    account, organization, project, _snapshot, _deployment = local_deployment_fixture
    foreign_account = create_account(email: "foreign@example.test")
    foreign_organization = create_organization(account: foreign_account, slug: "foreign")
    foreign_snapshot = within_organization(foreign_account, foreign_organization) do
      foreign_project = Projects::Create.call(
        account: foreign_account,
        organization: foreign_organization,
        attributes: { name: "Foreign", slug: "foreign" },
      ).project
      SourceSnapshot.create!(
        organization: foreign_organization,
        project: foreign_project,
        kind: "local",
        digest: DIGEST.call("f"),
        object_ref: "s3://foreign/source.tar.gz",
        size_bytes: 100,
        retention_until: 30.days.from_now,
      )
    end

    within_organization(account, organization) do
      expect do
        Deployments::Create.call(
          account:,
          organization:,
          project:,
          attributes: {
            environment_id: project.environments.first.public_id,
            source: { kind: "local", source_snapshot_id: foreign_snapshot.public_id },
            manifest_revision: 1,
            reason: "Foreign snapshot substitution"
          },
        )
      end.to raise_error(ActiveRecord::RecordNotFound)
    end
  end
end
