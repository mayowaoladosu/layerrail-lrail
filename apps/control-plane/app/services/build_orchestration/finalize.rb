module BuildOrchestration
  class Finalize
    EVIDENCE_KINDS = Attestation::KINDS.freeze

    def self.call(deployment:, build:, result:)
      values = result.to_h.deep_stringify_keys
      validate_identity!(deployment:, build:, values:)

      Build.transaction do
        build.lock!
        deployment.lock!
        return build if build.state.in?(%w[complete failed canceled waiting])

        case values.fetch("state")
        when "complete"
          finalize_complete!(deployment:, build:, values:)
        when "waiting"
          finalize_noncomplete!(deployment:, build:, values:, state: "waiting", operation_state: "waiting")
        when "canceled"
          finalize_noncomplete!(deployment:, build:, values:, state: "canceled", operation_state: "canceled")
          Deployments::Transition.call(deployment:, to: "canceled", reason: values.fetch("failure_code"), actor: nil) if deployment.state == "canceling"
        when "failed"
          finalize_noncomplete!(deployment:, build:, values:, state: "failed", operation_state: "failed")
          transition_failed!(deployment, values.fetch("failure_code"))
        else
          raise ArgumentError, "build result state is invalid"
        end
        build
      end
    end

    def self.finalize_complete!(deployment:, build:, values:)
      outputs = Array(values.fetch("outputs"))
      services = Array(values.fetch("services")).index_by { |service| service.fetch("name") }
      raise ArgumentError, "build output set is incomplete" unless
        outputs.length.positive? && outputs.length == services.length &&
        values.dig("cleanup", "status") == "clean" && values.fetch("logs_digest").present?

      revisions = outputs.sort_by { |output| output.fetch("name") }.map do |output|
        service_result = services.fetch(output.fetch("name"))
        service = persist_service!(deployment:, service_result:)
        revision = Revision.find_or_initialize_by(build:, service:)
        evidence = evidence_by_kind(output)
        revision.assign_attributes(
          organization: deployment.organization,
          image_digest: output.fetch("artifact_digest"),
          manifest_digest: output.fetch("manifest_digest"),
          sbom_ref: evidence.fetch("sbom").fetch("reference"),
          provenance_ref: evidence.fetch("provenance").fetch("reference"),
          signature_ref: evidence.fetch("signature").fetch("reference"),
          scan_state: output.dig("supply_chain", "scan_state"),
          policy_state: output.dig("supply_chain", "policy_state"),
        )
        revision.save!
        persist_attestations!(deployment:, revision:, output:, evidence:)
        revision
      end

      build.update!(
        state: "complete",
        definition_digest: values.fetch("definition_digest"),
        artifact_digest: outputs.first.fetch("artifact_digest"),
        detection_digest: values.fetch("detection_digest"),
        detection_ref: values.fetch("detector_result_ref"),
        manifest_digest: values.fetch("manifest_digest"),
        manifest_ref: values.fetch("manifest_ref"),
        build_ir_digest: values.fetch("build_ir_digest"),
        build_ir_ref: values.fetch("build_ir_ref"),
        definition_lock_ref: values.fetch("definition_lock_ref"),
        assignment_digest: values.fetch("assignment_digest"),
        logs_digest: values.fetch("logs_digest"),
        worker_identity: values.fetch("worker_identity"),
        cleanup_state: values.dig("cleanup", "status"),
        completed_at: Time.iso8601(values.fetch("finished_at")),
        error_code: nil,
        error_message: nil,
      )
      deployment.update!(revision: revisions.one? ? revisions.first : nil)
      advance_to_artifact_ready!(deployment)
      deployment.operation.update!(
        state: "succeeded",
        stage: "artifact_ready",
        completed_steps: deployment.operation.total_steps,
        waiting_reason: nil,
        error_code: nil,
        error_message: nil,
      )
      DomainRecorder.record!(
        resource: deployment,
        event_type: "build.completed",
        action: "deployment.build.complete",
        actor: nil,
        data: {
          build_id: build.public_id,
          revision_ids: revisions.map(&:public_id),
          artifact_digests: outputs.map { |output| output.fetch("artifact_digest") }
        }
      )
    end

    def self.persist_service!(deployment:, service_result:)
      service = deployment.project.services.find_or_initialize_by(slug: service_result.fetch("name"))
      service.assign_attributes(
        organization: deployment.organization,
        name: service_result.fetch("name").tr("-", " ").titleize,
        kind: service_result.fetch("kind"),
        framework: service_result.fetch("framework"),
        build_specification: service_result.fetch("build"),
        runtime_specification: {
          language: service_result.fetch("language"),
          version: service_result["runtime_version"],
          root: service_result.fetch("root"),
          processes: service_result.fetch("processes")
        }.compact,
        health: "unknown",
      )
      service.save!
      service
    end

    def self.evidence_by_kind(output)
      chain = output.fetch("supply_chain")
      evidence = Array(chain.fetch("evidence")).index_by { |item| item.fetch("kind") }
      subject = output.fetch("manifest_digest")
      repository = output.fetch("artifact_ref").split("@", 2).first
      valid = chain.fetch("policy_state") == "accepted" && chain.fetch("scan_state") == "passed" &&
        chain.fetch("policy_digest").present? && chain.fetch("signer_key_id").present? &&
        Integer(chain.fetch("signer_key_version")).positive? && chain.fetch("signer_public_key_digest").present? &&
        evidence.keys.sort == EVIDENCE_KINDS.sort &&
        evidence.values.all? do |item|
          item.fetch("reference") == "#{repository}@#{item.fetch("manifest_digest")}" &&
            item.fetch("manifest_digest").match?(Attestation::DIGEST) &&
            item.fetch("payload_digest").match?(Attestation::DIGEST)
        end && subject.match?(Attestation::DIGEST)
      raise ArgumentError, "build evidence set is incomplete" unless valid

      evidence
    rescue KeyError, TypeError, ArgumentError
      raise ArgumentError, "build evidence set is incomplete"
    end

    def self.persist_attestations!(deployment:, revision:, output:, evidence:)
      chain = output.fetch("supply_chain")
      evidence.each do |kind, reference|
        attestation = Attestation.find_or_initialize_by(revision:, kind:)
        attestation.assign_attributes(
          organization: deployment.organization,
          digest: reference.fetch("manifest_digest"),
          payload_digest: reference.fetch("payload_digest"),
          subject_digest: output.fetch("manifest_digest"),
          object_ref: reference.fetch("reference"),
          signer_key_id: chain.fetch("signer_key_id"),
          signer_key_version: chain.fetch("signer_key_version"),
          signer_public_key_digest: chain.fetch("signer_public_key_digest"),
          policy_digest: chain.fetch("policy_digest"),
        )
        attestation.save!
      end
    end

    def self.finalize_noncomplete!(deployment:, build:, values:, state:, operation_state:)
      build.update!(
        state:,
        detection_digest: values["detection_digest"].presence,
        detection_ref: values["detector_result_ref"].presence,
        manifest_digest: values["manifest_digest"].presence,
        manifest_ref: values["manifest_ref"].presence,
        build_ir_digest: values["build_ir_digest"].presence,
        build_ir_ref: values["build_ir_ref"].presence,
        definition_digest: values["definition_digest"].presence,
        definition_lock_ref: values["definition_lock_ref"].presence,
        assignment_digest: values["assignment_digest"].presence,
        logs_digest: values["logs_digest"].presence,
        cleanup_state: values.dig("cleanup", "status"),
        error_code: values.fetch("failure_code"),
        error_message: values.fetch("failure_message"),
        completed_at: Time.iso8601(values.fetch("finished_at")),
      )
      deployment.operation.update!(
        state: operation_state,
        stage: values.fetch("state"),
        waiting_reason: state == "waiting" ? values.fetch("failure_message") : nil,
        error_code: values.fetch("failure_code"),
        error_message: values.fetch("failure_message"),
      )
    end

    def self.advance_to_artifact_ready!(deployment)
      %w[sourcing detecting queued building scanning publishing artifact_ready].each do |state|
        next if deployment.state == state && state != "artifact_ready"
        next unless deployment.can_transition_to?(state)

        Deployments::Transition.call(deployment:, to: state, reason: "build_complete", actor: nil)
      end
      raise ArgumentError, "deployment could not reach artifact_ready" unless deployment.state == "artifact_ready"
    end

    def self.transition_failed!(deployment, reason)
      return if deployment.state == "failed"
      Deployments::Transition.call(deployment:, to: "failed", reason:, actor: nil) if deployment.can_transition_to?("failed")
    end

    def self.validate_identity!(deployment:, build:, values:)
      valid = values.fetch("build_id") == build.public_id &&
        Integer(values.fetch("generation")) == build.generation &&
        values.fetch("source_snapshot_id") == build.source_snapshot.public_id &&
        values.fetch("source_digest") == build.source_snapshot.digest &&
        build.deployment_id == deployment.id
      raise ArgumentError, "build result identity mismatch" unless valid
    rescue KeyError, TypeError, ArgumentError
      raise ArgumentError, "build result identity mismatch"
    end

    private_class_method :finalize_complete!, :persist_service!, :evidence_by_kind,
      :persist_attestations!, :finalize_noncomplete!, :advance_to_artifact_ready!,
      :transition_failed!, :validate_identity!
  end
end
