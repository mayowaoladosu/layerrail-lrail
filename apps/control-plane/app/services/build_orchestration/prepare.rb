module BuildOrchestration
  class Prepare
    Result = Data.define(:build, :plan)
    DIGEST = /\Asha256:[0-9a-f]{64}\z/

    def self.call(deployment:, generation: 1, deadline: 2.hours.from_now)
      deployment.with_lock do
        raise ActiveRecord::RecordInvalid, deployment unless deployment.source_snapshot
        raise ArgumentError, "deployment generation is invalid" unless generation.to_i.positive?

        snapshot = deployment.source_snapshot
        source_metadata = source_metadata(snapshot)
        build = Build.find_or_initialize_by(deployment:, generation:)
        if build.new_record?
          build.assign_attributes(
            organization: deployment.organization,
            source_snapshot: snapshot,
            state: "accepted",
            network_profile: "packages",
          )
          build.save!
        elsif build.source_snapshot_id != snapshot.id
          raise ActiveRecord::RecordInvalid, build
        end

        plan = {
          version: 1,
          build_id: build.public_id,
          organization_id: deployment.organization.public_id,
          project_id: deployment.project.public_id,
          deployment_id: deployment.public_id,
          operation_id: deployment.operation.public_id,
          generation:,
          source: {
            snapshot_id: snapshot.public_id,
            snapshot_digest: snapshot.digest,
            manifest_digest: source_metadata.fetch(:manifest_digest),
            archive_digest: source_metadata.fetch(:archive_digest),
            archive_ref: source_metadata.fetch(:archive_ref),
            size_bytes: snapshot.size_bytes,
            selected_root: source_metadata.fetch(:selected_root)
          },
          configuration: configuration(deployment),
          target_platform: "linux/amd64",
          deadline: deadline.utc.iso8601(9)
        }
        Result.new(build, plan)
      end
    end

    def self.source_metadata(snapshot)
      if snapshot.kind == "local"
        session = SourceUploadSession.find_by!(source_snapshot: snapshot, state: "complete")
        return {
          manifest_digest: session.manifest_sha256,
          archive_digest: session.archive_sha256,
          archive_ref: session.archive_ref,
          selected_root: session.root_directory.presence || "."
        }
      end
      if snapshot.kind == "git"
        fetch = SourceFetch.where(source_snapshot: snapshot, state: "complete").order(finalized_at: :desc, id: :desc).first!
        return {
          manifest_digest: fetch.manifest_sha256,
          archive_digest: fetch.archive_sha256,
          archive_ref: fetch.archive_ref,
          selected_root: fetch.root_directory.presence || "."
        }
      end

      raise ArgumentError, "source snapshot kind is not deployable"
    end

    def self.configuration(deployment)
      if deployment.build_mode == "repository"
        return { mode: "repository", build_file: deployment.build_file, accept_detected: false }
      end

      { mode: "auto", accept_detected: deployment.accept_detected }
    end

    private_class_method :source_metadata, :configuration
  end
end
