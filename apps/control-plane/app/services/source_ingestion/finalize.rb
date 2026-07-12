module SourceIngestion
  class Finalize
    Result = Data.define(:session, :snapshot)

    def initialize(gateway: SourceIngestion.gateway_client)
      @gateway = gateway
    end

    def call(account:, organization:, session:, parts:)
      Authorization.authorize!(account:, organization:, action: "source.upload.finalize", resource: session)
      raise ActiveRecord::RecordNotFound unless session.organization_id == organization.id
      return Result.new(session, snapshot_for(session)) if session.state == "complete"
      raise InvalidInput, "source upload session cannot be finalized" unless session.state.in?(%w[uploading failed finalizing])
      raise InvalidInput, "source upload session has expired" unless session.expires_at.future?

      session.with_lock do
        return Result.new(session, snapshot_for(session)) if session.state == "complete"
        if session.state == "finalizing" && session.updated_at > 2.minutes.ago
          raise InProgress, "source upload finalization is already running"
        end

        session.update!(
          state: "finalizing",
          finalize_attempts: session.finalize_attempts + 1,
          uploaded_parts: normalize_parts(parts, session:),
          last_error: nil,
        )
      end

      result = @gateway.finalize(session, parts: session.uploaded_parts)
      snapshot = persist_result!(session:, result:, account:)
      Result.new(session.reload, snapshot)
    rescue InvalidInput, InProgress, Authorization::Denied, ActiveRecord::RecordNotFound
      raise
    rescue StandardError => error
      session&.update!(state: "failed", last_error: "#{error.class}: #{error.message}".first(2048)) unless session&.terminal?
      raise
    end

    private

    def persist_result!(session:, result:, account:)
      SourceSnapshot.transaction do
        snapshot = SourceSnapshot.find_or_initialize_by(
          organization_id: session.organization_id,
          project_id: session.project_id,
          digest: result.fetch("snapshot_sha256"),
        )
        snapshot.assign_attributes(
          organization: session.organization,
          project: session.project,
          kind: "local",
          digest: result.fetch("snapshot_sha256"),
          object_ref: result.fetch("archive_ref"),
          size_bytes: result.fetch("size_bytes"),
          retention_until: 30.days.from_now,
        )
        snapshot.save!
        session.update!(
          state: "complete",
          source_snapshot: snapshot,
          snapshot_sha256: result.fetch("snapshot_sha256"),
          manifest_sha256: result.fetch("manifest_sha256"),
          archive_sha256: result.fetch("archive_sha256"),
          manifest_ref: result.fetch("manifest_ref"),
          archive_ref: result.fetch("archive_ref"),
          signing_key_id: result.fetch("_key_id"),
          finalized_at: Time.iso8601(result.fetch("finalized_at")),
          last_error: nil,
        )
        DomainRecorder.record!(
          resource: snapshot,
          event_type: "source.snapshot.created",
          action: "source.snapshot.create",
          actor: account,
          data: {
            project_id: session.project.public_id,
            upload_session_id: session.public_id,
            manifest_sha256: session.manifest_sha256,
            policy_version: result.fetch("policy_version")
          },
        )
        snapshot
      end
    end

    def normalize_parts(parts, session:)
      normalized = Array(parts).map do |part|
        value = part.to_h.stringify_keys.slice("number", "size", "sha256")
        value["number"] = Integer(value.fetch("number"))
        value["size"] = Integer(value.fetch("size"))
        value["sha256"] = value.fetch("sha256").to_s
        value
      end.sort_by { |part| part.fetch("number") }
      expected_numbers = (1..session.expected_parts).to_a
      unless normalized.length == session.expected_parts && normalized.pluck("number") == expected_numbers &&
          normalized.all? { |part| part.fetch("size").between?(1, SourceUploadSession::MAX_PART_BYTES) } &&
          normalized.sum { |part| part.fetch("size") } == session.expected_archive_bytes &&
          normalized.all? { |part| part.fetch("sha256").match?(/\Asha256:[0-9a-f]{64}\z/) }
        raise InvalidInput, "source part metadata does not match the upload session"
      end
      normalized
    rescue KeyError, TypeError, ArgumentError
      raise InvalidInput, "source part metadata is invalid"
    end

    def snapshot_for(session)
      session.source_snapshot || raise(ActiveRecord::RecordNotFound)
    end
  end
end
