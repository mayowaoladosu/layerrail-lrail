module SourceIngestion
  class CreateSession
    Result = Data.define(:session, :parts)

    def initialize(gateway: SourceIngestion.gateway_client)
      @gateway = gateway
    end

    def call(account:, organization:, project:, attributes:)
      Authorization.authorize!(account:, organization:, action: "source.upload.create", resource: project)
      expires_at = 15.minutes.from_now
      session = SourceUploadSession.create!(
        organization:,
        project:,
        created_by_account: account,
        state: "authorized",
        expected_archive_bytes: attributes.fetch(:expected_archive_bytes),
        expected_archive_sha256: attributes.fetch(:expected_archive_sha256),
        expected_parts: attributes.fetch(:expected_parts),
        root_directory: attributes.fetch(:root_directory, ""),
        excluded_count: attributes.fetch(:excluded_count, 0),
        expires_at:,
      )
      response = @gateway.create_session(session)
      parts = response.fetch("parts")
      raise GatewayClient::Error, "source gateway returned unexpected part count" unless parts.length == session.expected_parts

      session.update!(state: "uploading")
      DomainRecorder.record!(
        resource: session,
        event_type: "source.upload.authorized",
        action: "source.upload.create",
        data: {
          project_id: project.public_id,
          expected_archive_bytes: session.expected_archive_bytes,
          expected_parts: session.expected_parts,
          expires_at: session.expires_at.iso8601(6)
        },
      )
      Result.new(session, parts)
    rescue StandardError
      session&.update!(state: "failed", last_error: "source gateway authorization failed") unless session&.terminal?
      raise
    end
  end
end
