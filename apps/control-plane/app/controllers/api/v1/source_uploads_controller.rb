module Api
  module V1
    class SourceUploadsController < BaseController
      rescue_from SourceIngestion::InvalidInput, with: :render_invalid_source_input
      rescue_from SourceIngestion::InProgress, with: :render_source_in_progress
      rescue_from SourceIngestion::GatewayClient::Rejected, with: :render_source_rejection
      rescue_from SourceIngestion::GatewayClient::Error, with: :render_source_unavailable

      def create
        project = current_organization!.projects.find_by_public_id!(params[:project_id])
        payload = create_params.to_h.deep_symbolize_keys
        idempotent(payload: payload.merge(project_id: project.public_id), expires_in: 15.minutes) do
          result = SourceIngestion::CreateSession.new.call(
            account: current_account,
            organization: current_organization!,
            project:,
            attributes: payload,
          )
          [
            201,
            {
              data: serialize_session(result.session),
              parts: result.parts
            }
          ]
        end
      end

      def finalize
        session = current_organization!.source_upload_sessions.find_by_public_id!(params[:id])
        payload = { id: session.public_id, parts: finalize_params.fetch(:parts).map(&:to_h) }
        idempotent(payload:) do
          result = SourceIngestion::Finalize.new.call(
            account: current_account,
            organization: current_organization!,
            session:,
            parts: payload.fetch(:parts),
          )
          [
            200,
            {
              data: serialize_session(result.session),
              snapshot: ApiResource.source_snapshot(result.snapshot)
            }
          ]
        end
      end

      private

      def create_params
        params.require(:source_upload).permit(
          :expected_archive_bytes,
          :expected_archive_sha256,
          :expected_parts,
          :root_directory,
          :excluded_count,
        )
      end

      def finalize_params
        params.require(:source_upload).permit(parts: %i[number size sha256])
      end

      def serialize_session(session)
        {
          id: session.public_id,
          type: "source_upload_session",
          state: session.effective_state,
          project_id: session.project.public_id,
          expected_archive_bytes: session.expected_archive_bytes,
          expected_archive_sha256: session.expected_archive_sha256,
          expected_parts: session.expected_parts,
          expires_at: session.expires_at.iso8601(6),
          snapshot_sha256: session.snapshot_sha256,
          created_at: session.created_at.iso8601(6),
          updated_at: session.updated_at.iso8601(6)
        }
      end

      def render_invalid_source_input
        render_error(
          status: :unprocessable_content,
          code: "invalid_source_parts",
          message: "Source part metadata is invalid.",
        )
      end

      def render_source_rejection(error)
        status = error.status.in?([ 409, 422 ]) ? error.status : 502
        code = status == 409 ? "parts_incomplete" : (status == 422 ? "unsafe_source" : "source_gateway_rejected")
        render_error(status:, code:, message: "The source gateway rejected the upload.")
      end

      def render_source_in_progress
        response.set_header("Retry-After", "2")
        render_error(
          status: :conflict,
          code: "source_finalization_in_progress",
          message: "Source finalization is already running.",
        )
      end

      def render_source_unavailable
        render_error(
          status: :service_unavailable,
          code: "source_gateway_unavailable",
          message: "The source gateway is temporarily unavailable.",
        )
      end
    end
  end
end
