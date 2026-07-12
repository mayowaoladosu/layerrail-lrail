class HealthController < ActionController::API
  def live
    render json: { status: "live", version: build_version }
  end

  def ready
    ApplicationRecord.connection.select_value("SELECT 1")
    render json: { status: "ready", version: build_version }
  rescue ActiveRecord::ActiveRecordError
    render json: {
      error: {
        code: "dependency_unavailable",
        message: "A mandatory dependency is unavailable.",
        request_id: request.request_id,
        details: []
      }
    }, status: :service_unavailable
  end

  def version
    render json: {
      version: build_version,
      commit: ENV.fetch("LRAIL_COMMIT", "development"),
      built_at: ENV.fetch("LRAIL_BUILT_AT", "local")
    }
  end

  private

  def build_version
    ENV.fetch("LRAIL_VERSION", "0.1.0-dev")
  end
end
