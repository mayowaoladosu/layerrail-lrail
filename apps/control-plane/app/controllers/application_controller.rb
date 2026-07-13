class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  before_action :assign_request_context

  rescue_from ActiveRecord::RecordNotFound, with: :render_not_found
  rescue_from ActiveRecord::RecordInvalid, with: :render_validation_failed
  rescue_from ActionController::ParameterMissing, with: :render_parameter_missing
  rescue_from Authorization::Denied, with: :render_forbidden
  rescue_from Idempotency::Mismatch, with: :render_idempotency_conflict

  helper_method :current_account

  private

  def current_account
    rodauth.rails_account
  end

  def require_account
    rodauth.require_account
  end

  def assign_request_context
    Current.request_id = RequestIdentity.request_id(request.request_id)
    Current.traceparent = RequestIdentity.traceparent(request.headers["traceparent"]&.first(128))
    Current.authentication_method = "session"
    response.set_header("X-Request-ID", Current.request_id)
  end

  def render_not_found
    render_error(status: :not_found, code: "not_found", message: "The requested resource was not found.")
  end

  def render_forbidden(error)
    render_error(status: :forbidden, code: error.reason, message: "This account cannot perform that action.")
  end

  def render_validation_failed(error)
    details = error.record.errors.map { |validation| { field: validation.attribute, reason: validation.type } }
    render_error(status: :unprocessable_content, code: "validation_failed", message: "The request failed validation.", details:)
  end

  def render_parameter_missing(error)
    render_error(
      status: :bad_request,
      code: "invalid_argument",
      message: "A required request field is missing.",
      details: [ { field: error.param, reason: "required" } ],
    )
  end

  def render_idempotency_conflict
    render_error(status: :conflict, code: "idempotency_key_reused", message: "This idempotency key was used with different input.")
  end

  def render_error(status:, code:, message:, details: [])
    if request.format.json?
      render json: { error: { code:, message:, request_id: Current.request_id, details: } }, status:
    else
      render "errors/show", status:, locals: { code:, message: }
    end
  end
end
