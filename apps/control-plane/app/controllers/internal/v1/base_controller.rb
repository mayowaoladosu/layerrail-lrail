module Internal
  module V1
    class BaseController < ActionController::API
      MAX_BODY_BYTES = 8.megabytes

      wrap_parameters false

      before_action :authenticate_service_identity!
      around_action :with_actor_context

      rescue_from ActiveRecord::RecordNotFound, with: :not_found
      rescue_from ActiveRecord::RecordInvalid, ArgumentError, KeyError, TypeError,
        ActionController::ParameterMissing, with: :invalid_request

      private

      attr_reader :current_actor, :current_organization

      def authenticate_service_identity!
        certificate = peer_certificate
        now = Time.current
        allowed = ENV.fetch(
          "LRAIL_INTERNAL_WORKER_URIS",
          "spiffe://lrail.internal/control-worker",
        ).split(",").map(&:strip).reject(&:blank?)
        san = certificate.extensions.find { |extension| extension.oid == "subjectAltName" }&.value.to_s
        uris = san.scan(/URI:([^,\s]+)/).flatten
        client_auth = certificate.extensions.find { |extension| extension.oid == "extendedKeyUsage" }&.value.to_s
        valid = certificate.not_before <= now && certificate.not_after > now &&
          uris.intersect?(allowed) && client_auth.include?("TLS Web Client Authentication")
        head :not_found unless valid
      rescue OpenSSL::X509::CertificateError, TypeError
        head :not_found
      end

      def peer_certificate
        value = request.env["puma.peercert"] || request.env["SSL_CLIENT_CERT"]
        return value if value.is_a?(OpenSSL::X509::Certificate)
        raise OpenSSL::X509::CertificateError if value.blank? || value.bytesize > 64.kilobytes

        OpenSSL::X509::Certificate.new(value)
      end

      def with_actor_context
        return if performed?
        raise ActionController::BadRequest, "request body is too large" if
          request.content_length.to_i > MAX_BODY_BYTES

        payload = request.request_parameters.deep_stringify_keys
        account = Account.find_by!(public_id: payload.fetch("actor_id"))
        Current.request_id = RequestIdentity.request_id(request.request_id)
        Current.authentication_method = "service_identity"
        OrganizationContext.select_for(account:, identifier: payload.fetch("organization_id")) do |organization|
          @current_actor = account
          @current_organization = organization
          yield
        end
      end

      def strict_body!(*allowed)
        payload = request.request_parameters.deep_stringify_keys
        extras = payload.keys - allowed.map(&:to_s)
        raise ActionController::BadRequest, "request contains unknown fields" if extras.any?

        payload
      end

      def not_found
        render json: { error: { code: "not_found", message: "Resource was not found" } }, status: :not_found
      end

      def invalid_request
        render json: { error: { code: "invalid_argument", message: "Request is invalid" } }, status: :bad_request
      end
    end
  end
end
