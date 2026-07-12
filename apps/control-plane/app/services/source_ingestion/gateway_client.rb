require "net/http"
require "uri"

module SourceIngestion
  class GatewayClient
    Error = Class.new(StandardError)
    class Rejected < Error
      attr_reader :status, :code

      def initialize(status:, code:)
        @status = status
        @code = code
        super("source gateway rejected the request")
      end
    end
    MAX_RESPONSE_BYTES = 256.kilobytes

    def initialize(base_url:, grant_signer:, result_verifier: nil)
      @base_url = URI(base_url)
      raise ArgumentError, "source gateway URL must use HTTPS" if Rails.env.production? && @base_url.scheme != "https"
      raise ArgumentError, "source gateway URL must be an HTTP origin" unless @base_url.is_a?(URI::HTTP) && @base_url.path.in?([ "", "/" ])

      @grant_signer = grant_signer
      @result_verifier = result_verifier
    end

    def create_session(session)
      request_json(session, "/v1/sessions", {})
    end

    def finalize(session, parts:)
      raise ArgumentError, "source result verifier is required" unless @result_verifier

      payload = request_json(session, "/v1/finalizations", { parts: })
      @result_verifier.verify!(payload, expected_session: session)
    end

    private

    def request_json(session, path, body)
      request = Net::HTTP::Post.new(path)
      request["Authorization"] = "Bearer #{@grant_signer.sign(session)}"
      request["Content-Type"] = "application/json"
      request["Accept"] = "application/json"
      request["X-Request-ID"] = Current.request_id if Current.request_id.present?
      request.body = JSON.generate(body)

      response = Net::HTTP.start(
        @base_url.host,
        @base_url.port,
        use_ssl: @base_url.scheme == "https",
        open_timeout: 2,
        read_timeout: 15.minutes,
        write_timeout: 30,
      ) { |connection| connection.request(request) }
      raw = response.body.to_s
      raise Error, "source gateway response exceeded limit" if raw.bytesize > MAX_RESPONSE_BYTES
      media_type = response["Content-Type"].to_s.split(";", 2).first
      raise Error, "source gateway returned a non-JSON response" unless media_type == "application/json"

      parsed = JSON.parse(raw, max_nesting: 50)
      unless response.is_a?(Net::HTTPSuccess)
        raise Rejected.new(status: response.code.to_i, code: parsed.dig("error", "code").to_s.first(64))
      end

      parsed
    rescue JSON::ParserError, IOError, SocketError, SystemCallError, Timeout::Error => error
      raise Error, "source gateway request failed: #{error.class}"
    end
  end
end
