require "net/http"

module BuildOrchestration
  class Client
    Error = Class.new(StandardError)
    MAX_RESPONSE_BYTES = 8.megabytes
    MAX_WATCH_SECONDS = 30

    def initialize(
      endpoint: ENV.fetch("LRAIL_BUILD_SERVICE_ENDPOINT"),
      ca_file: ENV.fetch("LRAIL_BUILD_SERVICE_CA_FILE"),
      certificate_file: ENV.fetch("LRAIL_BUILD_SERVICE_CLIENT_CERT"),
      key_file: ENV.fetch("LRAIL_BUILD_SERVICE_CLIENT_KEY")
    )
      @endpoint = URI(endpoint)
      raise Error, "build service endpoint must be an HTTPS origin" unless
        @endpoint.scheme == "https" && @endpoint.host.present? && @endpoint.path.in?([ "", "/" ]) &&
        @endpoint.userinfo.nil? && @endpoint.query.nil? && @endpoint.fragment.nil?

      @ca_file = ca_file
      @certificate_file = certificate_file
      @key_file = key_file
    rescue URI::InvalidURIError
      raise Error, "build service endpoint is invalid"
    end

    def submit(plan)
      request_json(:post, "/v1/builds:submit", body: plan)
    end

    def get(build_id:, generation:)
      request_json(:get, "/v1/builds/#{path_id(build_id)}", query: { generation: })
    end

    def watch(build_id:, generation:, after:, limit: 250, wait_seconds: 20)
      raise Error, "build event cursor is invalid" unless
        generation.to_i.positive? && after.to_i >= 0 && limit.to_i.between?(1, 1_000) &&
        wait_seconds.to_i.between?(0, MAX_WATCH_SECONDS)

      request_json(
        :get,
        "/v1/builds/#{path_id(build_id)}/events",
        query: { generation:, after:, limit:, wait_seconds: },
        read_timeout: wait_seconds.to_i + 10,
      )
    end

    def cancel(build_id:, generation:, reason:)
      request_json(
        :post,
        "/v1/builds/#{path_id(build_id)}:cancel",
        body: { generation:, reason: reason.to_s.first(512) },
      )
    end

    private

    def request_json(method, path, body: nil, query: nil, read_timeout: 40)
      uri = @endpoint.dup
      uri.path = path
      uri.query = URI.encode_www_form(query) if query
      request = method == :post ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"
      request["Cache-Control"] = "no-store"
      if body
        request["Content-Type"] = "application/json"
        request.body = JSON.generate(body)
      end

      response = nil
      payload = nil
      http(read_timeout:).request(request) do |received|
        response = received
        payload = read_bounded(received)
      end
      unless response.is_a?(Net::HTTPSuccess) || response.code == "202"
        raise Error, "build service rejected the request"
      end
      JSON.parse(payload, max_nesting: 100)
    rescue Error
      raise
    rescue JSON::ParserError, OpenSSL::OpenSSLError, SystemCallError, Timeout::Error,
        IOError, EOFError, SocketError
      raise Error, "build service is unavailable"
    end

    def http(read_timeout:)
      client = Net::HTTP.new(@endpoint.host, @endpoint.port)
      client.use_ssl = true
      client.min_version = OpenSSL::SSL::TLS1_3_VERSION
      client.verify_mode = OpenSSL::SSL::VERIFY_PEER
      client.ca_file = @ca_file
      client.cert = OpenSSL::X509::Certificate.new(File.binread(@certificate_file))
      client.key = OpenSSL::PKey.read(File.binread(@key_file))
      client.open_timeout = 10
      client.read_timeout = read_timeout
      client.write_timeout = 10
      client.keep_alive_timeout = 30
      client
    rescue Errno::ENOENT, OpenSSL::PKey::PKeyError
      raise Error, "build service client identity is unavailable"
    end

    def read_bounded(response)
      contents = +""
      response.read_body do |chunk|
        raise Error, "build service response is oversized" if contents.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES

        contents << chunk
      end
      raise Error, "build service response is empty" if contents.empty?

      contents
    end

    def path_id(value)
      id = value.to_s
      raise Error, "build identity is invalid" unless id.match?(/\Abld_[0-9a-f-]{36}\z/)

      id
    end
  end
end
