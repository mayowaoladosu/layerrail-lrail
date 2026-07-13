require "json"
require "net/http"
require "openssl"
require "uri"

module LrailControlWorkers
  class HTTPJSONClient
    class Error < StandardError; end

    MAX_RESPONSE_BYTES = 8 * 1024 * 1024

    def initialize(endpoint:, ca_file:, certificate_file:, key_file:)
      @endpoint = parse_endpoint(endpoint)
      @ca_file = ca_file
      @certificate_file = certificate_file
      @key_file = key_file
    end

    def get(path, query: nil, read_timeout: 40)
      request(:get, path, read_timeout:, query:)
    end

    def post(path, body:, read_timeout: 40)
      request(:post, path, read_timeout:, body:)
    end

    private

    def request(method, path, read_timeout:, body: nil, query: nil)
      raise Error, "internal path is invalid" unless path.start_with?("/") && !path.include?("..")

      uri = @endpoint.dup
      uri.path = path
      uri.query = URI.encode_www_form(query) if query
      response, payload = perform(build_request(method, uri, body), read_timeout:)
      raise Error, "internal service rejected the request" unless response.is_a?(Net::HTTPSuccess)

      JSON.parse(payload, max_nesting: 100)
    rescue Error
      raise
    rescue JSON::ParserError, OpenSSL::OpenSSLError, SystemCallError, Timeout::Error,
           IOError, SocketError
      raise Error, "internal service is unavailable"
    end

    def parse_endpoint(value)
      endpoint = URI(value)
      valid = endpoint.scheme == "https" && endpoint.host &&
              [ "", "/" ].include?(endpoint.path) &&
              [ endpoint.userinfo, endpoint.query, endpoint.fragment ].all?(&:nil?)
      raise Error, "internal endpoint must be an HTTPS origin" unless valid

      endpoint
    rescue URI::InvalidURIError
      raise Error, "internal endpoint is invalid"
    end

    def build_request(method, uri, body)
      request = method == :post ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
      request["Accept"] = "application/json"
      request["Cache-Control"] = "no-store"
      return request unless body

      request["Content-Type"] = "application/json"
      request.body = JSON.generate(body)
      request
    end

    def perform(request, read_timeout:)
      response = nil
      payload = nil
      http(read_timeout:).request(request) do |received|
        response = received
        payload = read_bounded(received)
      end
      [ response, payload ]
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
      raise Error, "internal service client identity is unavailable"
    end

    def read_bounded(response)
      contents = +""
      response.read_body do |chunk|
        raise Error, "internal response is oversized" if contents.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES

        contents << chunk
      end
      raise Error, "internal response is empty" if contents.empty?

      contents
    end
  end
end
