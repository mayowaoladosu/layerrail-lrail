module LrailControlWorkers
  class BuildServiceClient
    def initialize(http: default_http)
      @http = http
    end

    def submit(plan)
      @http.post("/v1/builds:submit", body: plan)
    end

    def watch(build_id:, generation:, after:, wait_seconds: 20)
      @http.get(
        "/v1/builds/#{build_id}/events",
        query: { generation:, after:, limit: 250, wait_seconds: },
        read_timeout: wait_seconds + 10
      )
    end

    def cancel(build_id:, generation:, reason:)
      @http.post(
        "/v1/builds/#{build_id}:cancel",
        body: { generation:, reason: reason.to_s[0, 512] }
      )
    end

    private

    def default_http
      HTTPJSONClient.new(
        endpoint: ENV.fetch("LRAIL_BUILD_SERVICE_ENDPOINT"),
        ca_file: ENV.fetch("LRAIL_BUILD_SERVICE_CA_FILE"),
        certificate_file: ENV.fetch("LRAIL_BUILD_SERVICE_CLIENT_CERT"),
        key_file: ENV.fetch("LRAIL_BUILD_SERVICE_CLIENT_KEY")
      )
    end
  end
end
