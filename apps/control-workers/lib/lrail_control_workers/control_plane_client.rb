module LrailControlWorkers
  class ControlPlaneClient
    def initialize(http: default_http)
      @http = http
    end

    def prepare(input)
      @http.post(
        "/internal/v1/deployments/#{deployment_id(input)}/builds:prepare",
        body: context(input)
      )
    end

    def persist_events(input, build_id:, events:)
      @http.post(
        "/internal/v1/deployments/#{deployment_id(input)}/build-events",
        body: context(input).merge("build_id" => build_id, "events" => events)
      )
    end

    def finalize(input, build_id:, result:)
      @http.post(
        "/internal/v1/deployments/#{deployment_id(input)}/build-result",
        body: context(input).merge("build_id" => build_id, "result" => result)
      )
    end

    private

    def context(input)
      input.slice("actor_id", "organization_id", "operation_id", "workflow_id", "generation")
    end

    def deployment_id(input)
      value = input.fetch("deployment_id")
      raise ArgumentError, "invalid deployment ID" unless value.match?(/\Adep_[0-9a-f-]{36}\z/)

      value
    end

    def default_http
      HTTPJSONClient.new(
        endpoint: ENV.fetch("LRAIL_CONTROL_INTERNAL_ENDPOINT"),
        ca_file: ENV.fetch("LRAIL_CONTROL_INTERNAL_CA_FILE"),
        certificate_file: ENV.fetch("LRAIL_CONTROL_INTERNAL_CLIENT_CERT"),
        key_file: ENV.fetch("LRAIL_CONTROL_INTERNAL_CLIENT_KEY")
      )
    end
  end
end
