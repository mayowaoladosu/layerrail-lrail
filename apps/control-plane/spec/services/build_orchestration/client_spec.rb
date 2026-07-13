require "rails_helper"

RSpec.describe BuildOrchestration::Client do
  def client
    described_class.new(
      endpoint: "https://build.internal.test",
      ca_file: "unused-ca",
      certificate_file: "unused-cert",
      key_file: "unused-key",
    )
  end

  def fake_http(response_class, code, message, body)
    response = response_class.new("1.1", code, message)
    allow(response).to receive(:read_body).and_yield(body)
    request_value = nil
    http = instance_double(Net::HTTP)
    allow(http).to receive(:request) do |value, &block|
      request_value = value
      block.call(response)
      response
    end
    [ http, -> { request_value } ]
  end

  it "sends bounded strict JSON and parses a successful response" do
    http, request_value = fake_http(Net::HTTPOK, "200", "OK", '{"state":"accepted"}')
    value = client
    allow(value).to receive(:http).and_return(http)

    result = value.submit(version: 1, build_id: "bld_019b01da-7e31-7000-8000-000000000001")

    expect(result).to eq("state" => "accepted")
    expect(request_value.call).to be_a(Net::HTTP::Post)
    expect(request_value.call["Content-Type"]).to eq("application/json")
    expect(JSON.parse(request_value.call.body)).to include("version" => 1)
  end

  it "constructs an exact resumable event cursor" do
    http, request_value = fake_http(
      Net::HTTPOK,
      "200",
      "OK",
      '{"events":[],"run":{"state":"running"}}',
    )
    value = client
    allow(value).to receive(:http).and_return(http)

    value.watch(
      build_id: "bld_019b01da-7e31-7000-8000-000000000001",
      generation: 2,
      after: 41,
      limit: 100,
      wait_seconds: 20,
    )

    expect(request_value.call.uri.query).to eq("generation=2&after=41&limit=100&wait_seconds=20")
  end

  it "does not expose a remote response body in errors" do
    http, = fake_http(Net::HTTPConflict, "409", "Conflict", '{"secret":"must-not-leak"}')
    value = client
    allow(value).to receive(:http).and_return(http)

    expect do
      value.submit(version: 1)
    end.to raise_error(BuildOrchestration::Client::Error, "build service rejected the request")
  end

  it "rejects non-TLS endpoints and invalid build identities" do
    expect do
      described_class.new(
        endpoint: "http://build.internal.test",
        ca_file: "unused",
        certificate_file: "unused",
        key_file: "unused",
      )
    end.to raise_error(BuildOrchestration::Client::Error, /HTTPS origin/)

    expect do
      client.get(build_id: "../foreign", generation: 1)
    end.to raise_error(BuildOrchestration::Client::Error, /identity/)
  end
end
