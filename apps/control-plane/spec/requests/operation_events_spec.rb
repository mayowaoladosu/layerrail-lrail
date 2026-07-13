require "rails_helper"

RSpec.describe "operation events API", type: :request do
  it "returns a generation-bound resumable ordered cursor" do
    account = create_account
    organization = create_organization(account:)
    operation = within_organization(account, organization) do
      project = Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Event App", slug: "event-app" },
      ).project
      value = Operation.create!(
        organization:,
        resource_type: "project",
        resource_public_id: project.public_id,
        state: "running",
        stage: "building",
        total_steps: 2,
      )
      2.times do |index|
        OperationEvent.create!(
          organization:,
          operation: value,
          generation: 1,
          sequence: index + 1,
          attempt: 1,
          stage: "building",
          kind: "log",
          line: "retained line #{index + 1}",
          occurred_at: Time.current + index.seconds,
        )
      end
      value
    end
    login(account)

    get "/v1/operations/#{operation.public_id}/events",
      params: { generation: 1, after: 1, limit: 10 },
      headers: { "X-Lrail-Organization" => organization.public_id }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("generation")).to eq(1)
    expect(response.parsed_body.fetch("next_sequence")).to eq(2)
    expect(response.parsed_body.fetch("data").pluck("sequence")).to eq([ 2 ])
    expect(response.parsed_body.dig("data", 0, "line")).to eq("retained line 2")
    expect(response.parsed_body.dig("operation", "state")).to eq("running")
  end

  it "does not reveal a foreign operation or accept an invalid cursor" do
    account = create_account
    organization = create_organization(account:)
    foreign = create_account(email: "foreign-events@example.test")
    foreign_organization = create_organization(account: foreign, slug: "foreign-events")
    foreign_operation = within_organization(foreign, foreign_organization) do
      Operation.create!(
        organization: foreign_organization,
        resource_type: "project",
        resource_public_id: "prj_019b01da-7e31-7000-8000-000000000099",
        state: "running",
        stage: "building",
      )
    end
    login(account)

    get "/v1/operations/#{foreign_operation.public_id}/events",
      headers: { "X-Lrail-Organization" => organization.public_id }
    expect(response).to have_http_status(:not_found)

    own_operation = within_organization(account, organization) do
      Operation.create!(
        organization:,
        resource_type: "project",
        resource_public_id: "prj_019b01da-7e31-7000-8000-000000000098",
        state: "running",
        stage: "building",
      )
    end
    get "/v1/operations/#{own_operation.public_id}/events",
      params: { generation: 0 },
      headers: { "X-Lrail-Organization" => organization.public_id }
    expect(response).to have_http_status(:bad_request)
  end

  it "allows an operation-scoped API key to resume retained events" do
    account = create_account
    organization = create_organization(account:)
    issued, operation = within_organization(account, organization) do
      token = ApiKeys::Issue.call(
        account:,
        organization:,
        attributes: { name: "CLI logs", scopes: %w[operation.read] },
      )
      value = Operation.create!(
        organization:,
        resource_type: "deployment",
        resource_public_id: "dep_019b01da-7e31-7000-8000-000000000097",
        state: "running",
        stage: "building",
      )
      [ token, value ]
    end
    expect(ApiKeys::Authenticate.call(token: issued.token, remote_ip: "127.0.0.1")).to be_present

    get "/v1/operations/#{operation.public_id}/events",
      params: { generation: 1, after: 0 },
      headers: { "Authorization" => "Bearer #{issued.token}" }

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.fetch("data")).to eq([])
    expect(response.parsed_body.dig("operation", "id")).to eq(operation.public_id)

    get "/v1/operations/#{operation.public_id}/events",
      headers: { "Authorization" => "Bearer lrail_key_invalid" }
    expect(response).to have_http_status(:unauthorized)
    expect(response).not_to be_redirect
    expect(response.parsed_body.dig("error", "code")).to eq("unauthenticated")
  end
end
