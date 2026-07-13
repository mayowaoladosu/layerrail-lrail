require "rails_helper"

RSpec.describe "API keys", type: :request do
  it "creates once, shows the secret once, authenticates, scopes, and revokes" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Token App", slug: "token-app" }).project
    end
    login(account)
    headers = {
      "X-Lrail-Organization" => organization.public_id,
      "Idempotency-Key" => "create-api-key-request-1",
      "Content-Type" => "application/json"
    }
    body = {
      api_key: {
        name: "CLI",
        scopes: %w[project.read source.write],
        constraints: { ip_cidrs: [ "127.0.0.0/8" ] },
        expires_at: 30.days.from_now.iso8601(6)
      }
    }

    post "/v1/api_keys", params: JSON.generate(body), headers: headers
    expect(response).to have_http_status(:created)
    first = response.parsed_body
    token = first.fetch("secret")
    expect(token).to start_with("lrail_key_")
    idempotency_record = IdempotencyKey.find_by!(organization:)
    expect(idempotency_record.response_body.to_json).not_to include(token)

    post "/v1/api_keys", params: JSON.generate(body), headers: headers
    expect(response).to have_http_status(:created)
    expect(response.headers["Idempotency-Replayed"]).to eq("true")
    expect(response.parsed_body.fetch("secret")).to eq(token)
    expect(ApiKey.count).to eq(1)

    get "/v1/projects/#{project.public_id}", headers: {
      "Authorization" => "Bearer #{token}",
      "X-Lrail-Organization" => organization.public_id
    }
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.dig("data", "id")).to eq(project.public_id)

    get "/v1/projects/#{project.public_id}", headers: { "Authorization" => "Bearer #{token}" }
    expect(response).to have_http_status(:ok)

    get "/v1/projects/#{project.public_id}", headers: {
      "Authorization" => "Bearer #{token}",
      "X-Lrail-Organization" => "org_019b01da-7e31-7000-8000-000000000099"
    }
    expect(response).to have_http_status(:not_found)

    post "/v1/organizations/#{organization.public_id}/projects",
      params: JSON.generate(slug: "denied", name: "Denied"),
      headers: {
        "Authorization" => "Bearer #{token}",
        "Idempotency-Key" => "api-key-scope-denied",
        "Content-Type" => "application/json"
      }
    expect(response).to have_http_status(:forbidden)
    expect(response.parsed_body.dig("error", "code")).to eq("api_key_scope_missing")

    delete "/v1/api_keys/#{first.dig("data", "id")}", headers: headers.merge("Idempotency-Key" => "revoke-api-key-request")
    expect(response).to have_http_status(:ok)
    delete "/v1/api_keys/#{first.dig("data", "id")}", headers: headers.merge("Idempotency-Key" => "revoke-api-key-request")
    expect(response).to have_http_status(:ok)
    expect(response.headers["Idempotency-Replayed"]).to eq("true")
    expect(OutboxEvent.where(event_type: "api_key.revoked").count).to eq(1)
    get "/v1/projects/#{project.public_id}", headers: { "Authorization" => "Bearer #{token}" }
    expect(response).to have_http_status(:unauthorized)
  end

  it "never includes a secret in list responses" do
    account = create_account
    organization = create_organization(account:)
    within_organization(account, organization) do
      ApiKeys::Issue.call(account:, organization:, attributes: { name: "Listed", scopes: %w[project.read] })
    end
    login(account)

    get "/v1/api_keys", headers: { "X-Lrail-Organization" => organization.public_id }

    expect(response).to have_http_status(:ok)
    expect(response.body).not_to include("secret", "$argon2")
    expect(response.parsed_body.fetch("data").first.fetch("display_prefix")).to start_with("lrail_key_")
  end
end
