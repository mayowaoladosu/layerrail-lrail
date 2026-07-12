require "rails_helper"

RSpec.describe "projects API", type: :request do
  it "creates once and replays the same response for a repeated idempotency key" do
    account = create_account
    organization = create_organization(account:)
    login(account)
    headers = {
      "X-Lrail-Organization" => organization.public_id,
      "Idempotency-Key" => "request-project-create-0001",
      "Content-Type" => "application/json"
    }
    body = { name: "API Project", slug: "api-project", description: "Created through v1" }.to_json
    path = "/v1/organizations/#{organization.public_id}/projects"

    post path, params: body, headers: headers
    expect(response).to have_http_status(:accepted)
    first = response.parsed_body

    post path, params: body, headers: headers
    expect(response).to have_http_status(:accepted)
    expect(response.headers["Idempotency-Replayed"]).to eq("true")
    expect(response.parsed_body).to eq(first)

    within_organization(account, organization) do
      expect(organization.projects.where(slug: "api-project").count).to eq(1)
      expect(OutboxEvent.where(event_type: "project.created").count).to eq(1)
    end
  end

  it "does not reveal a foreign project under the selected organization" do
    account = create_account
    foreign = create_account(email: "foreign-api@example.test", name: "Foreign")
    organization = create_organization(account:)
    foreign_org = create_organization(account: foreign, slug: "foreign-api")
    foreign_project = within_organization(foreign, foreign_org) do
      Projects::Create.call(account: foreign, organization: foreign_org, attributes: { name: "Secret", slug: "secret" }).project
    end
    login(account)

    get "/v1/projects/#{foreign_project.public_id}", headers: { "X-Lrail-Organization" => organization.public_id }

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body.dig("error", "code")).to eq("not_found")
  end
end
