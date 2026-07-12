require "rails_helper"

RSpec.describe "service health", type: :request do
  it "reports liveness, readiness, and redacted build version" do
    get "/live"
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include("status" => "live")

    get "/ready"
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to include("status" => "ready")

    get "/version"
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.keys).to contain_exactly("version", "commit", "built_at")
  end
end
