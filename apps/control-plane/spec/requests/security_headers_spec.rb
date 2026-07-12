require "rails_helper"

RSpec.describe "browser security boundaries", type: :request do
  before { Rack::Attack.cache.store.clear }

  it "serves a deny-by-default content security policy" do
    get "/auth/login"

    expect(response).to have_http_status(:ok)
    expect(response.headers.fetch("Content-Security-Policy")).to include(
      "default-src 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'"
    )
    expect(response.headers.fetch("Permissions-Policy")).to include("camera=()", "microphone=()")
    expect(response.headers.fetch("X-Frame-Options")).to eq("DENY")
  end

  it "rate limits repeated login attempts without disclosing the principal" do
    21.times do
      post "/auth/login", params: { email: "unknown@example.test", password: "not-the-password" }
    end

    expect(response).to have_http_status(:too_many_requests)
    expect(response.headers.fetch("Retry-After").to_i).to be_positive
    expect(response.parsed_body).to eq(
      "error" => {
        "code" => "rate_limited",
        "message" => "Too many requests",
        "retry_after" => response.headers.fetch("Retry-After").to_i
      }
    )
    expect(response.body).not_to include("unknown@example.test")
  end
end
