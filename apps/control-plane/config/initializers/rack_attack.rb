require "digest"

class Rack::Attack
  Rack::Attack.cache.store = Rails.env.test? ? ActiveSupport::Cache::MemoryStore.new : Rails.cache

  throttle("auth/ip", limit: 60, period: 5.minutes) do |request|
    request.ip if request.post? && request.path.start_with?("/auth/")
  end

  throttle("login/principal", limit: 20, period: 15.minutes) do |request|
    next unless request.post? && request.path == "/auth/login"

    login = request.params["email"].to_s.strip.downcase.first(320)
    "#{request.ip}:#{Digest::SHA256.hexdigest(login)}"
  rescue ActionDispatch::Http::Parameters::ParseError
    request.ip
  end

  throttle("account-creation/ip", limit: 10, period: 1.hour) do |request|
    request.ip if request.post? && request.path == "/auth/create-account"
  end

  throttle("password-reset/ip", limit: 10, period: 1.hour) do |request|
    request.ip if request.post? && request.path == "/auth/reset-password-request"
  end

  throttle("api/ip", limit: 600, period: 1.minute) do |request|
    request.ip if request.path.start_with?("/v1/")
  end

  throttle("provider-webhooks/ip", limit: 600, period: 1.minute) do |request|
    request.ip if request.post? && request.path.start_with?("/webhooks/")
  end

  self.throttled_responder = lambda do |request|
    match = request.env.fetch("rack.attack.match_data", {})
    period = Integer(match.fetch(:period, 60))
    retry_after = period - (Time.current.to_i % period)
    headers = {
      "Content-Type" => "application/json; charset=utf-8",
      "Retry-After" => retry_after.to_s,
      "Cache-Control" => "no-store"
    }
    body = JSON.generate(error: { code: "rate_limited", message: "Too many requests", retry_after: })
    [ 429, headers, [ body ] ]
  end
end
