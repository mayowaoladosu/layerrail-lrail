module SourceProviders
  class GithubWebhook
    Result = Data.define(:outcome, :delivery_public_id, :organization_public_id, :actor_public_id, :work_pending)

    def initialize(secret: SourceProviders.webhook_secret, repository: GithubDeliveryRepository.new)
      @secret = secret
      @repository = repository
      raise ArgumentError, "GitHub webhook secret must contain at least 32 bytes" if @secret.bytesize < 32
    end

    def process(raw_body:, headers:)
      raise InvalidWebhook, "GitHub webhook body is outside limits" if raw_body.blank? || raw_body.bytesize > MAX_WEBHOOK_BYTES

      values = normalized_headers(headers)
      verify_signature!(raw_body, values.fetch("signature"))
      event_type = values.fetch("event")
      delivery_id = values.fetch("delivery")
      raise InvalidWebhook, "unsupported GitHub event" unless event_type.in?(SUPPORTED_EVENTS)
      raise InvalidWebhook, "invalid GitHub delivery ID" unless DELIVERY_PATTERN.match?(delivery_id)

      payload = JSON.parse(raw_body, max_nesting: 64)
      raise InvalidWebhook, "GitHub payload must be an object" unless payload.is_a?(Hash)
      installation_id = payload.dig("installation", "id").to_s
      return Result.new("pong", nil, nil, nil, false) if event_type == "ping"

      attributes = normalized_event(event_type, payload)
      applied = @repository.apply(
        installation_id:,
        delivery_id:,
        event_type:,
        payload_digest: "sha256:#{Digest::SHA256.hexdigest(raw_body)}",
        attributes:,
      )
      raise DuplicateMismatch, "GitHub delivery ID was reused with different content" if applied.outcome == "mismatch"

      Result.new(
        applied.outcome,
        applied.delivery_public_id,
        applied.organization_public_id,
        applied.actor_public_id,
        applied.work_pending,
      )
    rescue JSON::ParserError, KeyError, ActiveRecord::StatementInvalid
      raise InvalidWebhook, "GitHub webhook is invalid"
    end

    private

    def normalized_event(event_type, payload)
      case event_type
      when "push" then push_event(payload)
      when "pull_request" then pull_request_event(payload)
      when "installation" then installation_event(payload)
      when "installation_repositories" then installation_repositories_event(payload)
      else raise InvalidWebhook, "unsupported GitHub event"
      end
    end

    def push_event(payload)
      deleted = payload.fetch("deleted") == true
      commit = payload.fetch("after").to_s.downcase
      commit = nil if deleted
      validate_commit!(commit) unless deleted
      {
        state: deleted ? "ignored" : "received",
        repository: repository_name(payload),
        ref: payload.fetch("ref").to_s,
        commit_sha: commit,
        base_commit_sha: valid_optional_commit(payload.fetch("before").to_s.downcase),
        forced: payload.fetch("forced") == true,
        deleted:
      }
    end

    def pull_request_event(payload)
      action = payload.fetch("action").to_s
      relevant = action.in?(%w[opened reopened synchronize])
      request = payload.fetch("pull_request")
      head = request.dig("head", "sha").to_s.downcase
      base = request.dig("base", "sha").to_s.downcase
      validate_commit!(head)
      validate_commit!(base)
      {
        state: relevant ? "received" : "ignored",
        action:,
        repository: repository_name(payload),
        ref: request.dig("head", "ref").to_s,
        commit_sha: head,
        base_commit_sha: base,
        pull_request_number: Integer(payload.fetch("number")),
        deleted: action == "closed"
      }
    end

    def installation_event(payload)
      action = payload.fetch("action").to_s
      account = payload.dig("installation", "account") || {}
      next_status = { "deleted" => "revoked", "suspend" => "suspended", "unsuspend" => "active", "created" => "active" }[action]
      repositories = repository_names(payload["repositories"])
      {
        state: next_status ? "processed" : "ignored",
        action:,
        next_connection_status: next_status,
        provider_account_login: account.fetch("login").to_s,
        provider_account_id: Integer(account.fetch("id")),
        repository_selection: payload.dig("installation", "repository_selection").to_s,
        repositories_mode: action == "created" ? "replace" : "none",
        repository_values: repositories
      }
    end

    def installation_repositories_event(payload)
      action = payload.fetch("action").to_s
      source = action == "added" ? payload["repositories_added"] : payload["repositories_removed"]
      names = repository_names(source)
      {
        state: action.in?(%w[added removed]) ? "processed" : "ignored",
        action:,
        repository_selection: payload.fetch("repository_selection").to_s,
        repositories_mode: { "added" => "add", "removed" => "remove" }.fetch(action, "none"),
        repository_values: names
      }
    end

    def repository_names(values)
      Array(values).map do |repository|
        name = repository.fetch("full_name").to_s.downcase
        raise InvalidWebhook, "invalid GitHub repository" unless SourceFetch::REPOSITORY_PATTERN.match?(name)

        name
      end.uniq.sort
    end

    def repository_name(payload)
      value = payload.dig("repository", "full_name").to_s.downcase
      raise InvalidWebhook, "invalid GitHub repository" unless SourceFetch::REPOSITORY_PATTERN.match?(value)

      value
    end

    def validate_commit!(value)
      raise InvalidWebhook, "invalid GitHub commit" unless SourceFetch::COMMIT_PATTERN.match?(value)
    end

    def valid_optional_commit(value)
      SourceFetch::COMMIT_PATTERN.match?(value) && value.match?(/[^0]/) ? value : nil
    end

    def verify_signature!(raw_body, signature)
      expected = "sha256=#{OpenSSL::HMAC.hexdigest("SHA256", @secret, raw_body)}"
      raise InvalidWebhook, "GitHub signature is invalid" unless secure_equal?(expected, signature)
    end

    def secure_equal?(left, right)
      left.bytesize == right.to_s.bytesize && ActiveSupport::SecurityUtils.secure_compare(left, right.to_s)
    end

    def normalized_headers(headers)
      values = headers.to_h.transform_keys { |key| key.to_s.downcase }
      {
        "signature" => values["x-hub-signature-256"] || values["http_x_hub_signature_256"],
        "delivery" => values["x-github-delivery"] || values["http_x_github_delivery"],
        "event" => values["x-github-event"] || values["http_x_github_event"]
      }.transform_values(&:to_s)
    end
  end
end
