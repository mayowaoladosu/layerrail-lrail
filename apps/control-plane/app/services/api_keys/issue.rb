module ApiKeys
  class Issue
    Result = Data.define(:api_key, :token)

    def self.call(account:, organization:, attributes:)
      Authorization.authorize!(account:, organization:, action: "api_key.create")
      secret = SecureRandom.urlsafe_base64(32, false)
      prefix = SecureRandom.alphanumeric(12)
      keyed = ApiKeys.keyed_secret(secret)

      ApiKey.transaction do
        api_key = ApiKey.create!(
          organization:,
          account:,
          name: attributes.fetch(:name),
          prefix:,
          secret_digest: Argon2::Password.create(keyed),
          scopes: Array(attributes.fetch(:scopes)).map(&:to_s),
          constraints: attributes.fetch(:constraints, {}).to_h,
          expires_at: attributes[:expires_at],
        )
        DomainRecorder.record!(
          resource: api_key,
          event_type: "api_key.created",
          action: "api_key.create",
          data: { scopes: api_key.scopes, expires_at: api_key.expires_at&.iso8601(6) },
        )
        Result.new(api_key, "lrail_key_#{prefix}_#{secret}")
      end
    end
  end
end
