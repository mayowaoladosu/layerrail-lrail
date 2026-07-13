module ApiKeys
  class Revoke
    def self.call(account:, organization:, api_key:)
      Authorization.authorize!(account:, organization:, action: "api_key.revoke", resource: api_key)

      ApiKey.transaction do
        api_key.lock!
        unless api_key.revoked_at?
          api_key.update!(revoked_at: Time.current)
          DomainRecorder.record!(
            resource: api_key,
            event_type: "api_key.revoked",
            action: "api_key.revoke",
            data: { name: api_key.name },
          )
        end
        api_key
      end
    end
  end
end
