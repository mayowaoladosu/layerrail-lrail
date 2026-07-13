module SourceProviders
  class GithubDeliveryRepository
    ApplyResult = Data.define(:outcome, :delivery_public_id, :organization_public_id, :actor_public_id, :work_pending)

    def initialize(connection: ApplicationRecord.connection)
      @connection = connection
    end

    def apply(installation_id:, delivery_id:, event_type:, payload_digest:, attributes:)
      delivery_public_id = PlatformId.generate(:evt)
      values = [
        installation_id,
        delivery_id,
        event_type,
        attributes[:action],
        payload_digest,
        attributes[:repository],
        attributes[:ref],
        attributes[:commit_sha],
        attributes[:base_commit_sha],
        attributes[:pull_request_number],
        attributes.fetch(:forced, false),
        attributes.fetch(:deleted, false),
        attributes.fetch(:state),
        attributes[:next_connection_status],
        attributes[:provider_account_login],
        attributes[:provider_account_id],
        attributes[:repository_selection],
        attributes.fetch(:repositories_mode, "none"),
        JSON.generate(attributes.fetch(:repository_values, [])),
        delivery_public_id,
        PlatformId.generate(:evt),
        PlatformId.generate(:evt),
        RequestIdentity.request_id(Current.request_id)
      ]
      quoted = values.each_with_index.map do |value, index|
        literal = @connection.quote(value)
        index == 18 ? "#{literal}::jsonb" : literal
      end
      raw = @connection.select_value(<<~SQL.squish)
        SELECT lrail_apply_github_provider_delivery(#{quoted.join(", ")})
      SQL
      result = (raw.is_a?(String) ? JSON.parse(raw) : raw).deep_stringify_keys
      ApplyResult.new(
        result.fetch("outcome"),
        result["delivery_public_id"],
        result["organization_public_id"],
        result["actor_public_id"],
        result.fetch("work_pending", false),
      )
    end

    def claim(delivery_public_id:, lease_token:)
      @connection.select_value(<<~SQL.squish)
        SELECT lrail_claim_github_provider_delivery(
          #{@connection.quote(delivery_public_id)},
          #{@connection.quote(lease_token)}
        )
      SQL
    end

    def finish(delivery_public_id:, lease_token:, succeeded:, error_code: nil)
      @connection.select_value(<<~SQL.squish) == true
        SELECT lrail_finish_github_provider_delivery(
          #{@connection.quote(delivery_public_id)},
          #{@connection.quote(lease_token)},
          #{@connection.quote(succeeded)},
          #{@connection.quote(error_code.to_s)}
        )
      SQL
    end
  end
end
