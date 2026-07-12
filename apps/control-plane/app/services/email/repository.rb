module Email
  class Repository
    LostClaim = Class.new(StandardError)

    def initialize(connection: ApplicationRecord.connection)
      @connection = connection
    end

    def claim(worker_name:, limit: 25)
      worker = @connection.quote(worker_name.to_s.first(128))
      batch = Integer(limit).clamp(1, 100)
      rows = @connection.select_all("SELECT * FROM lrail_claim_email(#{worker}, #{batch})")
      rows.map { |attributes| EmailIntent.instantiate(attributes) }
    end

    def finish(intent:, worker_name:, state:, provider:, message_id: nil, error: nil, retry_at: nil)
      values = [
        intent.id,
        @connection.quote(worker_name.to_s.first(128)),
        @connection.quote(state),
        @connection.quote(provider),
        @connection.quote(message_id),
        @connection.quote(error.to_s.first(2048)),
        @connection.quote(retry_at)
      ]
      result = @connection.select_value(<<~SQL.squish)
        SELECT lrail_finish_email(#{values.join(", ")})
      SQL
      finished = ActiveModel::Type::Boolean.new.cast(result)
      raise LostClaim, "email claim is no longer owned by #{worker_name}" unless finished

      true
    end
  end
end
