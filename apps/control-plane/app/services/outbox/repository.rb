module Outbox
  class Repository
    LostClaim = Class.new(StandardError)

    def initialize(connection: ApplicationRecord.connection)
      @connection = connection
    end

    def claim(worker_name:, limit: 25)
      worker = @connection.quote(worker_name.to_s.first(128))
      batch = Integer(limit).clamp(1, 100)
      rows = @connection.select_all("SELECT * FROM lrail_claim_outbox(#{worker}, #{batch})")
      rows.map { |attributes| OutboxEvent.instantiate(attributes) }
    end

    def finish(event:, worker_name:, published:, error: nil, retry_at: nil, dead_letter: false)
      values = [
        event.id,
        @connection.quote(worker_name.to_s.first(128)),
        @connection.quote(published),
        @connection.quote(error.to_s.first(2048)),
        @connection.quote(retry_at),
        @connection.quote(dead_letter)
      ]
      result = @connection.select_value(<<~SQL.squish)
        SELECT lrail_finish_outbox(#{values.join(", ")})
      SQL
      finished = ActiveModel::Type::Boolean.new.cast(result)
      raise LostClaim, "outbox claim is no longer owned by #{worker_name}" unless finished

      true
    end
  end
end
