class Current < ActiveSupport::CurrentAttributes
  attribute :account, :organization, :request_id, :traceparent

  resets do
    RequestStore.clear!
  end
end
