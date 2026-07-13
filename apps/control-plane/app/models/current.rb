class Current < ActiveSupport::CurrentAttributes
  attribute :account, :organization, :api_key, :authentication_method, :request_id, :traceparent

  resets do
    RequestStore.clear!
  end
end
