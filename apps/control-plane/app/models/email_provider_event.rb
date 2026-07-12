class EmailProviderEvent < ApplicationRecord
  validates :provider_event_id, :event_type, :payload_digest, :outcome, :received_at, presence: true
  validates :provider_event_id, uniqueness: true
end
