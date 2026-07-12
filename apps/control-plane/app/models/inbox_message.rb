class InboxMessage < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  STATES = %w[processing completed dead_lettered].freeze

  validates :consumer, :event_public_id, :event_type, :schema_version, :subject,
    :payload_digest, :state, :first_received_at, presence: true
  validates :state, inclusion: { in: STATES }
  validates :event_public_id, uniqueness: { scope: :consumer }
end
