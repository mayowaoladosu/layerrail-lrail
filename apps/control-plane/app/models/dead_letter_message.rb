class DeadLetterMessage < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  validates :consumer, :event_public_id, :event_type, :subject, :reason,
    :attempt_count, :first_failed_at, :last_failed_at, presence: true
  validates :event_public_id, uniqueness: { scope: :consumer }
end
