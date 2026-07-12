class OutboxEvent < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  validates :event_type, :resource_type, :resource_public_id, :resource_version,
    :actor_type, :correlation_id, :occurred_at, presence: true

  scope :unpublished, -> { where(published_at: nil).order(:occurred_at, :id) }
  scope :deliverable, lambda {
    unpublished.where(discarded_at: nil)
      .where("next_attempt_at IS NULL OR next_attempt_at <= ?", Time.current)
  }
end
