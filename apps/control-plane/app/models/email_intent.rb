class EmailIntent < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  belongs_to :account, optional: true

  STATES = %w[pending sending sent delivered retryable bounced complained failed].freeze

  validates :template, :template_version, :recipient, :locale, :idempotency_key, :state,
    presence: true
  validates :state, inclusion: { in: STATES }
  validates :idempotency_key, uniqueness: true

  scope :deliverable, lambda {
    where(state: %w[pending retryable])
      .where("next_attempt_at IS NULL OR next_attempt_at <= ?", Time.current)
  }
end
