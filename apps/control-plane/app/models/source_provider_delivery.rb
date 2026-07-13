class SourceProviderDelivery < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  STATES = %w[received processing processed ignored failed].freeze
  EVENTS = %w[push pull_request installation installation_repositories ping].freeze
  DIGEST_PATTERN = /\Asha256:[0-9a-f]{64}\z/
  COMMIT_PATTERN = /\A[0-9a-f]{40}(?:[0-9a-f]{24})?\z/

  belongs_to :source_connection
  has_many :source_fetches, dependent: :restrict_with_error
  has_many :project_source_bindings, foreign_key: :last_provider_delivery_id, dependent: :nullify

  validates :provider, inclusion: { in: %w[github] }
  validates :event_type, inclusion: { in: EVENTS }
  validates :state, inclusion: { in: STATES }
  validates :external_delivery_id, presence: true, length: { maximum: 128 }, uniqueness: { scope: :provider }
  validates :payload_digest, format: { with: DIGEST_PATTERN }
  validates :commit_sha, :base_commit_sha, allow_nil: true, format: { with: COMMIT_PATTERN }
  validates :repository, length: { maximum: 201 }
  validates :ref, length: { maximum: 512 }
  validates :attempt_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
end
