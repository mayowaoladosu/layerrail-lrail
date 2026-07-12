class Environment < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :env

  HEALTH_STATES = %w[healthy degraded deploying paused unknown].freeze

  belongs_to :project
  has_many :deployments, dependent: :restrict_with_error
  has_many :releases, dependent: :restrict_with_error

  normalizes :slug, with: ->(value) { value.to_s.strip.downcase }

  validates :name, presence: true, length: { maximum: 100 }
  validates :slug, presence: true, uniqueness: { scope: :project_id },
    format: { with: /\A[a-z][a-z0-9-]{0,62}\z/ }
  validates :health, inclusion: { in: HEALTH_STATES }
  validates :generation, numericality: { only_integer: true, greater_than: 0 }
end
