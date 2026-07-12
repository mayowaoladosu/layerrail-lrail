class Project < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :prj

  STATUSES = %w[healthy degraded deploying paused].freeze

  has_many :environments, dependent: :destroy
  has_many :services, dependent: :destroy
  has_many :deployments, dependent: :restrict_with_error
  has_many :domains, dependent: :restrict_with_error
  has_many :addons, dependent: :restrict_with_error

  normalizes :slug, with: ->(value) { value.to_s.strip.downcase }

  validates :name, presence: true, length: { maximum: 100 }
  validates :slug, presence: true, uniqueness: { scope: :organization_id },
    format: { with: /\A[a-z][a-z0-9-]{0,62}\z/ }
  validates :status, inclusion: { in: STATUSES }
  validates :manifest_revision, numericality: { only_integer: true, greater_than: 0 }
end
