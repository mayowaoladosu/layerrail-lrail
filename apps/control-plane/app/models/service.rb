class Service < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :svc

  KINDS = %w[web worker private_service static].freeze
  HEALTH_STATES = Environment::HEALTH_STATES

  belongs_to :project
  belongs_to :current_release, class_name: "Release", optional: true
  has_many :revisions, dependent: :restrict_with_error
  has_many :releases, dependent: :restrict_with_error

  normalizes :slug, with: ->(value) { value.to_s.strip.downcase }

  validates :name, presence: true, length: { maximum: 100 }
  validates :slug, presence: true, uniqueness: { scope: :project_id },
    format: { with: /\A[a-z][a-z0-9-]{0,62}\z/ }
  validates :kind, inclusion: { in: KINDS }
  validates :health, inclusion: { in: HEALTH_STATES }
end
