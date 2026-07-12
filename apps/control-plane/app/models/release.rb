class Release < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :rel

  STATES = %w[
    draft policy_check provisioning previewing shifting verifying active paused aborting
    rolled_back superseded retired
  ].freeze

  belongs_to :service
  belongs_to :environment
  belongs_to :revision
  belongs_to :deployment, optional: true

  validates :state, inclusion: { in: STATES }
  validates :generation, numericality: { only_integer: true, greater_than: 0 },
    uniqueness: { scope: %i[service_id environment_id] }
  validates :traffic_weight, numericality: { only_integer: true, in: 0..100 }
end
