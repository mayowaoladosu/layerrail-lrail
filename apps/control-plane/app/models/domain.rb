class Domain < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :dom

  STATES = %w[
    requested challenge_pending verified dns_pending certificate_pending active renewing suspended
    revalidating expired detaching released
  ].freeze
  MODES = %w[external_dns delegated_zone registered platform_subdomain].freeze

  belongs_to :project
  belongs_to :environment
  belongs_to :service

  normalizes :hostname, with: ->(value) { value.to_s.strip.downcase.delete_suffix(".") }

  validates :hostname, presence: true, length: { maximum: 253 }
  validates :state, inclusion: { in: STATES }
  validates :mode, inclusion: { in: MODES }
end
