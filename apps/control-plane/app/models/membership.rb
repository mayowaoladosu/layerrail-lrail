class Membership < ApplicationRecord
  include HasPublicId

  uses_public_id :mbr

  ROLES = %w[owner admin developer operator billing auditor].freeze
  STATUSES = %w[active suspended revoked].freeze

  belongs_to :account
  belongs_to :organization

  validates :role, inclusion: { in: ROLES }
  validates :status, inclusion: { in: STATUSES }
  validates :account_id, uniqueness: { scope: :organization_id }

  scope :active, -> { where(status: "active") }
  scope :owners, -> { active.where(role: "owner") }
end
