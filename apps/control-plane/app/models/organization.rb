class Organization < ApplicationRecord
  include HasPublicId

  uses_public_id :org

  enum :plan, { free: "free", pro: "pro", enterprise: "enterprise" }, suffix: true

  belongs_to :created_by_account, class_name: "Account"
  has_many :memberships, dependent: :destroy
  has_many :accounts, through: :memberships
  has_many :projects, dependent: :destroy
  has_many :environments, dependent: :destroy
  has_many :services, dependent: :destroy
  has_many :deployments, dependent: :restrict_with_error
  has_many :operations, dependent: :destroy
  has_many :releases, dependent: :restrict_with_error
  has_many :domains, dependent: :restrict_with_error
  has_many :addons, dependent: :restrict_with_error
  has_many :audit_events, dependent: :restrict_with_error
  has_many :usage_ledger, class_name: "UsageLedger", dependent: :restrict_with_error
  has_many :webhooks, dependent: :destroy

  normalizes :slug, with: ->(value) { value.to_s.strip.downcase }

  validates :name, presence: true, length: { maximum: 100 }
  validates :slug, presence: true, uniqueness: true,
    format: { with: /\A[a-z][a-z0-9-]{0,62}\z/ }
end
