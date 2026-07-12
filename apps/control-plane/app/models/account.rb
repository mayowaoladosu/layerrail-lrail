class Account < ApplicationRecord
  include Rodauth::Rails.model
  include HasPublicId

  uses_public_id :acct

  enum :status, { unverified: 1, verified: 2, closed: 3 }

  has_many :memberships, dependent: :destroy
  has_many :organizations, through: :memberships

  normalizes :email, with: ->(value) { value.to_s.strip.downcase }

  validates :email, presence: true
  validates :display_name, presence: true, length: { maximum: 100 }
end
