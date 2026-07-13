class Build < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :bld

  belongs_to :source_snapshot
  belongs_to :deployment, optional: true
  has_many :revisions, dependent: :restrict_with_error
  has_many :build_steps, dependent: :destroy
  has_many :operation_events, dependent: :nullify

  STATES = %w[accepted running waiting retrying canceling complete failed canceled].freeze

  validates :state, :network_profile, presence: true
  validates :state, inclusion: { in: STATES }
  validates :generation, numericality: { only_integer: true, greater_than: 0 }
  validates :definition_digest, format: { with: /\Asha256:[0-9a-f]{64}\z/ }, allow_nil: true
end
