class Deployment < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :dep

  STATES = %w[
    created sourcing detecting queued building scanning publishing scheduling starting verifying
    ready promoted canceling canceled failed retrying
  ].freeze
  TRANSITIONS = {
    "created" => %w[sourcing canceling failed],
    "sourcing" => %w[detecting canceling failed],
    "detecting" => %w[queued canceling failed],
    "queued" => %w[building canceling failed],
    "building" => %w[scanning canceling failed],
    "scanning" => %w[publishing canceling failed],
    "publishing" => %w[scheduling canceling failed],
    "scheduling" => %w[starting canceling failed],
    "starting" => %w[verifying canceling failed],
    "verifying" => %w[ready canceling failed],
    "ready" => %w[promoted],
    "canceling" => %w[canceled failed],
    "failed" => %w[retrying],
    "retrying" => %w[queued canceling failed]
  }.freeze

  belongs_to :project
  belongs_to :environment
  belongs_to :source_snapshot, optional: true
  belongs_to :revision, optional: true
  belongs_to :operation
  has_many :deployment_transitions, dependent: :destroy

  validates :state, inclusion: { in: STATES }
  validates :manifest_revision, numericality: { only_integer: true, greater_than: 0 }
  validates :reason, presence: true, length: { maximum: 512 }
  validate :source_is_object

  def can_transition_to?(target)
    target.to_s.in?(TRANSITIONS.fetch(state, []))
  end

  private

  def source_is_object
    errors.add(:source, "must be an object") unless source.is_a?(Hash)
  end
end
