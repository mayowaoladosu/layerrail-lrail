class Deployment < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :dep

  STATES = %w[
    created sourcing detecting queued building scanning publishing artifact_ready scheduling starting verifying
    ready promoted canceling canceled failed retrying
  ].freeze
  TRANSITIONS = {
    "created" => %w[sourcing retrying canceling failed],
    "sourcing" => %w[detecting retrying canceling failed],
    "detecting" => %w[queued retrying canceling failed],
    "queued" => %w[building retrying canceling failed],
    "building" => %w[scanning retrying canceling failed],
    "scanning" => %w[publishing retrying canceling failed],
    "publishing" => %w[artifact_ready retrying canceling failed],
    "artifact_ready" => %w[scheduling canceling failed],
    "scheduling" => %w[starting canceling failed],
    "starting" => %w[verifying canceling failed],
    "verifying" => %w[ready canceling failed],
    "ready" => %w[promoted],
    "canceling" => %w[canceled failed],
    "failed" => %w[retrying],
    "retrying" => %w[sourcing detecting queued building canceling failed]
  }.freeze

  belongs_to :project
  belongs_to :environment
  belongs_to :source_snapshot, optional: true
  belongs_to :source_fetch, optional: true
  belongs_to :revision, optional: true
  belongs_to :operation
  has_many :deployment_transitions, dependent: :destroy
  has_many :builds, dependent: :restrict_with_error

  validates :state, inclusion: { in: STATES }
  validates :manifest_revision, numericality: { only_integer: true, greater_than: 0 }
  validates :reason, presence: true, length: { maximum: 512 }
  validates :build_mode, inclusion: { in: %w[auto repository] }
  validates :build_file, length: { maximum: 1_024 }, allow_nil: true
  validate :source_is_object
  validate :build_configuration_is_consistent

  def can_transition_to?(target)
    target.to_s.in?(TRANSITIONS.fetch(state, []))
  end

  private

  def source_is_object
    errors.add(:source, "must be an object") unless source.is_a?(Hash)
  end

  def build_configuration_is_consistent
    valid = (build_mode == "auto" && build_file.nil?) ||
      (build_mode == "repository" && build_file.present?)
    errors.add(:build_file, "does not match build mode") unless valid
  end
end
