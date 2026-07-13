class SourceFetch < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :fet

  STATES = %w[authorized fetching complete failed expired canceled].freeze
  REPOSITORY_PATTERN = /\A[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\/[A-Za-z0-9_.-]{1,100}\z/
  COMMIT_PATTERN = /\A[0-9a-f]{40}(?:[0-9a-f]{24})?\z/

  belongs_to :project
  belongs_to :source_connection
  belongs_to :created_by_account, class_name: "Account"
  belongs_to :source_snapshot, optional: true
  belongs_to :project_source_binding, optional: true
  belongs_to :source_provider_delivery, optional: true
  belongs_to :superseded_by_source_fetch, class_name: "SourceFetch", optional: true

  validates :state, inclusion: { in: STATES }
  validates :repository, format: { with: REPOSITORY_PATTERN }
  validates :requested_commit_sha, format: { with: COMMIT_PATTERN }
  validates :resolved_commit_sha, allow_nil: true, format: { with: COMMIT_PATTERN }
  validates :tree_sha, allow_nil: true, format: { with: COMMIT_PATTERN }
  validates :root_directory, length: { maximum: 512 }
  validates :author, allow_nil: true, length: { maximum: 512 }
  validates :policy_version, allow_nil: true, length: { in: 1..128 }
  validates :expires_at, presence: true
  validate :github_connection_is_active, on: :create
  validate :expiry_is_bounded, on: :create
  validate :associations_belong_to_organization
  validate :root_directory_is_canonical
  validate :receipt_evidence_is_bounded

  def terminal?
    state.in?(%w[complete expired canceled])
  end

  private

  def github_connection_is_active
    return unless source_connection
    return if source_connection.provider == "github" && source_connection.status == "active"

    errors.add(:source_connection, "must be an active GitHub installation")
  end

  def expiry_is_bounded
    return unless expires_at
    return if expires_at > Time.current && expires_at <= 30.minutes.from_now

    errors.add(:expires_at, "must be in the future and no more than thirty minutes away")
  end

  def associations_belong_to_organization
    return unless organization_id

    errors.add(:project, "must belong to the organization") if project && project.organization_id != organization_id
    if source_connection && source_connection.organization_id != organization_id
      errors.add(:source_connection, "must belong to the organization")
    end
    if project_source_binding && project_source_binding.organization_id != organization_id
      errors.add(:project_source_binding, "must belong to the organization")
    end
    if source_provider_delivery && source_provider_delivery.organization_id != organization_id
      errors.add(:source_provider_delivery, "must belong to the organization")
    end
  end

  def root_directory_is_canonical
    return if root_directory.blank?

    path = Pathname.new(root_directory)
    if path.absolute? || path.cleanpath.to_s != root_directory || root_directory.include?("\\") || root_directory.include?(":")
      errors.add(:root_directory, "must be a canonical relative path")
    end
  end

  def receipt_evidence_is_bounded
    valid_warnings = warnings.is_a?(Array) && warnings.uniq == warnings && warnings == warnings.sort &&
      warnings.all? { |warning| warning.is_a?(String) && warning.bytesize <= 512 }
    errors.add(:warnings, "must contain sorted unique bounded strings") unless valid_warnings
    errors.add(:submodules, "must be empty until submodule policy is enabled") unless submodules == []
    errors.add(:lfs_digests, "must be empty until LFS policy is enabled") unless lfs_digests == []
  end
end
