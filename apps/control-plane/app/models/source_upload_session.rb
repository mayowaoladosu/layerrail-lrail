class SourceUploadSession < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :upl

  STATES = %w[authorized uploading finalizing complete failed expired canceled].freeze
  MAX_ARCHIVE_BYTES = 1.gigabyte
  MAX_PART_BYTES = 16.megabytes
  MAX_PARTS = 256

  belongs_to :project
  belongs_to :created_by_account, class_name: "Account"
  belongs_to :source_snapshot, optional: true

  validates :state, inclusion: { in: STATES }
  validates :expected_archive_bytes,
    numericality: { only_integer: true, greater_than: 0, less_than_or_equal_to: MAX_ARCHIVE_BYTES }
  validates :expected_parts,
    numericality: { only_integer: true, greater_than: 0, less_than_or_equal_to: MAX_PARTS }
  validates :excluded_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
  validates :expected_archive_sha256, format: { with: /\Asha256:[0-9a-f]{64}\z/ }
  validates :expires_at, presence: true
  validate :part_capacity_covers_archive
  validate :root_directory_is_canonical

  def terminal?
    state.in?(%w[complete expired canceled])
  end

  def effective_state(now: Time.current)
    return "expired" if !terminal? && expires_at.present? && expires_at <= now

    state
  end

  private

  def part_capacity_covers_archive
    return if expected_archive_bytes.blank? || expected_parts.blank?
    return if expected_archive_bytes <= expected_parts * MAX_PART_BYTES

    errors.add(:expected_parts, "cannot carry the declared archive size")
  end

  def root_directory_is_canonical
    return if root_directory.blank?

    path = Pathname.new(root_directory)
    if path.absolute? || path.cleanpath.to_s != root_directory || root_directory.include?("\\") ||
        root_directory.include?(":") || root_directory.bytesize > 512
      errors.add(:root_directory, "must be a canonical relative path")
    end
  end
end
