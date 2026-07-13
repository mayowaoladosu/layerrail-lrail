class ProjectSourceBinding < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :psb

  belongs_to :project
  belongs_to :source_connection
  belongs_to :created_by_account, class_name: "Account"
  belongs_to :current_source_fetch, class_name: "SourceFetch", optional: true
  belongs_to :last_provider_delivery, class_name: "SourceProviderDelivery", optional: true
  has_many :source_fetches, dependent: :restrict_with_error

  normalizes :repository, with: ->(value) { value.to_s.strip.downcase }

  validates :repository, format: { with: SourceFetch::REPOSITORY_PATTERN }
  validates :production_branch, presence: true, length: { maximum: 255 }
  validates :root_directory, length: { maximum: 512 }
  validates :generation, numericality: { only_integer: true, greater_than: 0 }
  validates :project_id, uniqueness: true
  validate :associations_belong_to_organization
  validate :creator_belongs_to_organization, on: :create
  validate :source_connection_authorizes_repository
  validate :production_branch_is_canonical
  validate :root_directory_is_canonical

  private

  def associations_belong_to_organization
    return unless organization_id

    %i[project source_connection created_by_account].each do |association|
      value = public_send(association)
      next unless value.respond_to?(:organization_id)
      next if value.organization_id == organization_id

      errors.add(association, "must belong to the organization")
    end
  end

  def source_connection_authorizes_repository
    return unless source_connection && repository.present?
    return if source_connection.repository_selection == "all"
    return if source_connection.selected_repositories.include?(repository)

    errors.add(:repository, "is not authorized by the source connection")
  end

  def creator_belongs_to_organization
    return unless organization_id && created_by_account_id
    return if Membership.active.exists?(organization_id:, account_id: created_by_account_id)

    errors.add(:created_by_account, "must be an active organization member")
  end

  def production_branch_is_canonical
    value = production_branch.to_s
    invalid = value.blank? || value.start_with?("/", ".") || value.end_with?("/", ".", ".lock") ||
      value.include?("..") || value.include?("@{") || value.match?(/[\x00-\x20~^:?*\[\\]/)
    errors.add(:production_branch, "must be a canonical Git branch") if invalid
  end

  def root_directory_is_canonical
    return if root_directory.blank?

    path = Pathname.new(root_directory)
    if path.absolute? || path.cleanpath.to_s != root_directory || root_directory.include?("\\") || root_directory.include?(":")
      errors.add(:root_directory, "must be a canonical relative path")
    end
  end
end
