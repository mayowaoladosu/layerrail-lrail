class SourceConnection < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :src

  PROVIDERS = %w[github].freeze
  STATUSES = %w[active suspended revoked].freeze

  has_many :source_fetches, dependent: :restrict_with_error
  has_many :source_snapshots, dependent: :restrict_with_error
  has_many :source_provider_deliveries, dependent: :restrict_with_error
  has_many :project_source_bindings, dependent: :restrict_with_error
  belongs_to :connected_by_account, class_name: "Account"

  validates :provider, :installation_external_id, :status, presence: true
  validates :provider, inclusion: { in: PROVIDERS }
  validates :status, inclusion: { in: STATUSES }
  validates :installation_external_id, uniqueness: { scope: :provider }, format: { with: /\A[1-9][0-9]{0,19}\z/ }
  validates :provider_account_login, presence: true, length: { maximum: 255 }
  validates :provider_account_id, allow_nil: true, numericality: { only_integer: true, greater_than: 0 }
  validates :repository_selection, inclusion: { in: %w[all selected] }
  validate :scopes_are_read_only
  validate :selected_repositories_are_valid
  validate :connected_by_account_is_member, on: :create

  private

  def scopes_are_read_only
    return if scopes.is_a?(Array) && scopes.uniq == scopes && scopes.all? { |scope| scope.in?(%w[contents:read metadata:read pull_requests:read]) }

    errors.add(:scopes, "must contain only supported read scopes")
  end

  def selected_repositories_are_valid
    valid = selected_repositories.is_a?(Array) && selected_repositories.uniq == selected_repositories &&
      selected_repositories == selected_repositories.sort &&
      selected_repositories.all? { |repository| SourceFetch::REPOSITORY_PATTERN.match?(repository) }
    errors.add(:selected_repositories, "must contain sorted, unique repository names") unless valid
  end

  def connected_by_account_is_member
    return unless organization_id && connected_by_account_id
    return if Membership.active.exists?(organization_id:, account_id: connected_by_account_id)

    errors.add(:connected_by_account, "must be an active organization member")
  end
end
