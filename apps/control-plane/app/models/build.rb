class Build < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :bld

  belongs_to :source_snapshot
  has_many :revisions, dependent: :restrict_with_error

  validates :definition_digest, :state, :network_profile, presence: true
end
