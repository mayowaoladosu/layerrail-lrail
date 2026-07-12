class Revision < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :rev

  belongs_to :service
  belongs_to :build
  has_many :releases, dependent: :restrict_with_error

  validates :image_digest, :manifest_digest, :sbom_ref, :provenance_ref, :signature_ref,
    :scan_state, :policy_state, presence: true
end
