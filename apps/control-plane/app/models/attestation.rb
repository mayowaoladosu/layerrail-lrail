class Attestation < ApplicationRecord
  include OrganizationScoped

  KINDS = %w[sbom vulnerability_scan provenance signature policy_decision].freeze
  DIGEST = /\Asha256:[0-9a-f]{64}\z/

  belongs_to :revision

  validates :kind, inclusion: { in: KINDS }
  validates :digest, :payload_digest, :subject_digest, :object_ref,
    :signer_key_id, :signer_key_version, :signer_public_key_digest, :policy_digest,
    presence: true
  validates :digest, :payload_digest, :subject_digest, :signer_public_key_digest,
    :policy_digest, format: { with: DIGEST }
  validates :signer_key_version, numericality: { only_integer: true, greater_than: 0 }
  validates :kind, uniqueness: { scope: :revision_id }
end
