class SourceSnapshot < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :snp

  belongs_to :project
  belongs_to :source_connection, optional: true
  has_many :builds, dependent: :restrict_with_error

  validates :kind, :digest, :object_ref, :retention_until, presence: true
  validates :size_bytes, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
end
