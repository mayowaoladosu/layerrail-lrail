class SourceConnection < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :src

  validates :provider, :installation_external_id, :status, presence: true
end
