module OrganizationScoped
  extend ActiveSupport::Concern

  included do
    belongs_to :organization
    validates :organization_id, presence: true
  end
end
