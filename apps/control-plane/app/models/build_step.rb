class BuildStep < ApplicationRecord
  include OrganizationScoped

  belongs_to :build

  validates :position, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
  validates :name, :state, presence: true
  validates :position, uniqueness: { scope: :build_id }
end
