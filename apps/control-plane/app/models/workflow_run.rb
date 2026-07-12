class WorkflowRun < ApplicationRecord
  include OrganizationScoped

  STATES = %w[accepted running completed failed canceled].freeze

  validates :workflow_id, :workflow_type, :resource_public_id, :state, presence: true
  validates :workflow_id, uniqueness: true
  validates :state, inclusion: { in: STATES }
end
