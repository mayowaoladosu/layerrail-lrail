class Operation < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :op

  STATES = %w[accepted running waiting retrying succeeded failed canceling canceled].freeze

  validates :resource_type, :resource_public_id, :stage, presence: true
  validates :state, inclusion: { in: STATES }
  validates :completed_steps, :total_steps, numericality: { only_integer: true, greater_than_or_equal_to: 0 }

  has_many :operation_events, dependent: :destroy

  def terminal?
    state.in?(%w[succeeded failed canceled])
  end
end
