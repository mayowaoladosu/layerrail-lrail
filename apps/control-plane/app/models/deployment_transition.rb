class DeploymentTransition < ApplicationRecord
  include OrganizationScoped

  belongs_to :deployment

  validates :to_state, :reason, :actor_type, :correlation_id, presence: true

  def readonly?
    persisted?
  end
end
