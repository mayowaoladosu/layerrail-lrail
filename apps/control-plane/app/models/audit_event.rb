class AuditEvent < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  validates :actor_type, :action, :resource_type, :resource_public_id, :request_id,
    :outcome, :policy_version, :occurred_at, presence: true

  def readonly?
    persisted?
  end
end
