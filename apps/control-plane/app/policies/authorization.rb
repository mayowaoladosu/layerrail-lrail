module Authorization
  class Denied < StandardError
    attr_reader :action, :reason

    def initialize(action:, reason:)
      @action = action
      @reason = reason
      super("#{action} denied: #{reason}")
    end
  end

  Decision = Data.define(:allowed, :reason, :role, :policy_version)

  POLICY_VERSION = "2026-07-12.v1"
  ROLE_ACTIONS = {
    "owner" => [ "*" ],
    "admin" => %w[
      organization.read organization.update membership.read membership.invite
      project.* environment.* service.* deployment.* release.* domain.* addon.*
      telemetry.* operation.read webhook.* schedule.*
    ],
    "developer" => %w[
      organization.read project.read project.create environment.read service.read service.update
      deployment.read deployment.create deployment.cancel release.read telemetry.read operation.read
    ],
    "operator" => %w[
      organization.read project.read environment.read service.read deployment.read deployment.cancel
      release.read release.pause release.rollback telemetry.read operation.read addon.read addon.backup
    ],
    "billing" => %w[organization.read usage.read invoice.read billing.update],
    "auditor" => %w[organization.read project.read environment.read service.read deployment.read release.read domain.read addon.read telemetry.read audit.read usage.read]
  }.freeze

  def self.decision(account:, organization:, action:, resource: nil)
    membership = Membership.active.find_by(account:, organization:)
    return Decision.new(false, "membership_missing", nil, POLICY_VERSION) unless membership
    return Decision.new(false, "foreign_resource", membership.role, POLICY_VERSION) if resource&.respond_to?(:organization_id) && resource.organization_id != organization.id

    patterns = ROLE_ACTIONS.fetch(membership.role, [])
    allowed = patterns.any? { |pattern| pattern == "*" || pattern == action || (pattern.end_with?(".*") && action.start_with?(pattern.delete_suffix("*"))) }
    return Decision.new(false, "role_missing_action", membership.role, POLICY_VERSION) unless allowed
    return Decision.new(false, "protected_environment", membership.role, POLICY_VERSION) if protected_action?(action, resource, membership.role)

    Decision.new(true, "allowed", membership.role, POLICY_VERSION)
  end

  def self.authorize!(**arguments)
    decision = decision(**arguments)
    raise Denied.new(action: arguments.fetch(:action), reason: decision.reason) unless decision.allowed

    decision
  end

  def self.protected_action?(action, resource, role)
    environment = resource if resource.is_a?(Environment)
    environment ||= resource.environment if resource&.respond_to?(:environment)
    environment&.protected? && action.in?(%w[release.promote addon.restore domain.transfer]) && !role.in?(%w[owner admin])
  end

  private_class_method :protected_action?
end
