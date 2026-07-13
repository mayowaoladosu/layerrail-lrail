module Deployments
  class Transition
    class InvalidTransition < StandardError; end

    def self.call(deployment:, to:, reason:, actor: Current.account)
      Deployment.transaction do
        deployment.lock!
        raise InvalidTransition, "#{deployment.state} cannot transition to #{to}" unless deployment.can_transition_to?(to)

        from = deployment.state
        deployment.update!(state: to, **terminal_attributes(to))
        DeploymentTransition.create!(
          organization: deployment.organization,
          deployment:,
          from_state: from,
          to_state: to,
          reason:,
          actor_type: actor ? "account" : "system",
          actor_public_id: actor&.public_id,
          correlation_id: Current.request_id.presence || "req_#{SecureRandom.hex(16)}",
          metadata: {},
          created_at: Time.current,
        )
        DomainRecorder.record!(
          resource: deployment,
          event_type: "deployment.#{to}",
          action: "deployment.transition",
          actor:,
          data: { from:, to:, reason:, workflow_id: deployment.operation.workflow_id },
        )
        deployment
      end
    end

    def self.terminal_attributes(state)
      case state.to_s
      when "artifact_ready" then { artifact_ready_at: Time.current }
      when "ready" then { ready_at: Time.current }
      when "promoted" then { promoted_at: Time.current }
      when "canceled" then { canceled_at: Time.current }
      else {}
      end
    end

    private_class_method :terminal_attributes
  end
end
