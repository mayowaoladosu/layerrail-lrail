module Deployments
  class Create
    Result = Data.define(:deployment, :operation)

    def self.call(account:, organization:, project:, attributes:)
      Authorization.authorize!(account:, organization:, action: "deployment.create", resource: project)
      environment = project.environments.find_by_public_id!(attributes.fetch(:environment_id))
      source = attributes.fetch(:source).to_h.stringify_keys
      source_snapshot = resolve_source_snapshot!(organization:, project:, source:)

      Deployment.transaction do
        operation_public_id = PlatformId.generate(:op)
        operation = Operation.create!(
          public_id: operation_public_id,
          organization:,
          resource_type: "deployment",
          resource_public_id: "pending:#{operation_public_id}",
          state: "accepted",
          stage: "sourcing",
          total_steps: 11,
        )
        deployment = Deployment.create!(
          organization:,
          project:,
          environment:,
          operation:,
          source_snapshot:,
          source:,
          build_mode: attributes.fetch(:build_mode, "auto"),
          build_file: attributes[:build_file].presence,
          accept_detected: ActiveModel::Type::Boolean.new.cast(attributes.fetch(:accept_detected, false)),
          manifest_revision: attributes.fetch(:manifest_revision),
          reason: attributes.fetch(:reason),
          state: "created",
        )
        DeploymentTransition.create!(
          organization:,
          deployment:,
          to_state: "created",
          reason: attributes.fetch(:reason),
          actor_type: "account",
          actor_public_id: account.public_id,
          correlation_id: Current.request_id.presence || "req_#{SecureRandom.hex(16)}",
          metadata: {},
          created_at: Time.current,
        )
        operation.update!(
          resource_public_id: deployment.public_id,
          workflow_id: "deployment/#{deployment.public_id}/build/1",
        )
        DomainRecorder.record!(
          resource: deployment,
          event_type: "deployment.created",
          action: "deployment.create",
          data: {
            environment_id: environment.public_id,
            operation_id: operation.public_id,
            source_snapshot_id: source_snapshot&.public_id,
            workflow_id: operation.workflow_id
          }.compact,
        )
        Result.new(deployment, operation)
      end
    end

    def self.resolve_source_snapshot!(organization:, project:, source:)
      case source.fetch("kind")
      when "local"
        organization.source_snapshots.where(project:).find_by_public_id!(source.fetch("source_snapshot_id"))
      when "git"
        nil
      else
        raise ActiveRecord::RecordNotFound
      end
    end

    private_class_method :resolve_source_snapshot!
  end
end
