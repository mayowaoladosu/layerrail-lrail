module Deployments
  class Create
    Result = Data.define(:deployment, :operation)

    def self.call(account:, organization:, project:, attributes:, source_snapshot: nil, source_fetch: nil)
      Authorization.authorize!(account:, organization:, action: "deployment.create", resource: project)
      environment = project.environments.find_by_public_id!(attributes.fetch(:environment_id))
      source = attributes.fetch(:source).to_h.stringify_keys
      source_snapshot = resolve_source_snapshot!(organization:, project:, source:, source_snapshot:, source_fetch:)

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
          source_fetch:,
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

    def self.resolve_source_snapshot!(organization:, project:, source:, source_snapshot:, source_fetch:)
      case source.fetch("kind")
      when "local"
        raise ActiveRecord::RecordNotFound unless source.keys.sort == %w[kind source_snapshot_id]

        resolved = organization.source_snapshots.where(project:).find_by_public_id!(source.fetch("source_snapshot_id"))
        raise ActiveRecord::RecordNotFound if source_fetch || (source_snapshot && source_snapshot != resolved)

        resolved
      when "git"
        valid = source.keys.sort == %w[commit connection_id kind repository] && source_snapshot&.kind == "git" &&
          source_snapshot.organization_id == organization.id &&
          source_snapshot.project_id == project.id && source_fetch&.state == "complete" &&
          source_fetch.organization_id == organization.id && source_fetch.project_id == project.id &&
          source_fetch.source_snapshot_id == source_snapshot.id && source_fetch.source_connection.public_id == source.fetch("connection_id") &&
          source_fetch.repository == source.fetch("repository") && source_fetch.resolved_commit_sha == source.fetch("commit") &&
          source_snapshot.source_connection_id == source_fetch.source_connection_id && source_snapshot.repository == source.fetch("repository") &&
          source_snapshot.commit_sha == source.fetch("commit")
        raise ActiveRecord::RecordNotFound unless valid

        source_snapshot
      else
        raise ActiveRecord::RecordNotFound
      end
    end

    private_class_method :resolve_source_snapshot!
  end
end
