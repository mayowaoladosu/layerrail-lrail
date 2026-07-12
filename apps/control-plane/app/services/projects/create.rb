module Projects
  class Create
    Result = Data.define(:project, :operation)

    def self.call(account:, organization:, attributes:)
      decision = Authorization.authorize!(account:, organization:, action: "project.create")

      Project.transaction do
        project = Project.create!(
          organization:,
          slug: attributes.fetch(:slug),
          name: attributes.fetch(:name),
          description: attributes[:description],
          status: "deploying",
          manifest: attributes.fetch(:manifest, {}),
        )
        production = project.environments.create!(
          organization:,
          slug: "production",
          name: "Production",
          protected: true,
          health: "unknown",
        )
        project.environments.create!(
          organization:,
          slug: "preview",
          name: "Preview",
          protected: false,
          health: "unknown",
        )
        operation = Operation.create!(
          organization:,
          resource_type: "project",
          resource_public_id: project.public_id,
          state: "accepted",
          stage: "provisioning",
          total_steps: 3,
          workflow_id: "project/#{project.public_id}/provision/1",
        )
        DomainRecorder.record!(
          resource: project,
          event_type: "project.created",
          action: "project.create",
          data: {
            environment_id: production.public_id,
            operation_id: operation.public_id,
            workflow_id: operation.workflow_id,
            policy_reason: decision.reason
          },
        )
        Result.new(project, operation)
      end
    end
  end
end
