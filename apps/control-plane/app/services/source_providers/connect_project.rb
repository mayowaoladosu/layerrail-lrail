module SourceProviders
  class ConnectProject
    Result = Data.define(:binding)

    def self.call(
      account:,
      organization:,
      project:,
      source_connection:,
      repository:,
      production_branch: "main",
      root_directory: "",
      automatic_deployments: true
    )
      Authorization.authorize!(
        account:,
        organization:,
        action: "source.connection.update",
        resource: project,
      )
      unless project.organization_id == organization.id && source_connection.organization_id == organization.id &&
          source_connection.status == "active"
        raise ActiveRecord::RecordNotFound
      end

      binding = ProjectSourceBinding.find_or_initialize_by(project:)
      binding.assign_attributes(
        organization:,
        source_connection:,
        created_by_account: account,
        repository: repository.to_s,
        production_branch: production_branch.to_s,
        root_directory: root_directory.to_s,
        automatic_deployments: ActiveModel::Type::Boolean.new.cast(automatic_deployments),
        generation: binding.persisted? ? binding.generation + 1 : 1,
      )
      binding.save!
      DomainRecorder.record!(
        resource: binding,
        event_type: "source.project.connected",
        action: "source.connection.update",
        actor: account,
        data: {
          project_id: project.public_id,
          source_connection_id: source_connection.public_id,
          repository: binding.repository,
          production_branch: binding.production_branch,
          root_directory: binding.root_directory,
          automatic_deployments: binding.automatic_deployments,
          generation: binding.generation
        },
      )
      Result.new(binding)
    end
  end
end
