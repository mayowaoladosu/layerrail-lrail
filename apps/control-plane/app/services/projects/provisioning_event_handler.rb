module Projects
  class ProvisioningEventHandler
    def self.call(envelope)
      raise ArgumentError, "unsupported event" unless envelope.fetch("event_type") == "project.created"

      project = Project.find_by!(public_id: envelope.dig("resource", "id"))
      operation = provisioning_operation(project:, public_id: envelope.dig("data", "operation_id"))
      workflow_id = envelope.dig("data", "workflow_id") || operation.workflow_id
      raise ArgumentError, "operation does not belong to project" unless operation.resource_public_id == project.public_id
      raise ArgumentError, "workflow ID does not match operation" unless workflow_id == operation.workflow_id
      return operation if operation.terminal?

      workflow = WorkflowRun.find_or_initialize_by(workflow_id:)
      workflow.assign_attributes(
        organization: project.organization,
        workflow_type: "project.provisioning.v1",
        resource_public_id: project.public_id,
        state: "completed",
        run_id: envelope.fetch("event_id"),
        started_at: workflow.started_at || Time.current,
        completed_at: Time.current,
      )
      workflow.save!
      operation.update!(state: "succeeded", stage: "provisioned", completed_steps: operation.total_steps)
      project.update!(status: "healthy")
      DomainRecorder.record!(
        resource: project,
        event_type: "project.provisioned",
        action: "project.provision.complete",
        actor: nil,
        data: { operation_id: operation.public_id, workflow_id: },
      )
      operation
    end

    def self.provisioning_operation(project:, public_id:)
      return Operation.find_by!(public_id:) if public_id.present?

      Operation.find_by!(
        resource_type: "project",
        resource_public_id: project.public_id,
        stage: "provisioning",
      )
    end

    private_class_method :provisioning_operation
  end
end
