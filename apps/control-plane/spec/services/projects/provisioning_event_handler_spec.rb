require "rails_helper"

RSpec.describe Projects::ProvisioningEventHandler do
  it "completes the accepted operation and records one workflow effect" do
    account = create_account
    organization = create_organization(account:)
    result = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Provision", slug: "provision" })
    end
    event = within_organization(account, organization) { OutboxEvent.find_by!(event_type: "project.created") }
    envelope = Events::Envelope.from(event)
    processor = Inbox::Processor.new(
      consumer: "project-provisioner-v1",
      context_resolver: Inbox::ActorContextResolver.method(:call),
      handler: described_class.method(:call),
    )

    first = processor.process(envelope:, subject: "lrail.domain.v1.project.created")
    second = processor.process(envelope:, subject: "lrail.domain.v1.project.created")

    expect(first.outcome).to eq(:processed)
    expect(second.outcome).to eq(:duplicate)
    expect(result.project.reload.status).to eq("healthy")
    expect(result.operation.reload).to have_attributes(state: "succeeded", stage: "provisioned", completed_steps: 3)
    expect(WorkflowRun.find_by!(workflow_id: result.operation.workflow_id)).to have_attributes(
      state: "completed",
      resource_public_id: result.project.public_id,
    )
    expect(OutboxEvent.where(event_type: "project.provisioned").count).to eq(1)
  end
end
