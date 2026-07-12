require "rails_helper"

RSpec.describe Idempotency::Execute do
  it "replays the committed result without executing the command twice" do
    account = create_account
    organization = create_organization(account:)
    executions = 0

    within_organization(account, organization) do
      arguments = {
        key: "test-idempotency-key-0001",
        principal: account,
        organization:,
        http_method: "POST",
        route: "/v1/projects",
        payload: { name: "API", nested: { b: 2, a: 1 } }
      }
      first = described_class.call(**arguments) do
        executions += 1
        [ 202, { data: { id: "prj_test" } } ]
      end
      replay = described_class.call(**arguments.merge(payload: { nested: { a: 1, b: 2 }, name: "API" })) do
        executions += 1
        [ 500, {} ]
      end

      expect(first.replayed).to be(false)
      expect(replay.replayed).to be(true)
      expect(replay.body).to eq("data" => { "id" => "prj_test" })
      expect(executions).to eq(1)
    end
  end

  it "rejects reuse with different input" do
    account = create_account
    organization = create_organization(account:)

    within_organization(account, organization) do
      base = {
        key: "test-idempotency-key-0002",
        principal: account,
        organization:,
        http_method: "POST",
        route: "/v1/projects"
      }
      described_class.call(**base, payload: { name: "A" }) { [ 201, { data: {} } ] }
      expect do
        described_class.call(**base, payload: { name: "B" }) { [ 201, { data: {} } ] }
      end.to raise_error(Idempotency::Mismatch)
    end
  end
end
