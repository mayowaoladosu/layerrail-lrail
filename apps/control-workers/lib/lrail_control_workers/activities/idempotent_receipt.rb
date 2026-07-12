require "temporalio/activity"

module LrailControlWorkers
  module Activities
    class IdempotentReceipt < Temporalio::Activity::Definition
      activity_name "lrail.project.record_provisioning.v1"

      def execute(input)
        idempotency_key = input.fetch("idempotency_key")
        resource_id = input.fetch("project_id")
        unless idempotency_key.match?(%r{\Aproject/prj_[0-9a-f-]{36}/provision/\d+\z})
          raise ArgumentError, "invalid idempotency key"
        end
        raise ArgumentError, "invalid project ID" unless resource_id.match?(/\Aprj_[0-9a-f-]{36}\z/)

        {
          "idempotency_key" => idempotency_key,
          "project_id" => resource_id,
          "recorded" => true
        }
      end
    end
  end
end
