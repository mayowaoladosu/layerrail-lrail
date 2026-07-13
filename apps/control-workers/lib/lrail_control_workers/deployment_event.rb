module LrailControlWorkers
  class DeploymentEvent
    TYPES = %w[deployment.created deployment.canceling].freeze
    ID = /\A[a-z]{2,5}_[0-9a-f-]{36}\z/
    WORKFLOW_ID = %r{\Adeployment/dep_[0-9a-f-]{36}/build/[1-9][0-9]*\z}
    COMMON_KEYS = %w[event_id event_type schema_version organization_id resource actor data].freeze
    CREATED_KEYS = %w[environment_id operation_id source_snapshot_id workflow_id].freeze
    CANCEL_KEYS = %w[from to reason workflow_id].freeze

    attr_reader :value

    def self.parse(value)
      new(value.to_h).tap(&:validate!)
    end

    def initialize(value)
      @value = value
    end

    def created?
      value.fetch("event_type") == "deployment.created"
    end

    def workflow_id
      value.dig("data", "workflow_id")
    end

    def reason
      value.dig("data", "reason") || "user_requested"
    end

    def workflow_input
      {
        "actor_id" => value.dig("actor", "id"),
        "organization_id" => value.fetch("organization_id"),
        "deployment_id" => value.dig("resource", "id"),
        "operation_id" => value.dig("data", "operation_id"),
        "workflow_id" => workflow_id,
        "idempotency_key" => workflow_id,
        "generation" => Integer(workflow_id.split("/").last)
      }
    end

    def validate!
      validate_shape!
      validate_identity!
      validate_data!
      self
    end

    private

    def validate_shape!
      raise ArgumentError, "deployment event is incomplete" unless
        COMMON_KEYS.all? { |key| value.key?(key) }
      raise ArgumentError, "deployment event version is invalid" unless value.fetch("schema_version") == 1
      raise ArgumentError, "deployment event type is unsupported" unless TYPES.include?(value.fetch("event_type"))
    end

    def validate_identity!
      identities = [
        value.fetch("organization_id"),
        value.dig("resource", "id"),
        value.dig("actor", "id")
      ]
      valid = identities.all? { |identity| identity.to_s.match?(ID) } &&
              value.dig("resource", "type") == "deployment" && value.dig("actor", "type") == "account"
      raise ArgumentError, "deployment event identity is invalid" unless valid
    end

    def validate_data!
      data = value.fetch("data").to_h
      allowed = created? ? CREATED_KEYS : CANCEL_KEYS
      raise ArgumentError, "deployment event data contains unknown fields" unless (data.keys - allowed).empty?
      raise ArgumentError, "deployment workflow ID is invalid" unless data.fetch("workflow_id").match?(WORKFLOW_ID)
      return unless created?
      raise ArgumentError, "deployment operation ID is invalid" unless data.fetch("operation_id").match?(ID)
    end
  end
end
