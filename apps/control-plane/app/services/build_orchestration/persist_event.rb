module BuildOrchestration
  class PersistEvent
    def self.call(deployment:, build:, event:)
      values = event.to_h.stringify_keys
      raise ArgumentError, "build event identity mismatch" unless
        values.fetch("build_id") == build.public_id &&
        Integer(values.fetch("generation")) == build.generation

      OperationEvent.transaction do
        deployment.operation.lock!
        existing = OperationEvent.find_by(
          operation: deployment.operation,
          generation: build.generation,
          sequence: Integer(values.fetch("sequence")),
        )
        return existing if existing
        sequence = Integer(values.fetch("sequence"))
        expected_sequence = deployment.operation.operation_events
          .where(generation: build.generation).maximum(:sequence).to_i + 1
        raise ArgumentError, "build event sequence is not contiguous" unless sequence == expected_sequence

        occurred_at = Time.iso8601(values.fetch("occurred_at"))
        record = OperationEvent.create!(
          organization: deployment.organization,
          operation: deployment.operation,
          build:,
          generation: build.generation,
          sequence:,
          attempt: Integer(values.fetch("attempt")),
          stage: values.fetch("stage"),
          kind: values.fetch("kind"),
          output: values["output"].presence,
          vertex: values["vertex"].presence,
          name: values["name"].presence,
          current: values["current"],
          total: values["total"],
          cached: values.fetch("cached", false),
          stream: Integer(values.fetch("stream", 0)),
          line: values["line"].presence,
          code: values["code"].presence,
          message: values["message"].presence,
          occurred_at:,
        )
        update_progress!(deployment:, build:, values:, occurred_at:)
        record
      end
    rescue KeyError, TypeError, ArgumentError
      raise ArgumentError, "build event contract is invalid"
    end

    def self.update_progress!(deployment:, build:, values:, occurred_at:)
      stage = values.fetch("stage")
      build_state = case stage
      when "retrying" then "retrying"
      when "canceling" then "canceling"
      when "complete", "failed", "canceled" then build.state
      else "running"
      end
      build.update!(
        state: build_state,
        started_at: build.started_at || occurred_at,
      ) unless build.state.in?(%w[complete failed canceled waiting])

      target = DEPLOYMENT_STAGE.fetch(stage, nil)
      transition_to!(deployment, target) if target
      deployment.operation.update!(
        state: stage == "retrying" ? "retrying" : deployment.operation.state == "canceling" ? "canceling" : "running",
        stage: target || stage,
        completed_steps: [ deployment.operation.completed_steps, completed_steps(stage) ].max,
      ) unless deployment.operation.terminal?
    end

    DEPLOYMENT_STAGE = {
      "materializing" => "sourcing",
      "detecting" => "detecting",
      "compiling" => "queued",
      "assigning" => "queued",
      "assigned" => "building",
      "resuming" => "building",
      "resolving" => "building",
      "allocating" => "building",
      "solving" => "building",
      "exporting" => "publishing",
      "retrying" => "retrying",
      "canceling" => "canceling"
    }.freeze

    def self.completed_steps(stage)
      %w[accepted materializing detecting compiling assigning assigned solving exporting].index(stage).to_i
    end

    def self.transition_to!(deployment, target)
      while deployment.state != target
        next_state = Deployment::TRANSITIONS.fetch(deployment.state, []).find do |candidate|
          candidate == target || path_to?(candidate, target)
        end
        break unless next_state

        Deployments::Transition.call(deployment:, to: next_state, reason: "build_orchestration", actor: nil)
      end
    end

    def self.path_to?(from, target, seen = [])
      return true if from == target
      return false if seen.include?(from) || from.in?(%w[canceling canceled failed artifact_ready ready promoted])

      Deployment::TRANSITIONS.fetch(from, []).any? { |candidate| path_to?(candidate, target, [ *seen, from ]) }
    end

    private_class_method :update_progress!, :completed_steps, :transition_to!, :path_to?
  end
end
