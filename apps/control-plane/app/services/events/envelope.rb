module Events
  class Envelope
    Invalid = Class.new(StandardError)
    CONTRACT_ROOT = Rails.root.join("../..", "contracts").expand_path
    EVENT_SCHEMA_PATH = CONTRACT_ROOT.join("events", "domain-event.schema.json")
    RESOURCE_ID_SCHEMA_PATH = CONTRACT_ROOT.join("jsonschema", "common", "resource-id.schema.json")
    RESOURCE_ID_SCHEMA_URI = "https://contracts.lrail.dev/common/resource-id.schema.json"

    SCHEMER = JSONSchemer.schema(
      JSON.parse(EVENT_SCHEMA_PATH.read),
      ref_resolver: lambda do |uri|
        raise Invalid, "unsupported event schema reference: #{uri}" unless uri.to_s == RESOURCE_ID_SCHEMA_URI

        JSON.parse(RESOURCE_ID_SCHEMA_PATH.read)
      end
    )

    def self.from(event)
      data = JSON.parse(event.data.to_json)
      NoSecrets.validate!(data)

      envelope = {
        "event_id" => event.public_id,
        "event_type" => event.event_type,
        "schema_version" => event.schema_version,
        "occurred_at" => event.occurred_at.utc.iso8601(6),
        "producer" => "control-plane",
        "organization_id" => event.organization_public_id,
        "resource" => {
          "type" => event.resource_type,
          "id" => event.resource_public_id,
          "version" => event.resource_version
        },
        "actor" => {
          "type" => event.actor_type,
          "id" => event.actor_public_id
        },
        "correlation_id" => event.correlation_id,
        "causation_id" => event.causation_id,
        "traceparent" => event.traceparent,
        "data" => data
      }

      validate!(envelope)
      envelope
    end

    def self.validate!(envelope)
      errors = SCHEMER.validate(envelope).to_a
      return envelope if errors.empty?

      details = errors.first(5).map { |error| "#{error.fetch("data_pointer", "/")}: #{error.fetch("type")}" }
      raise Invalid, "invalid domain event: #{details.join(", ")}"
    end
  end
end
