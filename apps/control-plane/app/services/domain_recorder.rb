class DomainRecorder
  def self.record!(resource:, event_type:, action:, actor: Current.account, data: {}, outcome: "succeeded")
    organization = resource.organization
    correlation_id = RequestIdentity.request_id(Current.request_id)
    actor_type = actor ? "account" : "system"
    actor_public_id = actor&.public_id
    version = resource.respond_to?(:lock_version) ? resource.lock_version + 1 : 1
    Events::NoSecrets.validate!(data)

    OutboxEvent.create!(
      organization:,
      organization_public_id: organization.public_id,
      event_type:,
      schema_version: 1,
      resource_type: resource.class.name.underscore,
      resource_public_id: resource.public_id,
      resource_version: version,
      actor_type:,
      actor_public_id:,
      correlation_id:,
      traceparent: Current.traceparent,
      data:,
      occurred_at: Time.current,
    )

    AuditEvent.create!(
      organization:,
      actor_type:,
      actor_public_id:,
      authentication_method: "session",
      action:,
      resource_type: resource.class.name.underscore,
      resource_public_id: resource.public_id,
      after_fingerprint: fingerprint(resource),
      request_id: correlation_id,
      outcome:,
      policy_version: Authorization::POLICY_VERSION,
      occurred_at: Time.current,
      metadata: {},
    )
  end

  def self.fingerprint(resource)
    Digest::SHA256.hexdigest(resource.attributes.except("created_at", "updated_at").to_json)
  end

  private_class_method :fingerprint
end
