class ApiResource
  class << self
    def organization(value)
      base(value).merge(slug: value.slug, name: value.name, plan: value.plan, personal: value.personal, version: value.lock_version + 1)
    end

    def project(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        slug: value.slug,
        name: value.name,
        description: value.description,
        status: value.status,
        version: value.lock_version + 1,
      )
    end

    def environment(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        name: value.slug,
        protected: value.protected,
        generation: value.generation,
        health: value.health,
      )
    end

    def service(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        slug: value.slug,
        name: value.name,
        kind: value.kind,
        framework: value.framework,
        health: value.health,
        current_release_id: value.current_release&.public_id,
      )
    end

    def deployment(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        environment_id: value.environment.public_id,
        state: value.state,
        source: value.source,
        manifest_revision: value.manifest_revision,
        operation_id: value.operation.public_id,
        revision_id: value.revision&.public_id,
        revision_digest: value.revision&.image_digest,
      )
    end

    def operation(value)
      {
        id: value.public_id,
        state: value.state,
        stage: value.stage,
        waiting_reason: value.waiting_reason,
        progress: { completed: value.completed_steps, total: value.total_steps },
        resource: { type: value.resource_type, id: value.resource_public_id },
        conditions: value.conditions,
        error: value.error_code ? { code: value.error_code, message: value.error_message } : nil,
        created_at: timestamp(value.created_at),
        updated_at: timestamp(value.updated_at)
      }
    end

    def source_snapshot(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        kind: value.kind,
        repository: value.repository,
        commit_sha: value.commit_sha,
        digest: value.digest,
        object_ref: value.object_ref,
        size_bytes: value.size_bytes,
        retention_until: timestamp(value.retention_until),
      )
    end

    def api_key(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        account_id: value.account.public_id,
        name: value.name,
        display_prefix: "lrail_key_#{value.prefix}_…",
        scopes: value.scopes,
        constraints: value.constraints,
        expires_at: timestamp(value.expires_at),
        last_used_at: timestamp(value.last_used_at),
        revoked_at: timestamp(value.revoked_at),
      )
    end

    def domain(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        environment_id: value.environment.public_id,
        hostname: value.hostname,
        mode: value.mode,
        state: value.state,
        conditions: [],
      )
    end

    def addon(value)
      base(value).merge(
        organization_id: value.organization.public_id,
        project_id: value.project.public_id,
        environment_id: value.environment.public_id,
        name: value.name,
        engine: value.engine,
        state: value.state,
        region: value.region,
        deletion_protection: value.deletion_protection,
        conditions: value.conditions,
      )
    end

    private

    def base(value)
      { id: value.public_id, created_at: timestamp(value.created_at), updated_at: timestamp(value.updated_at) }
    end

    def timestamp(value)
      value&.iso8601(6)
    end
  end
end
