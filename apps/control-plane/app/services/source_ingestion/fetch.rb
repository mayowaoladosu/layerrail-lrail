module SourceIngestion
  class Fetch
    Result = Data.define(:fetch, :snapshot, :error) do
      def success?
        error.nil?
      end
    end

    def initialize(gateway: SourceIngestion.gateway_client)
      @gateway = gateway
    end

    def call(account:, organization:, project:, source_connection:, repository:, commit_sha:, root_directory: "")
      fetch = authorize(
        account:,
        organization:,
        project:,
        source_connection:,
        repository:,
        commit_sha:,
        root_directory:,
      )
      start(fetch:)
      result = acquire(fetch:)
      complete(fetch:, result:, account:)
    rescue Authorization::Denied, ActiveRecord::RecordNotFound, ActiveRecord::RecordInvalid
      raise
    rescue GatewayClient::Error, FetchResultVerifier::Invalid => error
      fail(fetch:, error:)
    end

    def authorize(
      account:,
      organization:,
      project:,
      source_connection:,
      repository:,
      commit_sha:,
      root_directory: "",
      project_source_binding: nil,
      source_provider_delivery: nil
    )
      Authorization.authorize!(account:, organization:, action: "source.fetch.create", resource: project)
      raise ActiveRecord::RecordNotFound unless source_connection.organization_id == organization.id
      repository = normalize_repository(repository)
      if source_connection.repository_selection == "selected" && !source_connection.selected_repositories.include?(repository)
        raise ActiveRecord::RecordNotFound
      end

      SourceFetch.create!(
        organization:,
        project:,
        source_connection:,
        created_by_account: account,
        project_source_binding:,
        source_provider_delivery:,
        state: "authorized",
        repository:,
        requested_commit_sha: commit_sha.to_s.downcase,
        root_directory: root_directory.to_s,
        expires_at: 15.minutes.from_now,
      )
    end

    def start(fetch:)
      fetch.with_lock do
        return fetch if fetch.state == "complete"
        connection = fetch.source_connection.reload
        authorized_repository = connection.repository_selection == "all" ||
          connection.selected_repositories.include?(fetch.repository)
        unless connection.status == "active" && authorized_repository
          fetch.errors.add(:source_connection, "no longer authorizes this repository")
          raise ActiveRecord::RecordInvalid.new(fetch)
        end
        fetch.expires_at = 15.minutes.from_now if fetch.expires_at <= Time.current

        fetch.update!(state: "fetching", attempt_count: fetch.attempt_count + 1, last_error: nil)
        fetch.association(:organization).load_target
        fetch.association(:project).load_target
        fetch.association(:source_connection).load_target
        fetch.association(:created_by_account).load_target
      end
      fetch
    end

    def acquire(fetch:)
      @gateway.fetch(fetch)
    end

    def complete(fetch:, result:, account:)
      snapshot = persist_result!(fetch:, result:, account:)
      Result.new(fetch.reload, snapshot, nil)
    rescue FetchResultVerifier::Invalid => error
      fail(fetch:, error:)
    end

    def fail(fetch:, error:)
      fetch.update!(state: "failed", last_error: error.class.name.first(2048)) unless fetch.terminal?
      Result.new(fetch.reload, nil, error)
    end

    private

    def persist_result!(fetch:, result:, account:)
      validate_result_scope!(fetch, result)
      SourceSnapshot.transaction do
        snapshot = SourceSnapshot.find_or_initialize_by(
          organization_id: fetch.organization_id,
          project_id: fetch.project_id,
          digest: result.fetch("snapshot_sha256"),
        )
        created = snapshot.new_record?
        if created
          snapshot.assign_attributes(
            organization: fetch.organization,
            project: fetch.project,
            source_connection: fetch.source_connection,
            kind: "git",
            repository: result.fetch("repository"),
            commit_sha: result.fetch("resolved_commit_sha"),
            digest: result.fetch("snapshot_sha256"),
            object_ref: result.fetch("archive_ref"),
            size_bytes: result.fetch("size_bytes"),
            retention_until: 30.days.from_now,
          )
          snapshot.save!
        else
          unless snapshot.object_ref == result.fetch("archive_ref") && snapshot.size_bytes == Integer(result.fetch("size_bytes"))
            raise FetchResultVerifier::Invalid, "immutable source snapshot evidence conflicts"
          end
          snapshot.update!(retention_until: [ snapshot.retention_until, 30.days.from_now ].max)
        end
        fetch.update!(
          state: "complete",
          source_snapshot: snapshot,
          resolved_commit_sha: result.fetch("resolved_commit_sha"),
          tree_sha: result.fetch("tree_sha"),
          snapshot_sha256: result.fetch("snapshot_sha256"),
          manifest_sha256: result.fetch("manifest_sha256"),
          archive_sha256: result.fetch("archive_sha256"),
          manifest_ref: result.fetch("manifest_ref"),
          archive_ref: result.fetch("archive_ref"),
          signing_key_id: result.fetch("_key_id"),
          author: result.fetch("author"),
          authored_at: Time.iso8601(result.fetch("authored_at")),
          policy_version: result.fetch("policy_version"),
          warnings: result.fetch("warnings"),
          submodules: result.fetch("submodules"),
          lfs_digests: result.fetch("lfs_digests"),
          token_expires_at: Time.iso8601(result.fetch("token_expires_at")),
          finalized_at: Time.iso8601(result.fetch("finalized_at")),
          last_error: nil,
        )
        fetch.source_connection.with_lock do
          expirations = [ fetch.source_connection.token_expires_at, fetch.token_expires_at ].compact
          fetch.source_connection.update!(token_expires_at: expirations.max)
        end
        DomainRecorder.record!(
          resource: snapshot,
          event_type: created ? "source.snapshot.created" : "source.snapshot.reused",
          action: created ? "source.snapshot.create" : "source.snapshot.reuse",
          actor: account,
          data: {
            project_id: fetch.project.public_id,
            source_fetch_id: fetch.public_id,
            source_connection_id: fetch.source_connection.public_id,
            provider: fetch.source_connection.provider,
            repository: fetch.repository,
            commit_sha: fetch.resolved_commit_sha,
            tree_sha: fetch.tree_sha,
            manifest_sha256: fetch.manifest_sha256,
            policy_version: result.fetch("policy_version")
          },
        )
        snapshot
      end
    end

    def normalize_repository(value)
      repository = value.to_s.strip
      raise ActiveRecord::RecordNotFound unless SourceFetch::REPOSITORY_PATTERN.match?(repository)

      repository.downcase
    end

    def validate_result_scope!(fetch, result)
      valid = result.fetch("repository").casecmp?(fetch.repository) &&
        result.fetch("requested_commit_sha") == fetch.requested_commit_sha &&
        result.fetch("resolved_commit_sha") == fetch.requested_commit_sha &&
        FetchResultVerifier::COMMIT_PATTERN.match?(result.fetch("tree_sha")) &&
        result.fetch("_key_id").present?
      raise FetchResultVerifier::Invalid, "source fetch result does not match authorization" unless valid
    rescue KeyError, NoMethodError
      raise FetchResultVerifier::Invalid, "source fetch result is incomplete"
    end
  end
end
