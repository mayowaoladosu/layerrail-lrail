module Deployments
  class CreateFromGit
    Result = Data.define(:deployment, :operation)
    SOURCE_FIELDS = %w[kind connection_id repository commit root_directory].freeze

    def initialize(fetcher: SourceIngestion::Fetch.new)
      @fetcher = fetcher
    end

    def call(account:, organization:, project:, attributes:)
      source = attributes.fetch(:source).to_h.stringify_keys
      raise ActiveRecord::RecordNotFound unless source["kind"] == "git" && (source.keys - SOURCE_FIELDS).empty?

      connection = organization.source_connections.find_by_public_id!(source.fetch("connection_id"))
      fetch = @fetcher.authorize(
        account:,
        organization:,
        project:,
        source_connection: connection,
        repository: source.fetch("repository"),
        commit_sha: source.fetch("commit"),
        root_directory: source.fetch("root_directory", ""),
      )
      @fetcher.start(fetch:)
      acquired = @fetcher.acquire(fetch:)
      completed = @fetcher.complete(fetch:, result: acquired, account:)
      raise completed.error unless completed.success?
      source = source.merge(
        "connection_id" => connection.public_id,
        "repository" => completed.fetch.repository,
        "commit" => completed.fetch.resolved_commit_sha,
      )

      result = Deployments::Create.call(
        account:,
        organization:,
        project:,
        attributes: attributes.merge(source: source.except("root_directory")),
        source_snapshot: completed.snapshot,
        source_fetch: completed.fetch,
      )
      Result.new(result.deployment, result.operation)
    rescue SourceIngestion::GatewayClient::Error, SourceIngestion::FetchResultVerifier::Invalid => error
      @fetcher.fail(fetch:, error:) if fetch && !fetch.terminal?
      raise
    end
  end
end
