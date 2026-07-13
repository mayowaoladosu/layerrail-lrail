module SourceProviders
  class ConnectGithubInstallation
    Result = Data.define(:source_connection)

    def self.call(account:, organization:, installation_id:, account_login:, account_id:, repository_selection:, repositories:)
      Authorization.authorize!(
        account:,
        organization:,
        action: "source.connection.update",
        resource: organization,
      )
      installation_id = installation_id.to_s
      raise ActiveRecord::RecordNotFound unless installation_id.match?(/\A[1-9][0-9]{0,19}\z/)

      names = Array(repositories).map { |repository| repository.to_s.strip.downcase }.uniq.sort
      unless names.all? { |repository| SourceFetch::REPOSITORY_PATTERN.match?(repository) }
        raise ActiveRecord::RecordNotFound
      end

      connection = SourceConnection.find_or_initialize_by(
        provider: "github",
        installation_external_id: installation_id,
      )
      if connection.persisted? && connection.organization_id != organization.id
        raise ActiveRecord::RecordNotFound
      end
      connection.assign_attributes(
        organization:,
        connected_by_account: account,
        status: "active",
        scopes: %w[contents:read metadata:read],
        provider_account_login: account_login.to_s,
        provider_account_id: Integer(account_id),
        repository_selection: repository_selection.to_s,
        selected_repositories: names,
        revoked_at: nil,
      )
      connection.save!
      DomainRecorder.record!(
        resource: connection,
        event_type: "source.connection.connected",
        action: "source.connection.update",
        actor: account,
        data: {
          provider: "github",
          provider_account_login: connection.provider_account_login,
          repository_selection: connection.repository_selection,
          repository_count: connection.selected_repositories.length
        },
      )
      Result.new(connection)
    rescue ArgumentError, TypeError, ActiveRecord::RecordNotUnique
      raise ActiveRecord::RecordNotFound
    end
  end
end
