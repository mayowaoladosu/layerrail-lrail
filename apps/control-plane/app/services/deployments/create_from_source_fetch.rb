module Deployments
  class CreateFromSourceFetch
    def self.call(account:, organization:, fetch:)
      raise ActiveRecord::RecordNotFound unless
        fetch.organization_id == organization.id && fetch.state == "complete" && fetch.source_snapshot
      return nil unless deployable?(fetch)

      existing = Deployment.find_by(source_fetch: fetch)
      return existing if existing

      Deployment.transaction do
        fetch.lock!
        existing = Deployment.find_by(source_fetch: fetch)
        return existing if existing
        return nil unless deployable?(fetch)

        delivery = fetch.source_provider_delivery
        environment = fetch.project.environments.find_by!(slug: delivery.event_type == "push" ? "production" : "preview")
        source = {
          kind: "git",
          connection_id: fetch.source_connection.public_id,
          repository: fetch.repository,
          commit: fetch.resolved_commit_sha
        }
        result = Deployments::Create.call(
          account:,
          organization:,
          project: fetch.project,
          attributes: {
            environment_id: environment.public_id,
            source:,
            build_mode: "auto",
            accept_detected: true,
            manifest_revision: fetch.project.manifest_revision,
            reason: delivery.event_type == "push" ? "github_push" : "github_pull_request"
          }
        )
        result.deployment.update!(source_snapshot: fetch.source_snapshot, source_fetch: fetch)
        result.deployment
      end
    rescue ActiveRecord::RecordNotUnique
      Deployment.find_by!(source_fetch: fetch)
    end

    def self.deployable?(fetch)
      return false if fetch.superseded_at || !fetch.project_source_binding&.automatic_deployments

      delivery = fetch.source_provider_delivery
      return false unless delivery&.event_type.in?(%w[push pull_request])
      return fetch.project_source_binding.current_source_fetch_id == fetch.id if delivery.event_type == "push"

      true
    end

    private_class_method :deployable?
  end
end
