module SourceProviders
  class DeliveryProcessor
    def initialize(fetcher: SourceIngestion::Fetch.new)
      @fetcher = fetcher
    end

    def prepare(account:, organization:, delivery:)
      raise ActiveRecord::RecordNotFound unless delivery.organization_id == organization.id
      raise ArgumentError, "provider delivery is not leased" unless delivery.state == "processing"
      return [] unless delivery.event_type.in?(%w[push pull_request]) && delivery.commit_sha.present?

      ProjectSourceBinding.where(
        source_connection_id: delivery.source_connection_id,
        repository: delivery.repository,
        automatic_deployments: true,
      ).order(:id).filter_map do |binding|
        prepare_binding(account:, organization:, delivery:, binding:)
      end
    end

    def acquire(fetch)
      @fetcher.acquire(fetch:)
    end

    def complete(fetch:, result:, account:)
      @fetcher.complete(fetch:, result:, account:)
    end

    def fail(fetch:, error:)
      @fetcher.fail(fetch:, error:)
    end

    private

    def prepare_binding(account:, organization:, delivery:, binding:)
      binding.with_lock do
        if delivery.event_type == "push"
          prepare_push_binding(account:, organization:, delivery:, binding:)
        else
          prepare_pull_request_binding(account:, organization:, delivery:, binding:)
        end
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end

    def prepare_push_binding(account:, organization:, delivery:, binding:)
      return if newer_delivery?(binding.last_provider_delivery, delivery)
      return unless delivery.ref == "refs/heads/#{binding.production_branch}"

      if binding.current_source_fetch&.state == "complete" &&
          binding.current_source_fetch.requested_commit_sha == delivery.commit_sha
        binding.update!(last_provider_delivery: delivery, current_ref: delivery.ref)
        return binding.current_source_fetch
      end

      fetch = fetch_for(binding:, delivery:) || authorize_fetch(account:, organization:, delivery:, binding:)
      unless binding.current_source_fetch_id == fetch.id
        supersede(binding.current_source_fetch, with: fetch)
        binding.update!(
          current_source_fetch: fetch,
          last_provider_delivery: delivery,
          current_ref: delivery.ref,
          requested_commit_sha: delivery.commit_sha,
          generation: binding.generation + 1,
        )
      end
      @fetcher.start(fetch:)
    end

    def prepare_pull_request_binding(account:, organization:, delivery:, binding:)
      prior_fetches = binding.source_fetches.joins(:source_provider_delivery).where(
        source_provider_deliveries: {
          event_type: "pull_request",
          pull_request_number: delivery.pull_request_number
        },
      ).where.not(source_provider_delivery_id: delivery.id)
      latest = prior_fetches.order("source_provider_deliveries.created_at DESC", "source_provider_deliveries.id DESC").first
      return if latest && newer_delivery?(latest.source_provider_delivery, delivery)
      return latest if latest&.state == "complete" && latest.requested_commit_sha == delivery.commit_sha

      fetch = fetch_for(binding:, delivery:) || authorize_fetch(account:, organization:, delivery:, binding:)
      supersede(latest, with: fetch)
      @fetcher.start(fetch:)
    end

    def fetch_for(binding:, delivery:)
      SourceFetch.find_by(project_source_binding: binding, source_provider_delivery: delivery)
    end

    def authorize_fetch(account:, organization:, delivery:, binding:)
      @fetcher.authorize(
        account:,
        organization:,
        project: binding.project,
        source_connection: binding.source_connection,
        repository: delivery.repository,
        commit_sha: delivery.commit_sha,
        root_directory: binding.root_directory,
        project_source_binding: binding,
        source_provider_delivery: delivery,
      )
    end

    def supersede(previous, with:)
      return unless previous && previous.id != with.id && previous.superseded_at.nil?

      previous.update!(superseded_by_source_fetch: with, superseded_at: Time.current)
    end

    def newer_delivery?(current, candidate)
      return false unless current

      ([ current.created_at, current.id ] <=> [ candidate.created_at, candidate.id ]) == 1
    end
  end
end
