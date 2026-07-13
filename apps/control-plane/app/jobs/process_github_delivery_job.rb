class ProcessGithubDeliveryJob < ApplicationJob
  class Busy < StandardError; end
  class Retryable < StandardError; end

  queue_as :source
  retry_on Busy, wait: 30.seconds, attempts: 50
  retry_on Retryable, wait: :polynomially_longer, attempts: 8

  def perform(delivery_public_id, organization_public_id, actor_public_id)
    repository = SourceProviders::GithubDeliveryRepository.new
    processor = SourceProviders::DeliveryProcessor.new
    fetches = []
    preparation_error = nil
    claim_state = nil

    in_context(organization_public_id:, actor_public_id:) do |account, organization|
      claim_state = repository.claim(delivery_public_id:, lease_token: job_id)
      if claim_state == "claimed"
        begin
          delivery = SourceProviderDelivery.find_by!(public_id: delivery_public_id)
          fetches = processor.prepare(account:, organization:, delivery:)
        rescue StandardError => error
          repository.finish(
            delivery_public_id:,
            lease_token: job_id,
            succeeded: false,
            error_code: error.class.name,
          )
          preparation_error = error
        end
      end
    end

    return if claim_state.in?(%w[complete unknown])
    raise Busy, "provider delivery is already leased" if claim_state == "busy"
    if preparation_error
      raise Retryable, "provider preparation failed (#{preparation_error.class.name})"
    end
    raise Retryable, "provider delivery could not be claimed" unless claim_state == "claimed"

    acquisitions = fetches.to_h do |fetch|
      if fetch.state == "complete"
        [ fetch.public_id, { result: nil, error: nil } ]
      else
        begin
          [ fetch.public_id, { result: processor.acquire(fetch), error: nil } ]
        rescue StandardError => error
          [ fetch.public_id, { result: nil, error: } ]
        end
      end
    end

    completion_error = nil
    in_context(organization_public_id:, actor_public_id:) do |account, _organization|
      acquisitions.each do |fetch_public_id, acquisition|
        fetch = SourceFetch.find_by!(public_id: fetch_public_id)
        next if fetch.state == "complete"

        if acquisition.fetch(:error)
          processor.fail(fetch:, error: acquisition.fetch(:error))
          completion_error ||= acquisition.fetch(:error)
          next
        end

        result = processor.complete(fetch:, result: acquisition.fetch(:result), account:)
        completion_error ||= result.error unless result.success?
      rescue StandardError => error
        processor.fail(fetch:, error:) if fetch && !fetch.terminal?
        completion_error ||= error
      end

      finished = repository.finish(
        delivery_public_id:,
        lease_token: job_id,
        succeeded: completion_error.nil?,
        error_code: completion_error&.class&.name,
      )
      completion_error ||= Retryable.new("provider delivery lease was lost") unless finished
    end

    return unless completion_error

    raise Retryable, "provider acquisition failed (#{completion_error.class.name})"
  end

  private

  def in_context(organization_public_id:, actor_public_id:)
    account = Account.find_by!(public_id: actor_public_id)
    OrganizationContext.select_for(account:, identifier: organization_public_id) do |organization|
      yield account, organization
    end
  end
end
