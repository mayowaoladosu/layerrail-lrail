require "json"
require "openssl"
require "pathname"
require "securerandom"

raise "M-B Git matrix is disabled in production" if Rails.env.production?

fixture_path = Pathname(ENV.fetch("LRAIL_MB_FIXTURE_FILE")).expand_path
runtime_root = Rails.root.join("../..", ".work", "mb-lab").expand_path
unless fixture_path.to_s.start_with?("#{runtime_root}#{File::SEPARATOR}")
  raise "LRAIL_MB_FIXTURE_FILE must be inside the ignored lab runtime directory"
end

fixture = JSON.parse(fixture_path.binread)
repository_name = fixture.fetch("repository")
first_commit = ENV.fetch("LRAIL_MB_GIT_FIRST_COMMIT").downcase
forced_commit = ENV.fetch("LRAIL_MB_GIT_FORCED_COMMIT").downcase
submodule_commit = ENV.fetch("LRAIL_MB_GIT_SUBMODULE_COMMIT").downcase
lfs_commit = ENV.fetch("LRAIL_MB_GIT_LFS_COMMIT").downcase
[ first_commit, forced_commit, submodule_commit, lfs_commit ].each do |commit|
  raise "M-B Git matrix commit is invalid" unless SourceFetch::COMMIT_PATTERN.match?(commit)
end

account = Account.find_by!(public_id: fixture.fetch("account_id"))
result = OrganizationContext.select_for(account:, identifier: fixture.fetch("organization_id")) do |organization|
  project = organization.projects.find_by_public_id!(fixture.fetch("project_id"))
  connection = organization.source_connections.find_by_public_id!(fixture.fetch("source_connection_id"))
  binding = project.project_source_binding
  raise "M-B Git project binding is missing" unless binding&.source_connection_id == connection.id

  processor = SourceProviders::DeliveryProcessor.new
  delivery_repository = SourceProviders::GithubDeliveryRepository.new
  baseline_deployments = project.deployments.count
  delivery_counter = 0

  process_push = lambda do |commit:, before:, forced:, delivery_id:|
    payload = {
      "installation" => { "id" => Integer(connection.installation_external_id) },
      "repository" => { "full_name" => repository_name },
      "ref" => "refs/heads/#{binding.production_branch}",
      "before" => before,
      "after" => commit,
      "forced" => forced,
      "deleted" => false
    }
    body = JSON.generate(payload)
    headers = {
      "x-hub-signature-256" => "sha256=#{OpenSSL::HMAC.hexdigest("SHA256", SourceProviders.webhook_secret, body)}",
      "x-github-delivery" => delivery_id,
      "x-github-event" => "push"
    }
    applied = SourceProviders::GithubWebhook.new.process(raw_body: body, headers:)
    return applied unless applied.work_pending

    delivery_counter += 1
    lease = "mb-git-matrix-#{delivery_counter}-#{SecureRandom.hex(8)}"
    claim = delivery_repository.claim(delivery_public_id: applied.delivery_public_id, lease_token: lease)
    raise "M-B Git delivery was not claimed" unless claim == "claimed"

    delivery = SourceProviderDelivery.find_by!(public_id: applied.delivery_public_id)
    fetches = processor.prepare(account:, organization:, delivery:)
    fetches.each do |fetch|
      acquired = processor.acquire(fetch)
      completed = processor.complete(fetch:, result: acquired, account:)
      raise completed.error unless completed.success?
    end
    finished = delivery_repository.finish(
      delivery_public_id: applied.delivery_public_id,
      lease_token: lease,
      succeeded: true,
    )
    raise "M-B Git delivery completion was not recorded" unless finished

    applied
  end

  first_delivery_id = SecureRandom.uuid
  first = process_push.call(
    commit: first_commit,
    before: "0" * 40,
    forced: false,
    delivery_id: first_delivery_id,
  )
  first_fetch = binding.reload.current_source_fetch
  raise "M-B Git first fetch did not complete" unless first_fetch&.state == "complete"

  replay = process_push.call(
    commit: first_commit,
    before: "0" * 40,
    forced: false,
    delivery_id: first_delivery_id,
  )
  unless replay.outcome == "duplicate" && !replay.work_pending && binding.source_fetches.count == 1
    raise "M-B Git replay created duplicate work"
  end

  forced = process_push.call(
    commit: forced_commit,
    before: first_commit,
    forced: true,
    delivery_id: SecureRandom.uuid,
  )
  forced_fetch = binding.reload.current_source_fetch
  unless forced.outcome == "inserted" && forced_fetch&.state == "complete" &&
      forced_fetch.snapshot_sha256 != first_fetch.snapshot_sha256 &&
      first_fetch.reload.superseded_by_source_fetch_id == forced_fetch.id && first_fetch.superseded_at.present?
    raise "M-B Git force-push divergence or supersession was not proven"
  end

  rejected = {}
  {
    "submodule" => submodule_commit,
    "lfs" => lfs_commit
  }.each do |name, commit|
    attempted = SourceIngestion::Fetch.new.call(
      account:,
      organization:,
      project:,
      source_connection: connection,
      repository: repository_name,
      commit_sha: commit,
      root_directory: binding.root_directory,
    )
    error = attempted.error
    unless !attempted.success? && error.is_a?(SourceIngestion::GatewayClient::Rejected) && error.code == "unsafe_source"
      raise "M-B Git #{name} policy did not fail closed"
    end
    rejected[name] = {
      fetch_id: attempted.fetch.public_id,
      state: attempted.fetch.state,
      code: error.code
    }
  end

  raise "M-B Git source matrix created a deployment" unless project.deployments.count == baseline_deployments

  {
    first: {
      delivery_id: first.delivery_public_id,
      fetch_id: first_fetch.public_id,
      commit: first_fetch.resolved_commit_sha,
      snapshot: first_fetch.snapshot_sha256,
      root_directory: first_fetch.root_directory
    },
    replay: {
      outcome: replay.outcome,
      work_pending: replay.work_pending,
      fetch_count: binding.source_fetches.where(requested_commit_sha: first_commit).count
    },
    forced: {
      delivery_id: forced.delivery_public_id,
      fetch_id: forced_fetch.public_id,
      commit: forced_fetch.resolved_commit_sha,
      snapshot: forced_fetch.snapshot_sha256,
      supersedes: first_fetch.public_id
    },
    rejected:,
    deployment_delta: project.deployments.count - baseline_deployments
  }
end

puts JSON.generate(result)
