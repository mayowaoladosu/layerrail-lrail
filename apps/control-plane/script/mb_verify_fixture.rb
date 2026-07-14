require "json"
require "pathname"

raise "M-B verification is disabled in production" if Rails.env.production?

fixture_path = Pathname(ENV.fetch("LRAIL_MB_FIXTURE_FILE")).expand_path
runtime_root = Rails.root.join("../..", ".work", "mb-lab").expand_path
unless fixture_path.to_s.start_with?("#{runtime_root}#{File::SEPARATOR}")
  raise "LRAIL_MB_FIXTURE_FILE must be inside the ignored lab runtime directory"
end

fixture = JSON.parse(fixture_path.binread)
account = Account.find_by!(public_id: fixture.fetch("account_id"))
result = OrganizationContext.select_for(account:, identifier: fixture.fetch("organization_id")) do |organization|
  project = organization.projects.find_by_public_id!(fixture.fetch("project_id"))
  deployment = if ENV["LRAIL_MB_DEPLOYMENT_ID"].present?
    project.deployments.find_by_public_id!(ENV.fetch("LRAIL_MB_DEPLOYMENT_ID"))
  else
    project.deployments.where(state: "artifact_ready").order(created_at: :desc).first!
  end
  build = deployment.builds.find_by!(generation: deployment.generation)
  revision = build.revisions.sole
  events = deployment.operation.operation_events.where(generation: build.generation).order(:sequence)
  sequences = events.pluck(:sequence)
  expected_sequences = (1..sequences.last).to_a
  attestations = revision.attestations.order(:kind)
  kinds = attestations.pluck(:kind)

  failures = []
  failures << "deployment state" unless deployment.state == "artifact_ready" && deployment.artifact_ready_at.present?
  failures << "operation state" unless deployment.operation.state == "succeeded" && deployment.operation.stage == "artifact_ready"
  failures << "build state" unless build.state == "complete" && build.cleanup_state == "clean" && build.error_code.nil?
  failures << "build identity" unless build.source_snapshot_id == deployment.source_snapshot_id && build.logs_digest.present?
  failures << "event sequence" unless sequences == expected_sequences
  failures << "event attempts" unless events.pluck(:attempt).all?(&:positive?)
  failures << "revision identity" unless deployment.revision_id == revision.id && revision.image_digest == build.artifact_digest
  failures << "attestation kinds" unless kinds == Attestation::KINDS.sort
  failures << "attestation subjects" unless attestations.pluck(:subject_digest).uniq == [ revision.manifest_digest ]
  failures << "attestation references" unless attestations.all? do |attestation|
    attestation.object_ref.end_with?("@#{attestation.digest}") && attestation.payload_digest.match?(Attestation::DIGEST)
  end
  expected_git_commit = ENV["LRAIL_MB_EXPECTED_GIT_COMMIT"]&.downcase
  expected_git_repository = ENV["LRAIL_MB_EXPECTED_GIT_REPOSITORY"]&.downcase
  expected_git_root = ENV["LRAIL_MB_EXPECTED_GIT_ROOT"]
  if expected_git_commit.present? || expected_git_repository.present? || expected_git_root.present?
    source_fetch = deployment.source_fetch
    failures << "Git expectation set" unless expected_git_commit&.match?(SourceFetch::COMMIT_PATTERN) &&
      expected_git_repository&.match?(SourceFetch::REPOSITORY_PATTERN) && expected_git_root.present?
    failures << "Git fetch state" unless source_fetch&.state == "complete"
    failures << "Git commit" unless source_fetch&.requested_commit_sha == expected_git_commit &&
      source_fetch&.resolved_commit_sha == expected_git_commit
    failures << "Git repository" unless source_fetch&.repository&.downcase == expected_git_repository
    failures << "Git root" unless source_fetch&.root_directory == expected_git_root
    failures << "Git snapshot" unless source_fetch&.source_snapshot_id == deployment.source_snapshot_id &&
      source_fetch&.source_snapshot_id == build.source_snapshot_id
  end
  failures << "release boundary" unless revision.releases.none?
  raise "M-B artifact verification failed: #{failures.join(", ")}" if failures.any?

  forbidden_tables = %w[target_bundles routes runtimes runtime_workloads workloads].to_h do |table|
    count = if ActiveRecord::Base.connection.data_source_exists?(table)
      ActiveRecord::Base.connection.select_value("SELECT COUNT(*) FROM #{table}").to_i
    else
      0
    end
    [ table, count ]
  end
  raise "M-B runtime boundary was crossed" unless forbidden_tables.values.all?(&:zero?)

  git_source = if deployment.source_fetch
    {
      fetch_id: deployment.source_fetch.public_id,
      repository: deployment.source_fetch.repository,
      requested_commit: deployment.source_fetch.requested_commit_sha,
      resolved_commit: deployment.source_fetch.resolved_commit_sha,
      tree_sha: deployment.source_fetch.tree_sha,
      root_directory: deployment.source_fetch.root_directory,
      snapshot_digest: deployment.source_snapshot.digest
    }
  end

  {
    deployment_id: deployment.public_id,
    deployment_state: deployment.state,
    operation_id: deployment.operation.public_id,
    operation_state: deployment.operation.state,
    operation_stage: deployment.operation.stage,
    build_id: build.public_id,
    build_state: build.state,
    cleanup_state: build.cleanup_state,
    worker_identity: build.worker_identity,
    logs_digest: build.logs_digest,
    event_count: sequences.length,
    first_sequence: sequences.first,
    last_sequence: sequences.last,
    sequence_gaps: expected_sequences - sequences,
    attempts: events.pluck(:attempt).uniq.sort,
    revision_id: revision.public_id,
    revision_count: build.revisions.count,
    image_digest: revision.image_digest,
    manifest_digest: revision.manifest_digest,
    scan_state: revision.scan_state,
    policy_state: revision.policy_state,
    attestation_count: attestations.count,
    attestation_kinds: kinds,
    release_count: revision.releases.count,
    git_source:,
    forbidden_tables:
  }
end

puts JSON.generate(result)
