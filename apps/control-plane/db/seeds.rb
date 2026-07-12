raise "development seeds are disabled in production" if Rails.env.production?

LOCAL_PASSWORD = "local-development-password"

def seeded_account(email, display_name)
  Account.find_or_create_by!(email:) do |account|
    account.display_name = display_name
    account.status = "verified"
    account.password = LOCAL_PASSWORD
  end
end

def seeded_organization(account, slug, name)
  OrganizationContext.with(account:) do
    organization = Organization.find_by(slug:)
    unless organization
      organization = Organization.create!(
        slug:,
        name:,
        plan: "pro",
        personal: false,
        created_by_account: account,
      )
      OrganizationContext.bind_organization!(organization)
      Membership.create!(account:, organization:, role: "owner", status: "active")
    end
    organization
  end
end

demo = seeded_account("demo@lrail.local", "Demo Operator")
foreign = seeded_account("foreign@lrail.local", "Foreign Tenant")
demo_org = seeded_organization(demo, "northstar-labs", "Northstar Labs")
foreign_org = seeded_organization(foreign, "foreign-systems", "Foreign Systems")

Current.request_id = "req_#{"1" * 32}"

OrganizationContext.with(account: demo, organization: demo_org) do
  unless demo_org.projects.exists?(slug: "checkout-platform")
    result = Projects::Create.call(
      account: demo,
      organization: demo_org,
      attributes: {
        name: "Checkout Platform",
        slug: "checkout-platform",
        description: "Customer checkout, payment orchestration, and receipts."
      },
    )
    project = result.project
    production = project.environments.find_by!(slug: "production")

    web = project.services.create!(
      organization: demo_org,
      name: "Storefront",
      slug: "storefront",
      kind: "web",
      framework: "Next.js",
      health: "healthy",
      build_specification: { "method" => "auto", "manager" => "pnpm" },
      runtime_specification: { "profile" => "small", "region" => "central-us", "replicas" => 3 },
    )
    project.services.create!(
      organization: demo_org,
      name: "Order worker",
      slug: "order-worker",
      kind: "worker",
      framework: "Node.js",
      health: "healthy",
      build_specification: { "method" => "auto", "manager" => "pnpm" },
      runtime_specification: { "profile" => "small", "region" => "central-us", "replicas" => 2 },
    )
    project.services.create!(
      organization: demo_org,
      name: "Receipt API",
      slug: "receipt-api",
      kind: "private_service",
      framework: "Go",
      health: "deploying",
      build_specification: { "method" => "auto" },
      runtime_specification: { "profile" => "nano", "region" => "central-us", "replicas" => 2 },
    )

    connection = SourceConnection.create!(
      organization: demo_org,
      provider: "github",
      installation_external_id: "local-fixture-installation",
      status: "active",
      scopes: [ "contents:read", "metadata:read" ],
    )
    snapshot = SourceSnapshot.create!(
      organization: demo_org,
      project:,
      source_connection: connection,
      kind: "git",
      repository: "northstar/checkout",
      commit_sha: "a1b2c3d4e5f6789012345678901234567890abcd",
      digest: "sha256:#{"a" * 64}",
      object_ref: "local://fixtures/checkout-snapshot",
      size_bytes: 1_048_576,
      retention_until: 30.days.from_now,
    )
    build = Build.create!(
      organization: demo_org,
      source_snapshot: snapshot,
      definition_digest: "sha256:#{"b" * 64}",
      state: "complete",
      network_profile: "packages",
      artifact_digest: "sha256:#{"c" * 64}",
      started_at: 5.minutes.ago,
      completed_at: 3.minutes.ago,
    )
    revision = Revision.create!(
      organization: demo_org,
      service: web,
      build:,
      image_digest: "sha256:#{"c" * 64}",
      manifest_digest: "sha256:#{"d" * 64}",
      sbom_ref: "local://evidence/sbom",
      provenance_ref: "local://evidence/provenance",
      signature_ref: "local://evidence/signature",
      scan_state: "passed",
      policy_state: "accepted",
    )

    deployment_result = Deployments::Create.call(
      account: demo,
      organization: demo_org,
      project:,
      attributes: {
        environment_id: production.public_id,
        manifest_revision: project.manifest_revision,
        reason: "Ship checkout reliability update",
        source: { kind: "git", repository: "northstar/checkout", commit: snapshot.commit_sha }
      },
    )
    deployment = deployment_result.deployment
    deployment.update!(source_snapshot: snapshot, revision:)
    %w[sourcing detecting queued building scanning publishing scheduling starting verifying ready promoted].each do |state|
      Deployments::Transition.call(deployment:, to: state, reason: "local fixture advanced to #{state}", actor: nil)
    end
    deployment.operation.update!(state: "succeeded", stage: "promoted", completed_steps: 11)

    release = Release.create!(
      organization: demo_org,
      service: web,
      environment: production,
      revision:,
      deployment:,
      generation: 1,
      state: "active",
      rollout_policy: "default_canary",
      traffic_weight: 100,
      activated_at: 1.minute.ago,
    )
    web.update!(current_release: release)
    project.update!(status: "healthy")
    production.update!(health: "healthy")

    Domain.create!(
      organization: demo_org,
      project:,
      environment: production,
      service: web,
      hostname: "checkout.localhost",
      mode: "platform_subdomain",
      state: "active",
      verified_at: 2.minutes.ago,
    )
    Addon.create!(
      organization: demo_org,
      project:,
      environment: production,
      name: "orders-postgres",
      engine: "postgresql",
      version_channel: "17",
      topology: "high_availability",
      size_profile: "small",
      storage_profile: "block-fast",
      region: "central-us",
      state: "available",
      deletion_protection: true,
    )
    UsageLedger.create!(
      organization: demo_org,
      meter_type: "compute_cpu_seconds",
      quantity: 3_600,
      unit: "cpu_second",
      period_start: 1.hour.ago,
      period_end: Time.current,
      resource_public_id: web.public_id,
      source_id: "cell-central-us-agent-1",
      source_epoch: "local-seed",
      sequence: 1,
      correlation_id: Current.request_id,
      meter_attributes: { region: "central-us" },
    )
  end
end

OrganizationContext.with(account: foreign, organization: foreign_org) do
  Projects::Create.call(
    account: foreign,
    organization: foreign_org,
    attributes: { name: "Foreign Private App", slug: "foreign-private-app" },
  ) unless foreign_org.projects.exists?(slug: "foreign-private-app")
end

puts "Seeded demo@lrail.local with password #{LOCAL_PASSWORD.inspect}; two-tenant fixtures are ready."
