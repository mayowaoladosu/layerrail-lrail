require "json"
require "pathname"
require "securerandom"

raise "M-B lab fixture is disabled in production" if Rails.env.production?

run_id = ENV.fetch("LRAIL_MB_RUN_ID")
raise "LRAIL_MB_RUN_ID is invalid" unless run_id.match?(/\A[0-9a-f]{12}\z/)

output = Pathname(ENV.fetch("LRAIL_MB_FIXTURE_FILE")).expand_path
runtime_root = Rails.root.join("../..", ".work", "mb-lab").expand_path
unless output.to_s.start_with?("#{runtime_root}#{File::SEPARATOR}")
  raise "LRAIL_MB_FIXTURE_FILE must be inside the ignored lab runtime directory"
end

Current.request_id = "req_#{SecureRandom.hex(16)}"
account = Account.create!(
  email: "mb-#{run_id}@lrail.local",
  display_name: "M-B Functional Lab",
  status: "verified",
  password: SecureRandom.urlsafe_base64(24),
)
organization = OrganizationContext.with(account:) do
  created = Organization.create!(
    created_by_account: account,
    slug: "mb-#{run_id}",
    name: "M-B Functional #{run_id}",
    plan: "pro",
    personal: false,
  )
  OrganizationContext.bind_organization!(created)
  Membership.create!(account:, organization: created, role: "owner", status: "active")
  created
end

fixture = OrganizationContext.with(account:, organization:) do
  project = Projects::Create.call(
    account:,
    organization:,
    attributes: {
      name: "Artifact Journey #{run_id}",
      slug: "artifact-#{run_id}",
      description: "Disposable functional source-to-artifact acceptance fixture."
    },
  ).project
  api_key = ApiKeys::Issue.call(
    account:,
    organization:,
    attributes: {
      name: "mb-functional-#{run_id}",
      scopes: %w[source.write deployment.write deployment.read operation.read],
      constraints: {},
      expires_at: 2.hours.from_now
    },
  )
  {
    run_id:,
    account_id: account.public_id,
    organization_id: organization.public_id,
    project_id: project.public_id,
    environment_id: project.environments.find_by!(slug: "preview").public_id,
    manifest_revision: project.manifest_revision,
    api_token: api_key.token,
    api_key_id: api_key.api_key.public_id,
    expires_at: api_key.api_key.expires_at.iso8601(6)
  }
end

output.dirname.mkpath
output.binwrite(JSON.generate(fixture))
File.chmod(0o600, output)
