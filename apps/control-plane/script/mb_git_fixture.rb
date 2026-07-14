require "json"
require "pathname"

raise "M-B Git fixture is disabled in production" if Rails.env.production?

fixture_path = Pathname(ENV.fetch("LRAIL_MB_FIXTURE_FILE")).expand_path
runtime_root = Rails.root.join("../..", ".work", "mb-lab").expand_path
unless fixture_path.to_s.start_with?("#{runtime_root}#{File::SEPARATOR}")
  raise "LRAIL_MB_FIXTURE_FILE must be inside the ignored lab runtime directory"
end

repository = ENV.fetch("LRAIL_MB_GITHUB_REPOSITORY").strip.downcase
installation_id = ENV.fetch("LRAIL_MB_GITHUB_INSTALLATION_ID")
account_login = ENV.fetch("LRAIL_MB_GITHUB_ACCOUNT_LOGIN")
account_id = Integer(ENV.fetch("LRAIL_MB_GITHUB_ACCOUNT_ID"))
production_branch = ENV.fetch("LRAIL_MB_GITHUB_BRANCH", "main")
root_directory = ENV.fetch("LRAIL_MB_GITHUB_ROOT", "")
fixture = JSON.parse(fixture_path.binread)

account = Account.find_by!(public_id: fixture.fetch("account_id"))
OrganizationContext.select_for(account:, identifier: fixture.fetch("organization_id")) do |organization|
  project = organization.projects.find_by_public_id!(fixture.fetch("project_id"))
  connection = SourceProviders::ConnectGithubInstallation.call(
    account:,
    organization:,
    installation_id:,
    account_login:,
    account_id:,
    repository_selection: "selected",
    repositories: [ repository ],
  ).source_connection
  binding = SourceProviders::ConnectProject.call(
    account:,
    organization:,
    project:,
    source_connection: connection,
    repository:,
    production_branch:,
    root_directory:,
  ).binding
  fixture.merge!(
    "source_connection_id" => connection.public_id,
    "project_source_binding_id" => binding.public_id,
    "repository" => binding.repository,
    "production_branch" => binding.production_branch,
    "root_directory" => binding.root_directory,
  )
end

fixture_path.binwrite(JSON.generate(fixture))
File.chmod(0o600, fixture_path)
puts JSON.generate(fixture.slice(
  "organization_id",
  "project_id",
  "source_connection_id",
  "project_source_binding_id",
  "repository",
  "production_branch",
  "root_directory",
))
