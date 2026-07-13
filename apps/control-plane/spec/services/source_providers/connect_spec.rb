require "rails_helper"

RSpec.describe "GitHub source connection commands" do
  it "connects and safely refreshes one installation in its original workspace" do
    account = create_account(email: "connect-owner@example.test")
    organization = create_organization(account:, slug: "connect-owner")

    first = within_organization(account, organization) do
      SourceProviders::ConnectGithubInstallation.call(
        account:,
        organization:,
        installation_id: 6_100_001,
        account_login: "NorthStar",
        account_id: 61,
        repository_selection: "selected",
        repositories: %w[NorthStar/Web NorthStar/API],
      ).source_connection
    end
    first.update!(status: "suspended")
    refreshed = within_organization(account, organization) do
      SourceProviders::ConnectGithubInstallation.call(
        account:,
        organization:,
        installation_id: 6_100_001,
        account_login: "northstar-renamed",
        account_id: 61,
        repository_selection: "selected",
        repositories: %w[northstar/api],
      ).source_connection
    end

    expect(refreshed.id).to eq(first.id)
    expect(refreshed).to have_attributes(
      status: "active",
      connected_by_account_id: account.id,
      provider_account_login: "northstar-renamed",
      selected_repositories: [ "northstar/api" ],
    )
  end

  it "does not expose or rebind an installation already owned by another tenant" do
    account = create_account(email: "connect-first@example.test")
    foreign = create_account(email: "connect-second@example.test")
    organization = create_organization(account:, slug: "connect-first")
    foreign_organization = create_organization(account: foreign, slug: "connect-second")
    within_organization(account, organization) do
      SourceProviders::ConnectGithubInstallation.call(
        account:,
        organization:,
        installation_id: 6_100_002,
        account_login: "first",
        account_id: 62,
        repository_selection: "all",
        repositories: [],
      )
    end

    expect do
      within_organization(foreign, foreign_organization) do
        SourceProviders::ConnectGithubInstallation.call(
          account: foreign,
          organization: foreign_organization,
          installation_id: 6_100_002,
          account_login: "second",
          account_id: 63,
          repository_selection: "all",
          repositories: [],
        )
      end
    end.to raise_error(ActiveRecord::RecordNotFound)
  end

  it "binds only an authorized repository with canonical branch and root values" do
    account = create_account(email: "binding-owner@example.test")
    organization = create_organization(account:, slug: "binding-owner")
    project = within_organization(account, organization) do
      Projects::Create.call(
        account:,
        organization:,
        attributes: { name: "Binding", slug: "binding" },
      ).project
    end
    connection = within_organization(account, organization) do
      SourceProviders::ConnectGithubInstallation.call(
        account:,
        organization:,
        installation_id: 6_100_003,
        account_login: "binding",
        account_id: 64,
        repository_selection: "selected",
        repositories: [ "northstar/allowed" ],
      ).source_connection
    end

    binding = within_organization(account, organization) do
      SourceProviders::ConnectProject.call(
        account:,
        organization:,
        project:,
        source_connection: connection,
        repository: "NorthStar/Allowed",
        production_branch: "release/stable",
        root_directory: "apps/api",
      ).binding
    end
    expect(binding).to have_attributes(
      repository: "northstar/allowed",
      production_branch: "release/stable",
      root_directory: "apps/api",
      automatic_deployments: true,
    )

    expect do
      within_organization(account, organization) do
        SourceProviders::ConnectProject.call(
          account:,
          organization:,
          project:,
          source_connection: connection,
          repository: "northstar/not-selected",
          production_branch: "../main",
          root_directory: "../escape",
        )
      end
    end.to raise_error(ActiveRecord::RecordInvalid)
  end
end
