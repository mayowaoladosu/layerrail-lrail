module Identity
  class ProvisionPersonalOrganization
    def self.call(account_id:)
      account = Account.find(account_id)
      OrganizationContext.with(account:) do
        existing = account.memberships.active.includes(:organization).first&.organization
        return existing if existing

        organization = Organization.create!(
          created_by_account: account,
          name: "#{account.display_name}'s workspace",
          slug: personal_slug(account),
          plan: "free",
          personal: true,
        )
        OrganizationContext.bind_organization!(organization)
        Membership.create!(account:, organization:, role: "owner", status: "active")
        Current.organization = organization
        organization
      end
    end

    def self.personal_slug(account)
      base = account.email.split("@", 2).first.to_s.parameterize.presence || "workspace"
      suffix = account.public_id.split("-").last.first(6)
      "#{base.first(55)}-#{suffix}"
    end

    private_class_method :personal_slug
  end
end
