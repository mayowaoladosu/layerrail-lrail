class OrganizationContext
  class MissingContext < StandardError; end

  def self.with(account:, organization: nil, &)
    raise MissingContext, "account is required" unless account

    ApplicationRecord.transaction do
      set_local("lrail.account_id", account.id)
      if organization
        membership = Membership.find_by(account:, organization:, status: "active")
        raise MissingContext, "active organization membership is required" unless membership

        set_local("lrail.organization_id", organization.id)
      end
      Current.set(account:, organization:, &)
    end
  end

  def self.select_for(account:, identifier:, &)
    with(account:) do
      organization = Organization.where(public_id: identifier).or(Organization.where(slug: identifier)).first!
      with(account:, organization:, &)
    end
  end

  def self.bind_organization!(organization)
    raise MissingContext, "organization is required" unless organization

    set_local("lrail.organization_id", organization.id)
    Current.organization = organization
  end

  def self.set_local(name, value)
    quoted_name = ApplicationRecord.connection.quote(name)
    quoted_value = ApplicationRecord.connection.quote(value.to_s)
    ApplicationRecord.connection.execute("SELECT set_config(#{quoted_name}, #{quoted_value}, true)")
  end

  private_class_method :set_local
end
