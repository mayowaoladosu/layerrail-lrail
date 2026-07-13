require "ipaddr"

module ApiKeys
  class Authenticate
    Authentication = Data.define(:api_key, :account, :organization)

    def self.call(token:, remote_ip:)
      parsed = ApiKeys.parse(token)
      return nil unless parsed

      row = find_by_prefix(parsed[:prefix])
      digest = row&.fetch("secret_digest") || dummy_digest
      valid = Argon2::Password.verify_password(ApiKeys.keyed_secret(parsed[:secret]), digest)
      return nil unless row && valid

      account = Account.verified.find_by(id: row.fetch("account_id"))
      return nil unless account

      api_key = nil
      organization = nil
      OrganizationContext.with(account:) do
        organization = Organization.find_by(id: row.fetch("organization_id"))
        if organization
          OrganizationContext.with(account:, organization:) do
            api_key = ApiKey.active.find_by(id: row.fetch("key_id"))
          end
        end
      end
      return nil unless api_key && allowed_ip?(api_key, remote_ip)

      Authentication.new(api_key, account, organization)
    rescue ActiveRecord::RecordNotFound, OrganizationContext::MissingContext, Argon2::ArgonHashFail
      nil
    end

    def self.find_by_prefix(prefix)
      quoted = ApplicationRecord.connection.quote(prefix)
      ApplicationRecord.connection.select_one("SELECT * FROM lrail_find_api_key(#{quoted})")
    end

    def self.allowed_ip?(api_key, remote_ip)
      cidrs = Array(api_key.constraints.to_h.stringify_keys["ip_cidrs"])
      return true if cidrs.empty?

      address = IPAddr.new(remote_ip)
      cidrs.any? { |cidr| IPAddr.new(cidr).include?(address) }
    rescue IPAddr::InvalidAddressError
      false
    end

    def self.dummy_digest
      @dummy_digest ||= Argon2::Password.create(ApiKeys.keyed_secret("x" * 43))
    end

    private_class_method :find_by_prefix, :allowed_ip?, :dummy_digest
  end
end
