module Inbox
  class ActorContextResolver
    UnsupportedActor = Class.new(StandardError)

    def self.call(organization_id, envelope)
      actor = envelope.fetch("actor")
      unless actor.fetch("type") == "account" && actor.fetch("id").present?
        raise UnsupportedActor, "event actor cannot establish organization context"
      end

      account = Account.find_by!(public_id: actor.fetch("id"))
      organization = nil
      OrganizationContext.select_for(account:, identifier: organization_id) { |resolved| organization = resolved }
      [ account, organization ]
    end
  end
end
