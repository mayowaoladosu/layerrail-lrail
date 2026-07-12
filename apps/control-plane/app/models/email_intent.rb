class EmailIntent < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :evt

  belongs_to :account, optional: true

  validates :template, :template_version, :recipient, :locale, :idempotency_key, :state,
    presence: true
end
