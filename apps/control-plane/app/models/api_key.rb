require "ipaddr"

class ApiKey < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :key

  AVAILABLE_SCOPES = %w[
    organization.read organization.write project.read project.write
    deployment.read deployment.write domain.read domain.write addon.read addon.write
    telemetry.read operation.read source.read source.write api_key.read api_key.write
  ].freeze

  belongs_to :account

  validates :name, presence: true, length: { maximum: 100 }
  validates :prefix, presence: true, uniqueness: true, format: { with: /\A[A-Za-z0-9]{12}\z/ }
  validates :secret_digest, presence: true,
    format: { with: %r{\A\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+\z} }
  validate :scopes_are_supported
  validate :constraints_are_supported
  validate :expiry_is_bounded, on: :create

  scope :active, -> { where(revoked_at: nil).where("expires_at IS NULL OR expires_at > ?", Time.current) }

  def allows_scope?(required)
    scopes.include?(required)
  end

  def active?
    revoked_at.nil? && (expires_at.nil? || expires_at.future?)
  end

  private

  def scopes_are_supported
    values = Array(scopes)
    if values.empty? || values.length > 32 || values.uniq.length != values.length || (values - AVAILABLE_SCOPES).any?
      errors.add(:scopes, "contain unsupported or duplicate values")
    end
  end

  def constraints_are_supported
    values = constraints.to_h.stringify_keys
    if (values.keys - [ "ip_cidrs" ]).any?
      errors.add(:constraints, "contain unsupported keys")
      return
    end
    cidrs = Array(values["ip_cidrs"])
    if cidrs.length > 32
      errors.add(:constraints, "contain too many IP ranges")
      return
    end
    if cidrs.uniq.length != cidrs.length
      errors.add(:constraints, "contain duplicate IP ranges")
      return
    end
    cidrs.each { |cidr| IPAddr.new(cidr) }
  rescue IPAddr::InvalidAddressError
    errors.add(:constraints, "contain an invalid IP range")
  end

  def expiry_is_bounded
    return if expires_at.nil?
    unless expires_at > Time.current && expires_at <= 1.year.from_now
      errors.add(:expires_at, "must be in the future and no more than one year away")
    end
  end
end
