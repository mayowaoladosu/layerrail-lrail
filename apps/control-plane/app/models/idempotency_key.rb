class IdempotencyKey < ApplicationRecord
  include OrganizationScoped

  validates :principal_public_id, :http_method, :normalized_route, :key_digest,
    :request_fingerprint, :expires_at, presence: true
end
