class RequestIdentity
  REQUEST_ID_PATTERN = /\Areq_[0-9a-f]{32}\z/
  TRACEPARENT_PATTERN = /\A00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}\z/

  def self.request_id(value)
    candidate = value.to_s.downcase
    return candidate if REQUEST_ID_PATTERN.match?(candidate)

    "req_#{Digest::SHA256.hexdigest(candidate.presence || SecureRandom.hex(32)).first(32)}"
  end

  def self.traceparent(value)
    candidate = value.to_s.downcase
    candidate if TRACEPARENT_PATTERN.match?(candidate)
  end
end
