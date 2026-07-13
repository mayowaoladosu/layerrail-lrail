require "base64"
require "openssl"
require "argon2"

module ApiKeys
  LOCAL_PEPPER = Base64.urlsafe_encode64((1..32).map(&:chr).join, padding: false)
  TOKEN_PATTERN = /\Alrail_key_(?<prefix>[A-Za-z0-9]{12})_(?<secret>[A-Za-z0-9_-]{43})\z/

  def self.keyed_secret(secret)
    OpenSSL::HMAC.hexdigest("SHA256", pepper, secret)
  end

  def self.pepper
    encoded = ENV["LRAIL_API_KEY_PEPPER"]
    encoded ||= local_value(LOCAL_PEPPER)
    value = Base64.urlsafe_decode64(pad(encoded))
    raise KeyError, "LRAIL_API_KEY_PEPPER must contain 32 bytes" unless value.bytesize == 32

    value
  rescue ArgumentError
    raise KeyError, "LRAIL_API_KEY_PEPPER must be unpadded base64url"
  end

  def self.parse(token)
    TOKEN_PATTERN.match(token.to_s)
  end

  def self.local_value(value)
    raise KeyError, "LRAIL_API_KEY_PEPPER is required in production" if Rails.env.production?

    value
  end

  def self.pad(value)
    value.to_s + ("=" * ((4 - value.to_s.length % 4) % 4))
  end

  private_class_method :local_value, :pad
end
