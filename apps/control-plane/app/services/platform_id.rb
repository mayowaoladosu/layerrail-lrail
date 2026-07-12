require "securerandom"

class PlatformId
  PREFIXES = %w[
    acct org mbr inv prj env svc src snp bld rev dep rel op dom crt rte add att bkp
    rst sch wh whd key evt tgt edg cell pop use sec var vol job run pol inc ses tok upl
  ].freeze
  PATTERN = /\A(?<prefix>[a-z]{2,5})_(?<uuid>[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\z/

  def self.generate(prefix, now: Time.now.utc, random: SecureRandom.random_bytes(10))
    prefix = prefix.to_s
    raise ArgumentError, "unsupported resource prefix" unless PREFIXES.include?(prefix)
    raise ArgumentError, "UUIDv7 randomness must contain 10 bytes" unless random.bytesize == 10

    milliseconds = (now.to_r * 1000).floor
    raise ArgumentError, "time is outside UUIDv7 range" unless milliseconds.between?(0, (1 << 48) - 1)

    bytes = [ milliseconds >> 16, milliseconds & 0xffff ].pack("Nn") + random
    bytes.setbyte(6, 0x70 | (bytes.getbyte(6) & 0x0f))
    bytes.setbyte(8, 0x80 | (bytes.getbyte(8) & 0x3f))
    hex = bytes.unpack1("H*")
    uuid = "#{hex[0, 8]}-#{hex[8, 4]}-#{hex[12, 4]}-#{hex[16, 4]}-#{hex[20, 12]}"
    "#{prefix}_#{uuid}"
  end

  def self.valid?(value, prefix: nil)
    match = PATTERN.match(value.to_s)
    match.present? && PREFIXES.include?(match[:prefix]) && (prefix.nil? || match[:prefix] == prefix.to_s)
  end
end
