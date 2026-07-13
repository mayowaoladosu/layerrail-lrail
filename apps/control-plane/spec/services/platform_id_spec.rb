require "rails_helper"

RSpec.describe PlatformId do
  it "creates canonical, time-sortable prefixed UUIDv7 identifiers" do
    now = Time.utc(2026, 7, 12, 20, 0, 0, 123_000)
    first = described_class.generate(:prj, now:, random: "\x11" * 10)
    second = described_class.generate(:prj, now: now + 0.001, random: "\x00" * 10)

    expect(first).to match(PlatformId::PATTERN)
    expect(first).to be < second
    expect(described_class.valid?(first, prefix: :prj)).to be(true)
    expect(described_class.valid?(first, prefix: :org)).to be(false)
    expect(described_class.generate(:fet, now:, random: "\x22" * 10)).to start_with("fet_")
    expect(described_class.generate(:psb, now:, random: "\x33" * 10)).to start_with("psb_")
  end

  it "rejects unsupported prefixes and malformed entropy" do
    expect { described_class.generate(:root) }.to raise_error(ArgumentError, /unsupported/)
    expect { described_class.generate(:org, random: "short") }.to raise_error(ArgumentError, /10 bytes/)
  end
end
