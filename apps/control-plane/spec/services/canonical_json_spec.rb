require "rails_helper"

RSpec.describe CanonicalJson do
  it "sorts nested object keys without changing array order" do
    expect(described_class.dump({ b: [ 2, 1 ], a: { z: true, y: nil } })).to eq(
      '{"a":{"y":null,"z":true},"b":[2,1]}',
    )
  end

  it "rejects non-finite and unsupported values" do
    expect { described_class.dump(Float::NAN) }.to raise_error(ArgumentError)
    expect { described_class.dump(Object.new) }.to raise_error(ArgumentError)
  end
end
