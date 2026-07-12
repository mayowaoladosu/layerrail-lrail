require "rails_helper"

RSpec.describe RequestIdentity do
  it "preserves canonical request and trace identifiers" do
    request_id = "req_#{"a" * 32}"
    traceparent = "00-#{"b" * 32}-#{"c" * 16}-01"

    expect(described_class.request_id(request_id)).to eq(request_id)
    expect(described_class.traceparent(traceparent)).to eq(traceparent)
  end

  it "deterministically replaces invalid request identifiers and drops invalid traces" do
    normalized = described_class.request_id("upstream-value")
    expect(normalized).to match(/\Areq_[0-9a-f]{32}\z/)
    expect(described_class.request_id("upstream-value")).to eq(normalized)
    expect(described_class.traceparent("not-a-traceparent")).to be_nil
  end
end
