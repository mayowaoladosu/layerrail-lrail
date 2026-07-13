require "rails_helper"

RSpec.describe SourceProviders::GithubWebhook do
  it "matches GitHub's published raw-body HMAC vector" do
    webhook = described_class.allocate
    webhook.instance_variable_set(:@secret, "It's a Secret to Everybody")
    signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"

    expect { webhook.send(:verify_signature!, "Hello, World!", signature) }.not_to raise_error
    expect { webhook.send(:verify_signature!, "Hello, World!!", signature) }
      .to raise_error(SourceProviders::InvalidWebhook)
  end

  it "rejects webhook secrets below 256 bits" do
    expect { described_class.new(secret: "s" * 31) }.to raise_error(ArgumentError, /32 bytes/)
    expect { described_class.new(secret: "s" * 32) }.not_to raise_error
  end
end
