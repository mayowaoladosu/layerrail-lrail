require "rails_helper"
require "tmpdir"

RSpec.describe SourceIngestion do
  around do |example|
    original_grant = ENV.delete("LRAIL_SOURCE_GRANT_KEY")
    original_keys = ENV.delete("LRAIL_SOURCE_SIGNING_PUBLIC_KEYS")
    example.run
  ensure
    ENV["LRAIL_SOURCE_GRANT_KEY"] = original_grant
    ENV["LRAIL_SOURCE_SIGNING_PUBLIC_KEYS"] = original_keys
  end

  it "loads functional-lab verifier material from ignored bounded files" do
    Dir.mktmpdir do |root|
      stub_const("SourceIngestion::LOCAL_LAB_ROOT", Pathname(root))
      grant = Base64.urlsafe_encode64("g" * 32, padding: false)
      keys = { "source-finalizer-mb-fixture" => Base64.urlsafe_encode64("p" * 32, padding: false) }
      File.binwrite(File.join(root, "source-grant-key"), grant)
      File.binwrite(File.join(root, "source-signing-public-keys.json"), JSON.generate(keys))

      expect(described_class.send(:local_grant_key)).to eq(grant)
      expect(described_class.signing_keys).to eq(keys)
    end
  end

  it "rejects oversized functional-lab verifier material" do
    Dir.mktmpdir do |root|
      stub_const("SourceIngestion::LOCAL_LAB_ROOT", Pathname(root))
      File.binwrite(File.join(root, "source-signing-public-keys.json"), "x" * (64.kilobytes + 1))

      expect { described_class.signing_keys }.to raise_error(KeyError, "local source lab configuration is unsafe")
    end
  end
end
