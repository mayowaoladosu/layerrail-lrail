require "rails_helper"
require "digest"
require "net/http"
require "rubygems/package"
require "stringio"
require "zlib"

RSpec.describe "source gateway ingestion" do
  before do
    skip "set LRAIL_SOURCE_INTEGRATION=1 to run the source gateway test" unless ENV["LRAIL_SOURCE_INTEGRATION"] == "1"
  end

  it "authorizes direct parts and verifies the signed immutable snapshot" do
    account = create_account
    organization = create_organization(account:)
    project = within_organization(account, organization) do
      Projects::Create.call(account:, organization:, attributes: { name: "Source E2E", slug: "source-e2e" }).project
    end
    archive = source_archive("source from Rails #{SecureRandom.hex(8)}\n")
    midpoint = archive.bytesize / 2
    bodies = [ archive.byteslice(0, midpoint), archive.byteslice(midpoint, archive.bytesize - midpoint) ]
    create_result = within_organization(account, organization) do
      SourceIngestion::CreateSession.new.call(
        account:,
        organization:,
        project:,
        attributes: {
          expected_archive_bytes: archive.bytesize,
          expected_archive_sha256: "sha256:#{Digest::SHA256.hexdigest(archive)}",
          expected_parts: bodies.length,
          root_directory: "",
          excluded_count: 1
        },
      )
    end
    parts = create_result.parts.zip(bodies).map do |authorization, body|
      uri = URI(authorization.fetch("url"))
      request = Net::HTTP::Put.new(uri)
      request.body = body
      response = Net::HTTP.start(uri.host, uri.port) { |connection| connection.request(request) }
      expect(response).to be_a(Net::HTTPSuccess)
      {
        number: authorization.fetch("number"),
        size: body.bytesize,
        sha256: "sha256:#{Digest::SHA256.hexdigest(body)}"
      }
    end

    first = within_organization(account, organization) do
      SourceIngestion::Finalize.new.call(
        account:,
        organization:,
        session: create_result.session,
        parts:,
      )
    end
    replay = within_organization(account, organization) do
      SourceIngestion::Finalize.new.call(
        account:,
        organization:,
        session: create_result.session.reload,
        parts:,
      )
    end

    expect(first.snapshot).to eq(replay.snapshot)
    expect(first.snapshot).to have_attributes(
      organization:,
      project:,
      kind: "local",
      digest: a_string_matching(/\Asha256:[0-9a-f]{64}\z/),
      object_ref: a_string_starting_with("s3://lrail-source/snapshots/"),
      size_bytes: archive.bytesize,
    )
    expect(create_result.session.reload).to have_attributes(
      state: "complete",
      source_snapshot: first.snapshot,
      signing_key_id: "source-finalizer-local-v1",
    )
  end

  def source_archive(body)
    output = StringIO.new("".b)
    compressed = Zlib::GzipWriter.new(output)
    compressed.mtime = 0
    Gem::Package::TarWriter.new(compressed) do |archive|
      archive.add_file_simple("README.md", 0o644, body.bytesize) { |file| file.write(body) }
    end
    compressed.close
    output.string
  end
end
