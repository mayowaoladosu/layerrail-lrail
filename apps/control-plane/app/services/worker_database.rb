require "cgi"

class WorkerDatabase
  def self.connect!
    url = ENV["LRAIL_WORKER_DATABASE_URL"]
    url ||= development_url if Rails.env.development?
    raise KeyError, "LRAIL_WORKER_DATABASE_URL is required" if url.blank?

    ApplicationRecord.establish_connection(url)
    ApplicationRecord.connection.verify!
  end

  def self.development_url
    host = ENV.fetch("LRAIL_DATABASE_HOST", "127.0.0.1")
    port = ENV.fetch("LRAIL_DATABASE_PORT", "55432")
    password = ENV.fetch("LRAIL_DATABASE_PASSWORD", "local-only-not-a-secret")
    database = ENV.fetch("LRAIL_DATABASE_NAME", "lrail_control_development")
    "postgresql://lrail_worker:#{CGI.escapeURIComponent(password)}@#{host}:#{port}/#{database}"
  end

  private_class_method :development_url
end
