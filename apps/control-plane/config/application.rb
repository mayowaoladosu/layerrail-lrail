require_relative "boot"

require "rails/all"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module ControlPlane
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    config.autoload_lib(ignore: %w[assets tasks])
    config.active_record.schema_format = :sql
    config.active_record.dump_schema_after_migration = false

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Don't generate system test files.
    config.generators.system_tests = nil

    config.action_dispatch.default_headers.merge!(
      "Permissions-Policy" => "camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()",
      "Referrer-Policy" => "strict-origin-when-cross-origin",
      "X-Content-Type-Options" => "nosniff",
      "X-Frame-Options" => "DENY"
    )
  end
end
