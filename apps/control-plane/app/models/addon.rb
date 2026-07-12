class Addon < ApplicationRecord
  include HasPublicId
  include OrganizationScoped

  uses_public_id :add

  ENGINES = %w[postgresql mysql mariadb valkey mongodb opensearch clickhouse rabbitmq].freeze
  STATES = %w[
    requested provisioning configuring available attached backing_up restoring resizing
    deletion_pending final_backup deleting deleted failed
  ].freeze

  belongs_to :project
  belongs_to :environment

  validates :name, :version_channel, :topology, :size_profile, :storage_profile, :region, presence: true
  validates :engine, inclusion: { in: ENGINES }
  validates :state, inclusion: { in: STATES }
end
