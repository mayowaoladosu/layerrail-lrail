class AddDeploymentSourceFetch < ActiveRecord::Migration[8.1]
  def change
    add_reference :deployments, :source_fetch,
      foreign_key: { on_delete: :restrict },
      index: { unique: true }
  end
end
