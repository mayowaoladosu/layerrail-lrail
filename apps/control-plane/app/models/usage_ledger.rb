class UsageLedger < ApplicationRecord
  self.table_name = "usage_ledger"

  include HasPublicId
  include OrganizationScoped

  uses_public_id :use

  validates :meter_type, :unit, :period_start, :period_end, :resource_public_id,
    :source_id, :source_epoch, :sequence, :correlation_id, presence: true
  validates :quantity, numericality: { other_than: 0 }

  def readonly?
    persisted?
  end
end
