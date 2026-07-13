class OperationEvent < ApplicationRecord
  include OrganizationScoped

  belongs_to :operation
  belongs_to :build, optional: true

  validates :generation, :sequence, :attempt,
    numericality: { only_integer: true, greater_than: 0 }
  validates :stage, :kind, :occurred_at, presence: true
  validates :stage, :kind, length: { maximum: 64 }
  validates :output, :vertex, :name, length: { maximum: 512 }, allow_nil: true
  validates :line, length: { maximum: 16_384 }, allow_nil: true
  validates :message, length: { maximum: 4_096 }, allow_nil: true
  validates :code, length: { maximum: 128 }, allow_nil: true
  validates :sequence, uniqueness: { scope: %i[operation_id generation] }
end
