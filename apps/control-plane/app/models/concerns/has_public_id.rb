module HasPublicId
  extend ActiveSupport::Concern

  included do
    class_attribute :public_id_prefix, instance_writer: false
    before_validation :assign_public_id, on: :create
    validates :public_id, presence: true, uniqueness: true
    validate :public_id_matches_resource
  end

  class_methods do
    def uses_public_id(prefix)
      self.public_id_prefix = prefix.to_s
    end

    def find_by_public_id!(value)
      find_by!(public_id: value)
    end
  end

  private

  def assign_public_id
    self.public_id ||= PlatformId.generate(public_id_prefix)
  end

  def public_id_matches_resource
    return if public_id.blank? || PlatformId.valid?(public_id, prefix: public_id_prefix)

    errors.add(:public_id, "must be a canonical #{public_id_prefix}_ UUIDv7")
  end
end
