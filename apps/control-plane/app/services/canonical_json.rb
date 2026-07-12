class CanonicalJson
  def self.dump(value)
    case value
    when Hash
      "{#{value.stringify_keys.sort.map { |key, item| "#{key.to_json}:#{dump(item)}" }.join(",")}}"
    when Array
      "[#{value.map { |item| dump(item) }.join(",")}]"
    when String, Integer, TrueClass, FalseClass, NilClass
      value.to_json
    when Float
      raise ArgumentError, "canonical JSON number must be finite" unless value.finite?

      value.to_json
    when BigDecimal
      value.to_s("F")
    when Time, ActiveSupport::TimeWithZone
      value.utc.iso8601(6).to_json
    else
      raise ArgumentError, "unsupported canonical JSON value: #{value.class}"
    end
  end
end
