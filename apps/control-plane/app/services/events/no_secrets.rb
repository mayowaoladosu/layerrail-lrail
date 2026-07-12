module Events
  class NoSecrets
    ForbiddenKey = Class.new(StandardError)
    FORBIDDEN_KEY = /(authorization|cookie|credential|password|private.?key|secret|session|token)/i

    def self.validate!(value, path = "data")
      case value
      when Hash
        value.each do |key, child|
          current_path = "#{path}.#{key}"
          raise ForbiddenKey, "event field #{current_path} is not allowed" if FORBIDDEN_KEY.match?(key.to_s)

          validate!(child, current_path)
        end
      when Array
        value.each_with_index { |child, index| validate!(child, "#{path}[#{index}]") }
      end
      value
    end
  end
end
