module Email
  class AdapterFactory
    def self.build(name: ENV.fetch("LRAIL_EMAIL_ADAPTER", default_name))
      case name
      when "fake" then Adapters::Fake.new
      when "resend" then Adapters::Resend.new
      else raise ArgumentError, "unsupported email adapter: #{name}"
      end
    end

    def self.default_name
      Rails.env.production? ? "resend" : "fake"
    end

    private_class_method :default_name
  end
end
