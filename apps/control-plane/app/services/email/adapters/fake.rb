module Email
  module Adapters
    class Fake
      Delivery = Data.define(:intent_id, :recipient, :subject, :text, :html)

      attr_reader :deliveries

      def initialize
        @deliveries = []
      end

      def provider_name
        "fake"
      end

      def terminal_state
        "delivered"
      end

      def deliver(intent:, rendered:)
        @deliveries << Delivery.new(intent.public_id, intent.recipient, rendered.subject, rendered.text, rendered.html)
        "fake_#{intent.public_id}"
      end
    end
  end
end
