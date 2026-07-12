module Email
  module Adapters
    class Resend
      def initialize(api_key: ENV.fetch("RESEND_API_KEY"), sender: ENV.fetch("LRAIL_EMAIL_FROM"))
        @api_key = api_key
        @sender = sender
      end

      def provider_name
        "resend"
      end

      def terminal_state
        "sent"
      end

      def deliver(intent:, rendered:)
        ::Resend.api_key = @api_key
        response = ::Resend::Emails.send(
          {
            "from" => @sender,
            "to" => [ intent.recipient ],
            "subject" => rendered.subject,
            "text" => rendered.text,
            "html" => rendered.html,
            "headers" => { "X-Entity-Ref-ID" => intent.public_id }
          },
          options: { idempotency_key: intent.idempotency_key },
        ).to_h
        response.fetch(:id) { response.fetch("id") }
      end
    end
  end
end
