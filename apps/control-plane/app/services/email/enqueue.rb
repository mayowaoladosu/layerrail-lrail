module Email
  class Enqueue
    TEMPLATE = "rodauth_message"
    TEMPLATE_VERSION = 1

    def self.from_mail(account:, message:)
      recipients = Array(message.to).map { |recipient| recipient.to_s.strip.downcase }.uniq
      raise ArgumentError, "email has no recipient" if recipients.empty?

      organization = primary_organization(account)
      rendered_data = mail_data(message)

      OrganizationContext.with(account:, organization:) do
        recipients.map do |recipient|
          enqueue_recipient(account:, organization:, recipient:, data: rendered_data)
        end
      end
    end

    def self.primary_organization(account)
      OrganizationContext.with(account:) do
        account.memberships.where(status: "active").order(:id).first!.organization
      end
    end

    def self.mail_data(message)
      {
        "subject" => TemplateRegistry.sanitize_subject(message.subject),
        "text" => message.text_part&.decoded || (message.html_part ? "" : message.body.decoded),
        "html" => message.html_part&.decoded
      }
    end

    def self.enqueue_recipient(account:, organization:, recipient:, data:)
      digest = Digest::SHA256.hexdigest(
        JSON.generate(
          account_id: account.public_id,
          recipient:,
          template: TEMPLATE,
          version: TEMPLATE_VERSION,
          data:,
        )
      )
      idempotency_key = "email:#{digest}"

      EmailIntent.transaction do
        intent = EmailIntent.find_by(idempotency_key:)
        return intent if intent

        intent = EmailIntent.create!(
          organization:,
          account:,
          template: TEMPLATE,
          template_version: TEMPLATE_VERSION,
          recipient:,
          locale: "en",
          data:,
          tags: { "category" => "authentication" },
          idempotency_key:,
          state: "pending",
        )
        DomainRecorder.record!(
          resource: intent,
          event_type: "email.intent.created",
          action: "email.intent.create",
          actor: account,
          data: { template: TEMPLATE, template_version: TEMPLATE_VERSION },
        )
        intent
      end
    rescue ActiveRecord::RecordNotUnique
      EmailIntent.find_by!(idempotency_key:)
    end

    private_class_method :primary_organization, :mail_data, :enqueue_recipient
  end
end
