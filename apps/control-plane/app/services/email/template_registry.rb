module Email
  class TemplateRegistry
    Rendered = Data.define(:subject, :text, :html)
    UnknownTemplate = Class.new(StandardError)

    def self.render(intent)
      case [ intent.template, intent.template_version ]
      when [ "rodauth_message", 1 ]
        data = intent.data.stringify_keys
        Rendered.new(
          sanitize_subject(data.fetch("subject")),
          data["text"].to_s,
          data["html"].to_s.presence,
        )
      else
        raise UnknownTemplate, "unknown email template #{intent.template}@#{intent.template_version}"
      end
    end

    def self.sanitize_subject(subject)
      subject.to_s.gsub(/[\r\n]+/, " ").squish.first(200)
    end
  end
end
