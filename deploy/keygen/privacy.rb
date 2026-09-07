# Deployment-specific privacy controls for Keygen CE v1.7.2.
Rails.application.configure do
  config.lograge.ignore_custom = ->(_event) { true }
  config.lograge.custom_payload = ->(_controller) { {} }
  config.log_level = :error
  config.action_mailer.perform_deliveries = false
  config.filter_parameters += [:key, :license_key, :fingerprint, :authorization]
  config.after_initialize do
    formatter = ActiveSupport::Logger::SimpleFormatter.new
    def formatter.call(severity, time, _progname, _message)
      "#{time.utc.iso8601} #{severity} Keygen operational event; details suppressed\n"
    end
    formatter.extend(ActiveSupport::TaggedLogging::Formatter)
    Rails.logger.formatter = formatter
    Sidekiq.logger.formatter = formatter
  end
  config.to_prepare do
    unless Machine.ancestors.any? { |m| m.name == 'SerializedMachineWrites' }
      module ::SerializedMachineWrites
        def save(**options, &block)
          return super unless license&.persisted?
          license.with_lock { super(**options, &block) }
        end
        def save!(**options, &block)
          return super unless license&.persisted?
          license.with_lock { super(**options, &block) }
        end
        def destroy
          return super unless license&.persisted?
          license.with_lock { super }
        end
      end
      Machine.prepend(SerializedMachineWrites)
    end
    # Prevent requesting a longer permit directly outside the official client.
    unless MachineCheckoutService.ancestors.any? { |m| m.name == 'PrivateCheckoutLimit' }
      module ::PrivateCheckoutLimit
        def initialize(**kwargs)
          kwargs[:ttl] = 604800 if kwargs[:ttl].nil?
          raise AbstractCheckoutService::InvalidTTLError, 'maximum TTL is seven days' if kwargs[:ttl] > 604800
          super(**kwargs)
        end
      end
      MachineCheckoutService.prepend(PrivateCheckoutLimit)
      LicenseCheckoutService.prepend(PrivateCheckoutLimit)
    end
  end
end
