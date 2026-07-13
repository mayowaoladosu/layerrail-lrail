module Api
  module V1
    class OperationsController < BaseController
      def show
        operation = current_organization!.operations.find_by_public_id!(params[:id])
        render_resource(ApiResource.operation(operation))
      end

      def events
        operation = current_organization!.operations.find_by_public_id!(params[:id])
        generation = integer_param(:generation, minimum: 1, default: operation.operation_events.maximum(:generation) || 1)
        after = integer_param(:after, minimum: 0, default: 0)
        limit = integer_param(:limit, minimum: 1, maximum: 1_000, default: 250)
        events = operation.operation_events.where(generation:).where("sequence > ?", after)
          .order(:sequence).limit(limit)
        render json: {
          data: events.map { |event| ApiResource.operation_event(event) },
          operation: ApiResource.operation(operation),
          generation:,
          next_sequence: events.last&.sequence || after
        }
      end

      private

      def integer_param(name, minimum:, default:, maximum: nil)
        return default unless params.key?(name)

        value = Integer(params.fetch(name).to_s, 10)
        valid = value >= minimum && (maximum.nil? || value <= maximum)
        raise ActionController::BadRequest, "#{name} is invalid" unless valid

        value
      rescue ArgumentError, TypeError
        raise ActionController::BadRequest, "#{name} is invalid"
      end
    end
  end
end
