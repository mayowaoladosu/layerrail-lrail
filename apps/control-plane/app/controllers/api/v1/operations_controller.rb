module Api
  module V1
    class OperationsController < BaseController
      def show
        operation = current_organization!.operations.find_by_public_id!(params[:id])
        render_resource(ApiResource.operation(operation))
      end
    end
  end
end
