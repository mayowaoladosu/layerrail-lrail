Rails.application.routes.draw do
    # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

    # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
    # Can be used by load balancers and uptime monitors to verify that the app is live.
    get "/live", to: "health#live"
    get "/ready", to: "health#ready"
    get "/version", to: "health#version"
    get "/up", to: "health#ready", as: :rails_health_check

    # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
    # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
    # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

    # Defines the root path route ("/")
    # root "posts#index"
    namespace :api, path: nil, defaults: { format: :json } do
      namespace :v1 do
        get "/me", to: "me#show"
        resources :organizations, param: :organization_id, only: %i[index create show update] do
          resources :projects, only: %i[index create]
        end
        resources :projects, only: %i[show destroy] do
          resources :environments, only: :index
          resources :services, only: :index
          resources :deployments, only: %i[index create]
          resources :domains, only: :index
          resources :addons, only: :index
        end
        resources :deployments, only: %i[show destroy]
        resources :operations, only: :show
      end
    end

    namespace :console do
      root "dashboard#show"
      resources :projects, only: %i[index new create]
      scope ":organization_id", as: :organization do
        get "/overview", to: "dashboard#show", as: :overview
        resources :projects, only: :show do
          resources :deployments, only: %i[index show create]
          resources :services, only: :show
        end
        get "/members", to: "organizations#members", as: :members
        get "/usage", to: "organizations#usage", as: :usage
        get "/audit", to: "organizations#audit", as: :audit
        get "/settings", to: "organizations#settings", as: :settings
      end
    end

    root "home#show"
end
