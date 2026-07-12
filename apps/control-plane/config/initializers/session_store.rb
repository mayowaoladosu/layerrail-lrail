Rails.application.config.session_store(
  :cookie_store,
  key: "_lrail_session",
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax,
  expire_after: 12.hours
)
