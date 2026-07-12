module ApplicationHelper
  ICON_PATHS = {
    overview: '<path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/>',
    projects: '<path d="M3 7.5h7l2 2h9v10H3z"/><path d="M3 7.5v-3h7l2 3"/>',
    activity: '<path d="M3 12h4l2.5-6 4.5 12 2.5-6H21"/>',
    deploy: '<path d="M12 3v12m0-12 5 5m-5-5L7 8"/><path d="M4 14v6h16v-6"/>',
    data: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/>',
    domains: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
    telemetry: '<path d="M4 19V9m5 10V5m5 14v-7m5 7V3"/>',
    members: '<circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2"/><path d="M3 20c0-4 2.5-7 6-7s6 3 6 7M15 14c3 0 5 2 5 5"/>',
    usage: '<circle cx="12" cy="12" r="9"/><path d="M12 7v10M15 9.5c0-1.4-1.3-2.5-3-2.5s-3 1-3 2.5 1.3 2.5 3 2.5 3 1.1 3 2.5-1.3 2.5-3 2.5-3-1.1-3-2.5"/>',
    audit: '<path d="M6 3h12v18H6z"/><path d="M9 7h6M9 11h6M9 15h4"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.5-2.4 1A7 7 0 0 0 15 6l-.3-2.5h-4L10.5 6A7 7 0 0 0 9 7L6.6 6 4.5 9.5 6.5 11a7 7 0 0 0 0 2l-2 1.5L6.6 18 9 17a7 7 0 0 0 1.5 1l.3 2.5h4L15 18a7 7 0 0 0 1.5-1l2.4 1 2-3.5-2-1.5a7 7 0 0 0 .1-1z"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    bell: '<path d="M18 8a6 6 0 1 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
    chevron: '<path d="m9 18 6-6-6-6"/>',
    git: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 6h8M7 8l4 8m6-8-4 8"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v7H4V6h7"/>',
    more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'
  }.freeze

  STATUS_LABELS = {
    "healthy" => [ "success", "Healthy" ], "ready" => [ "success", "Ready" ],
    "promoted" => [ "success", "Live" ], "active" => [ "success", "Active" ],
    "succeeded" => [ "success", "Succeeded" ], "available" => [ "success", "Available" ],
    "deploying" => [ "progress", "Deploying" ], "building" => [ "progress", "Building" ],
    "running" => [ "progress", "Running" ], "accepted" => [ "progress", "Accepted" ],
    "waiting" => [ "warning", "Waiting" ], "degraded" => [ "warning", "Degraded" ],
    "failed" => [ "danger", "Failed" ], "canceled" => [ "neutral", "Canceled" ],
    "paused" => [ "neutral", "Paused" ], "unknown" => [ "neutral", "Unknown" ]
  }.freeze

  def icon(name, size: 18)
    paths = ICON_PATHS.fetch(name.to_sym, ICON_PATHS[:overview])
    tag.svg(paths.html_safe, width: size, height: size, viewBox: "0 0 24 24", fill: "none",
      stroke: "currentColor", stroke_width: 1.7, stroke_linecap: "round",
      stroke_linejoin: "round", aria: { hidden: true })
  end

  def nav_class(controller_name, expected_action = nil)
    active = controller_path == controller_name && (expected_action.nil? || expected_action == action_name)
    class_names("app-nav__link", "is-active": active)
  end

  def status_badge(state)
    tone, label = STATUS_LABELS.fetch(state.to_s, [ "neutral", state.to_s.humanize ])
    tag.span(class: "status-badge status-badge--#{tone}") do
      tag.span("", class: "status-badge__dot", aria: { hidden: true }) + label
    end
  end

  def relative_time(value)
    value ? "#{time_ago_in_words(value)} ago" : "Never"
  end
end
