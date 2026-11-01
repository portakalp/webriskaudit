resource "google_monitoring_notification_channel" "email" {
  display_name = "WebRiskAudit owner"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }

  depends_on = [google_project_service.enabled]
}

# Both checks go through Cloudflare, like visitors. They watch the same
# failure domain as everything else here, so docs/DEPLOYMENT.md also sets up
# an independent monitor outside Google Cloud.
locals {
  uptime_checks = {
    api-health = {
      display_name = "API /health"
      host         = var.api_hostname
      path         = "/health"
      json_path    = "$.status"
      content      = "ok"
    }
    # Status only: the page content changes at the cutover to the new site.
    site-home = {
      display_name = "Website home page"
      host         = var.site_hostname
      path         = "/"
      json_path    = null
      content      = null
    }
  }
}

resource "google_monitoring_uptime_check_config" "https" {
  for_each = local.uptime_checks

  display_name     = "WebRiskAudit ${each.value.display_name}"
  timeout          = "10s"
  period           = "300s"
  selected_regions = ["EUROPE", "USA_VIRGINIA", "ASIA_PACIFIC"]

  http_check {
    request_method = "GET"
    path           = each.value.path
    port           = 443
    use_ssl        = true
    validate_ssl   = true
  }

  dynamic "content_matchers" {
    for_each = each.value.content == null ? [] : [each.value]
    content {
      content = content_matchers.value.content
      matcher = "MATCHES_JSON_PATH"
      json_path_matcher {
        json_path    = content_matchers.value.json_path
        json_matcher = "EXACT_MATCH"
      }
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = each.value.host
    }
  }
}

# Alerts when more than one of the three checker locations fails, which
# filters out a single location's network trouble.
resource "google_monitoring_alert_policy" "uptime" {
  for_each = local.uptime_checks

  display_name          = "WebRiskAudit ${each.value.display_name} is failing"
  combiner              = "OR"
  severity              = "CRITICAL"
  notification_channels = [google_monitoring_notification_channel.email.id]

  conditions {
    display_name = "${each.value.display_name} uptime check failing"
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.type=\"uptime_url\" AND metric.label.check_id=\"${google_monitoring_uptime_check_config.https[each.key].uptime_check_id}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      duration        = "60s"

      aggregations {
        alignment_period     = "1200s"
        per_series_aligner   = "ALIGN_NEXT_OLDER"
        cross_series_reducer = "REDUCE_COUNT_FALSE"
        group_by_fields      = ["resource.label.host"]
      }

      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    mime_type = "text/markdown"
    content   = "https://${each.value.host}${each.value.path} failed from more than one checker location. See docs/DEPLOYMENT.md, \"Rollback\"."
  }
}
