# Application logs stay in the EU for 14 days. The _Default sink would copy
# them into the global _Default bucket for 30 days, so it is disabled and a
# project sink routes the same entries to a bucket in var.region instead.
# Cloud Run's request logs (one entry per request, with the caller's address)
# are excluded from both. Audit logs go to _Required, which cannot be changed.
locals {
  # The audit logs that the _Required sink takes; the same filter as _Default's.
  not_required_logs = join(" AND ", [
    for id in [
      "cloudaudit.googleapis.com/activity",
      "externalaudit.googleapis.com/activity",
      "cloudaudit.googleapis.com/system_event",
      "externalaudit.googleapis.com/system_event",
      "cloudaudit.googleapis.com/access_transparency",
      "externalaudit.googleapis.com/access_transparency",
    ] : "NOT LOG_ID(\"${id}\")"
  ])
  cloud_run_request_logs = "LOG_ID(\"run.googleapis.com/requests\")"
}

resource "google_logging_project_bucket_config" "eu" {
  project        = var.project_id
  location       = var.region
  bucket_id      = local.log_bucket_name
  retention_days = 14
  description    = "WebRiskAudit logs, kept in ${var.region} for 14 days."

  depends_on = [google_project_service.enabled]
}

resource "google_logging_project_sink" "eu" {
  name        = local.log_bucket_name
  description = "Everything _Default would keep, except Cloud Run request logs, into the EU bucket."
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.eu.id}"
  filter      = local.not_required_logs

  exclusions {
    name        = "cloud-run-request-logs"
    description = "Request logs carry each caller's address."
    filter      = local.cloud_run_request_logs
  }

  unique_writer_identity = true
}

# _Default exists in every project and cannot be deleted. Declaring it here
# takes over the existing sink; "terraform destroy" leaves it as it is
# (disabled) and only forgets it.
resource "google_logging_project_sink" "default" {
  name        = "_Default"
  destination = "logging.googleapis.com/projects/${var.project_id}/locations/global/buckets/_Default"
  filter      = local.not_required_logs
  disabled    = true

  # Kept for the case that the sink is switched back on by hand.
  exclusions {
    name        = "cloud-run-request-logs"
    description = "Request logs carry each caller's address."
    filter      = local.cloud_run_request_logs
  }

  unique_writer_identity = true

  depends_on = [google_project_service.enabled]
}
