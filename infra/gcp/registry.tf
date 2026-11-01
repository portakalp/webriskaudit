resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = local.repository_id
  format        = "DOCKER"
  description   = "WebRiskAudit API images, pushed by the deploy workflow."

  # KEEP wins over DELETE: the 10 most recent versions stay (rollback targets),
  # anything older than 30 days beyond those is deleted.
  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "keep-10-most-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-older-than-30-days"
    action = "DELETE"
    condition {
      tag_state  = "ANY"
      older_than = "30d"
    }
  }

  depends_on = [google_project_service.enabled]
}
