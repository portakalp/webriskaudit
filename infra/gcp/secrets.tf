# Shared secret that Cloudflare adds as X-Origin-Auth and the API checks
# (ORIGIN_AUTH_SECRETS). Terraform creates the secret but never its value, so
# the value stays out of the state; versions are added with gcloud
# (docs/DEPLOYMENT.md).
resource "google_secret_manager_secret" "origin_auth" {
  secret_id = local.origin_secret

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_iam_member" "runtime_reads_origin_auth" {
  secret_id = google_secret_manager_secret.origin_auth.id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.api_runtime.member
}
