# Identity of the API container. It has no project roles: the metadata server
# hands its token to anything running in the container, so the token must be
# worthless beyond reading the origin secret.
resource "google_service_account" "api_runtime" {
  account_id   = "api-runtime"
  display_name = "WebRiskAudit API runtime"
  description  = "Runs the API on Cloud Run. Only role: secretAccessor on the origin-auth secret."

  depends_on = [google_project_service.enabled]
}

# Identity of the deploy workflow, reached through Workload Identity Federation (wif.tf).
resource "google_service_account" "deployer" {
  account_id   = "github-deployer"
  display_name = "WebRiskAudit GitHub deployer"
  description  = "Used by GitHub Actions on main to push images and update the Cloud Run service."

  depends_on = [google_project_service.enabled]
}

# Scoped to the one service rather than the project: the deployer can read and
# replace webriskaudit-api and move its traffic, nothing else in Cloud Run.
resource "google_cloud_run_v2_service_iam_member" "deployer_run_developer" {
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.developer"
  member   = google_service_account.deployer.member
}

resource "google_artifact_registry_repository_iam_member" "deployer_writer" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.deployer.member
}

# Needed to deploy a revision that runs as api-runtime.
resource "google_service_account_iam_member" "deployer_acts_as_runtime" {
  service_account_id = google_service_account.api_runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.deployer.member
}
