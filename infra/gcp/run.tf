# Placeholder for the API service. Terraform only creates it, so the load
# balancer and the IAM bindings have something to point at; the deploy
# workflow owns its spec (deploy/cloudrun/service.yaml) and replaces it on
# every deploy. ignore_changes = all keeps Terraform from reverting that.
resource "google_cloud_run_v2_service" "api" {
  name     = local.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  # With ignore_changes = all a later change to this flag would never be
  # applied, so it is off from the start; "terraform destroy" removes the service.
  deletion_protection = false

  template {
    service_account = google_service_account.api_runtime.email
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }

  lifecycle {
    ignore_changes = all
  }

  depends_on = [google_project_service.enabled]
}

# Requests arrive through the load balancer, which does not authenticate to
# Cloud Run; ingress (internal and Cloud Load Balancing only) and the origin
# secret checked by the app keep everyone else out.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
