output "lb_ip" {
  description = "Load balancer address: the target of the proxied A record for the API host in Cloudflare (repository variable API_LB_IP)."
  value       = google_compute_global_address.api.address
}

output "nat_ip" {
  description = "Address the scanner's outbound traffic comes from (SECURITY.md)."
  value       = google_compute_address.egress.address
}

output "wif_provider" {
  description = "Workload identity provider for google-github-actions/auth (repository variable GCP_WIF_PROVIDER)."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deployer_sa" {
  description = "Service account the deploy workflow impersonates (repository variable GCP_DEPLOYER_SA)."
  value       = google_service_account.deployer.email
}

output "runtime_sa" {
  description = "Service account the API runs as (serviceAccountName in deploy/cloudrun/*.yaml)."
  value       = google_service_account.api_runtime.email
}

output "image_registry" {
  description = "Artifact Registry path that images are pushed to, for example <image_registry>/api:<sha>."
  value       = local.image_registry
}

output "dns_authorization_record" {
  description = "Record to add in Cloudflare (DNS only) so Certificate Manager can issue the API certificate."
  value = {
    name = google_certificate_manager_dns_authorization.api.dns_resource_record[0].name
    type = google_certificate_manager_dns_authorization.api.dns_resource_record[0].type
    data = google_certificate_manager_dns_authorization.api.dns_resource_record[0].data
  }
}

output "certificate_name" {
  description = "Certificate Manager certificate of the API host (gcloud certificate-manager certificates describe)."
  value       = google_certificate_manager_certificate.api.name
}

output "nat_name" {
  description = "Cloud NAT gateway and its router, for the temporary logging switch in docs/DEPLOYMENT.md."
  value = {
    nat    = google_compute_router_nat.nat.name
    router = google_compute_router.nat.name
  }
}
