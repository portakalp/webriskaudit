# Global external Application Load Balancer in front of the service, reached
# only through Cloudflare (proxied DNS record, SSL mode Full (strict)). There
# is no port 80 listener: Cloudflare connects over HTTPS.
resource "google_compute_global_address" "api" {
  name         = "webriskaudit-api"
  ip_version   = "IPV4"
  address_type = "EXTERNAL"

  depends_on = [google_project_service.enabled]
}

resource "google_compute_region_network_endpoint_group" "api" {
  name                  = "webriskaudit-api"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.api.name
  }
}

# Serverless backends take no health check and no timeout_sec; the request
# timeout is the Cloud Run service's (120 s in service.yaml).
resource "google_compute_backend_service" "api" {
  name                  = "webriskaudit-api"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false

  backend {
    group = google_compute_region_network_endpoint_group.api.id
  }

  log_config {
    enable = false
  }
}

resource "google_compute_url_map" "api" {
  name            = "webriskaudit-api"
  default_service = google_compute_backend_service.api.id
}

resource "google_certificate_manager_dns_authorization" "api" {
  name        = "webriskaudit-api"
  location    = "global"
  domain      = var.api_hostname
  description = "CNAME under _acme-challenge, added in Cloudflare as DNS only."

  depends_on = [google_project_service.enabled]
}

# DNS authorization lets Google issue and renew the certificate while the
# api record is proxied by Cloudflare.
resource "google_certificate_manager_certificate" "api" {
  name     = "webriskaudit-api"
  location = "global"

  managed {
    domains            = [var.api_hostname]
    dns_authorizations = [google_certificate_manager_dns_authorization.api.id]
  }
}

resource "google_certificate_manager_certificate_map" "api" {
  name = "webriskaudit-api"

  depends_on = [google_project_service.enabled]
}

resource "google_certificate_manager_certificate_map_entry" "api" {
  name         = "webriskaudit-api"
  map          = google_certificate_manager_certificate_map.api.name
  hostname     = var.api_hostname
  certificates = [google_certificate_manager_certificate.api.id]
}

resource "google_compute_ssl_policy" "modern" {
  name            = "webriskaudit-modern-tls12"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"

  depends_on = [google_project_service.enabled]
}

resource "google_compute_target_https_proxy" "api" {
  name            = "webriskaudit-api"
  url_map         = google_compute_url_map.api.id
  certificate_map = "//certificatemanager.googleapis.com/${google_certificate_manager_certificate_map.api.id}"
  ssl_policy      = google_compute_ssl_policy.modern.id

  depends_on = [google_certificate_manager_certificate_map_entry.api]
}

resource "google_compute_global_forwarding_rule" "api_https" {
  name                  = "webriskaudit-api-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  ip_address            = google_compute_global_address.api.id
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
}
