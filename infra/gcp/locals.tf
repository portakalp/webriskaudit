locals {
  # Names shared with deploy/cloudrun/*.yaml and the deploy workflow.
  service_name    = "webriskaudit-api"
  repository_id   = "webriskaudit"
  network_name    = "webriskaudit"
  subnet_name     = "webriskaudit-euw1"
  subnet_cidr     = "10.10.0.0/26" # the smallest range Direct VPC egress accepts
  network_tag     = "webriskaudit-api"
  origin_secret   = "webriskaudit-origin-auth"
  log_bucket_name = "webriskaudit-logs"
  image_registry  = "${var.region}-docker.pkg.dev/${var.project_id}/${local.repository_id}"
}
