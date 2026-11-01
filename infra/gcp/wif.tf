# Keyless deploys: GitHub's OIDC token of a deploy run on main is exchanged
# for a short-lived token of the deployer service account. Numeric IDs are
# used because they cannot be re-registered by someone else, unlike
# owner/name. The ref alone is not enough: pull_request_target,
# issue_comment, workflow_run and schedule runs also carry refs/heads/main,
# and outsiders can start some of them, so the event and the workflow file
# are checked as well.
locals {
  github_deploy_events = ["push", "workflow_dispatch"]
  github_workflow_refs = [
    for file in var.github_deploy_workflows :
    "${var.github_repository}/.github/workflows/${file}@refs/heads/main"
  ]
  github_conditions = concat(
    [
      "assertion.repository_id == '${var.github_repository_id}'",
      "assertion.ref == 'refs/heads/main'",
      "(${join(" || ", [for event in local.github_deploy_events : "assertion.event_name == '${event}'"])})",
      "(${join(" || ", [for ref in local.github_workflow_refs : "assertion.workflow_ref == '${ref}'"])})",
    ],
    var.github_require_environment ? ["assertion.environment == '${var.github_environment}'"] : [],
  )
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
  description               = "Deploy workflow of the WebRiskAudit repository."

  depends_on = [google_project_service.enabled]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "webriskaudit"
  display_name                       = "webriskaudit repository"
  description                        = "GitHub OIDC tokens of the deploy workflows' push and dispatch runs on main."

  # Every claim the condition uses must be mapped.
  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository_id" = "assertion.repository_id"
    "attribute.ref"           = "assertion.ref"
    "attribute.event_name"    = "assertion.event_name"
    "attribute.workflow_ref"  = "assertion.workflow_ref"
    "attribute.environment"   = "assertion.environment"
  }
  attribute_condition = join(" && ", local.github_conditions)

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "deployer_wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_id/${var.github_repository_id}"
}
