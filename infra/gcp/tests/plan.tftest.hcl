# Plans against a mocked provider: no credentials and no API calls. Checks
# the values that decide who can deploy, what the API can reach and when the
# owner gets an alert.
mock_provider "google" {}

variables {
  project_id  = "webriskaudit-prod"
  alert_email = "owner@example.com"
}

run "defaults" {
  command = plan

  assert {
    condition = google_iam_workload_identity_pool_provider.github.attribute_condition == join(" && ", [
      "assertion.repository_id == '1441833024'",
      "assertion.ref == 'refs/heads/main'",
      "(assertion.event_name == 'push' || assertion.event_name == 'workflow_dispatch')",
      "(assertion.workflow_ref == 'portakalp/webriskaudit/.github/workflows/ci.yml@refs/heads/main' || assertion.workflow_ref == 'portakalp/webriskaudit/.github/workflows/rollback-api.yml@refs/heads/main')",
    ])
    error_message = "Unexpected WIF condition: ${google_iam_workload_identity_pool_provider.github.attribute_condition}"
  }

  assert {
    condition     = alltrue([for claim in ["repository_id", "ref", "event_name", "workflow_ref", "environment"] : google_iam_workload_identity_pool_provider.github.attribute_mapping["attribute.${claim}"] == "assertion.${claim}"])
    error_message = "Every claim the WIF condition uses must be mapped."
  }

  assert {
    condition     = google_monitoring_uptime_check_config.https["api-health"].content_matchers[0].content == "\"ok\""
    error_message = "The /health matcher must expect the JSON string \"ok\", quotes included."
  }

  assert {
    condition     = google_monitoring_uptime_check_config.https["api-health"].content_matchers[0].json_path_matcher[0].json_matcher == "EXACT_MATCH"
    error_message = "The /health matcher must be an exact match."
  }

  assert {
    condition     = !google_monitoring_alert_policy.uptime["api-health"].enabled && google_monitoring_alert_policy.uptime["site-home"].enabled
    error_message = "Before the first deploy only the site's alert may be on."
  }

  assert {
    condition = alltrue([
      google_compute_firewall.egress["deny-special-ranges"].priority == 900,
      contains(google_compute_firewall.egress["deny-special-ranges"].destination_ranges, "10.0.0.0/8"),
      contains(google_compute_firewall.egress["deny-special-ranges"].destination_ranges, "169.254.0.0/16"),
      google_compute_firewall.egress["allow-web"].priority == 1000,
      google_compute_firewall.egress["allow-dns-resolvers"].destination_ranges == toset(["1.1.1.1/32", "9.9.9.10/32"]),
      google_compute_firewall.egress["deny-all"].priority == 65000,
      google_compute_firewall.egress["deny-all"].destination_ranges == toset(["0.0.0.0/0"]),
    ])
    error_message = "The egress firewall rules differ from the documented order and ranges."
  }

  assert {
    condition     = alltrue([for rule in google_compute_firewall.egress : rule.direction == "EGRESS" && rule.target_tags == toset(["webriskaudit-api"])])
    error_message = "Every egress rule must target the API's network tag."
  }
}

run "variables_set" {
  command = plan

  variables {
    api_alert_enabled          = true
    github_require_environment = true
    github_deploy_workflows    = ["ci.yml"]
  }

  assert {
    condition     = google_monitoring_alert_policy.uptime["api-health"].enabled
    error_message = "api_alert_enabled must turn on the API's alert."
  }

  assert {
    condition     = endswith(google_iam_workload_identity_pool_provider.github.attribute_condition, " && (assertion.workflow_ref == 'portakalp/webriskaudit/.github/workflows/ci.yml@refs/heads/main') && assertion.environment == 'production'")
    error_message = "Unexpected WIF condition: ${google_iam_workload_identity_pool_provider.github.attribute_condition}"
  }
}

run "rejects_quotes_in_workflow_names" {
  command = plan

  variables {
    github_deploy_workflows = ["ci.yml' || true || '.yml"]
  }

  expect_failures = [var.github_deploy_workflows]
}
