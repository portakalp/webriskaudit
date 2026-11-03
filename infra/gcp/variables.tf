variable "project_id" {
  description = "ID of the Google Cloud project that hosts the API, for example webriskaudit-prod."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID (6-30 characters: lower-case letters, digits, hyphens)."
  }
}

variable "region" {
  description = "Region of the Cloud Run service, the network and the log bucket."
  type        = string
  default     = "europe-west1"
}

variable "api_hostname" {
  description = "Public host name of the API; the load balancer's certificate is issued for it."
  type        = string
  default     = "api.webriskaudit.com"
}

variable "site_hostname" {
  description = "Public host name of the website, watched by an uptime check."
  type        = string
  default     = "webriskaudit.com"
}

variable "api_alert_enabled" {
  description = "Turn on the alert of the API /health uptime check. Leave off until the first deploy serves the API; before that the check fails (docs/DEPLOYMENT.md, checklist step 10)."
  type        = bool
  default     = false
}

variable "alert_email" {
  description = "Address that receives uptime alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an email address."
  }
}

variable "github_repository_id" {
  description = "Numeric ID of the GitHub repository allowed to deploy (gh api repos/OWNER/REPO --jq .id)."
  type        = string
  default     = "1444080877"

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repository_id))
    error_message = "github_repository_id must be the numeric repository ID, not the owner/name."
  }
}

variable "github_repository" {
  description = "OWNER/NAME of the repository in github_repository_id, spelled as on GitHub; the WIF condition names its deploy workflows by this path."
  type        = string
  default     = "portakalp/webriskaudit"

  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.github_repository))
    error_message = "github_repository must be OWNER/NAME."
  }
}

variable "github_deploy_workflows" {
  description = "Files in .github/workflows whose push and workflow_dispatch runs on main may deploy."
  type        = list(string)
  default     = ["ci.yml", "rollback-api.yml"]

  validation {
    condition     = length(var.github_deploy_workflows) > 0 && alltrue([for file in var.github_deploy_workflows : can(regex("^[A-Za-z0-9._-]+[.]ya?ml$", file))])
    error_message = "github_deploy_workflows must list workflow file names such as ci.yml."
  }
}

variable "github_require_environment" {
  description = "Also require the GitHub environment claim. Turn on once the deploy jobs run in that environment (environments need a public repository on GitHub Free)."
  type        = bool
  default     = false
}

variable "github_environment" {
  description = "GitHub environment required when github_require_environment is true."
  type        = string
  default     = "production"
}

variable "dns_resolvers" {
  description = "Public resolvers the API queries (DNS_NAMESERVERS); the egress firewall allows port 53 to these only."
  type        = list(string)
  default     = ["1.1.1.1", "9.9.9.10"]

  validation {
    condition     = alltrue([for ip in var.dns_resolvers : can(cidrhost("${ip}/32", 0))])
    error_message = "dns_resolvers must be IPv4 addresses."
  }
}
