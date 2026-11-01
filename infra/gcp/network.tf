# The API reaches the internet only through this network: Direct VPC egress
# with all traffic routed here, an egress firewall on the instance tag, and
# Cloud NAT with one reserved address.
resource "google_compute_network" "vpc" {
  name                    = local.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.enabled]
}

resource "google_compute_subnetwork" "api" {
  name          = local.subnet_name
  region        = var.region
  network       = google_compute_network.vpc.id
  ip_cidr_range = local.subnet_cidr
  stack_type    = "IPV4_ONLY"
}

locals {
  # Priority 900 denies special-purpose ranges before the allows at 1000;
  # 65000 denies everything else ahead of the implied allow-all at 65535.
  egress_rules = {
    deny-special-ranges = {
      priority = 900
      action   = "deny"
      ranges = [
        "0.0.0.0/8",       # "this network"
        "10.0.0.0/8",      # RFC 1918
        "100.64.0.0/10",   # carrier-grade NAT
        "127.0.0.0/8",     # loopback
        "169.254.0.0/16",  # link-local, includes the metadata server
        "172.16.0.0/12",   # RFC 1918
        "192.0.0.0/24",    # IETF protocol assignments
        "192.0.2.0/24",    # TEST-NET-1
        "192.168.0.0/16",  # RFC 1918
        "198.18.0.0/15",   # benchmarking
        "198.51.100.0/24", # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",     # multicast
        "240.0.0.0/4",     # reserved, includes broadcast
      ]
      protocols = [{ protocol = "all", ports = [] }]
    }
    allow-web = {
      priority  = 1000
      action    = "allow"
      ranges    = ["0.0.0.0/0"]
      protocols = [{ protocol = "tcp", ports = ["80", "443"] }]
    }
    allow-dns-resolvers = {
      priority = 1000
      action   = "allow"
      ranges   = [for ip in var.dns_resolvers : "${ip}/32"]
      protocols = [
        { protocol = "tcp", ports = ["53"] },
        { protocol = "udp", ports = ["53"] },
      ]
    }
    deny-all = {
      priority  = 65000
      action    = "deny"
      ranges    = ["0.0.0.0/0"]
      protocols = [{ protocol = "all", ports = [] }]
    }
  }
}

resource "google_compute_firewall" "egress" {
  for_each = local.egress_rules

  name               = "webriskaudit-egress-${each.key}"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = each.value.priority
  target_tags        = [local.network_tag]
  destination_ranges = each.value.ranges

  dynamic "allow" {
    for_each = each.value.action == "allow" ? each.value.protocols : []
    content {
      protocol = allow.value.protocol
      ports    = allow.value.ports
    }
  }

  dynamic "deny" {
    for_each = each.value.action == "deny" ? each.value.protocols : []
    content {
      protocol = deny.value.protocol
      ports    = deny.value.ports
    }
  }
}

resource "google_compute_router" "nat" {
  name    = "webriskaudit-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

# The scanner's public address, published in SECURITY.md so site owners can
# recognise its traffic.
resource "google_compute_address" "egress" {
  name         = "webriskaudit-egress"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"

  depends_on = [google_project_service.enabled]
}

resource "google_compute_router_nat" "nat" {
  name   = "webriskaudit-nat"
  router = google_compute_router.nat.name
  region = var.region

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = [google_compute_address.egress.self_link]

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.api.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  # Dynamic port allocation excludes endpoint-independent mapping.
  enable_dynamic_port_allocation      = true
  enable_endpoint_independent_mapping = false
  min_ports_per_vm                    = 128

  # Translation logs would record every scanned address; keep errors only.
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
