# 7. Hosting the API on Cloud Run

Date: 2026-11-01

## Status

Accepted

## Context

The API is one Python process. Its rate limits, scan queue and report cache
live in memory, so a second process would multiply every limit, and a
restart resets them. It makes outbound connections to hosts chosen by
anonymous users. The code refuses non-public addresses
([ADR 0004](0004-guarded-network-layer.md)), but the threat model asks the
deployment for a second layer: an egress firewall, a public resolver
without internal zones, a client address that cannot be forged, and short
log retention. The site is a static export served by Cloudflare
([ADR 0005](0005-static-frontend-export.md)), which also proxies the API.

The project is a portfolio piece: the hosting should be reproducible from
the repository, deploy without long-lived keys, and keep data in the EU.
Cost matters less than control (budget about USD 30 a month).

Four options were compared: Render, Fly.io, Google Cloud Run and a VPS
(Hetzner or OVH) behind Cloudflare Tunnel.

## Decision

Run the API on **Google Cloud Run in europe-west1**, configured in this
repository:

- **Manual scaling, exactly one instance**
  (`run.googleapis.com/scalingMode: manual`, `manualInstanceCount: "1"`).
  Manual scaling switches the autoscaler off; minimum and maximum instance
  settings are not used. The Dockerfile already runs one uvicorn worker.
- **Global external Application Load Balancer** in front of the service,
  with a serverless NEG, a Certificate Manager certificate for
  `api.webriskaudit.com` (DNS authorization), an SSL policy with TLS 1.2 as
  the minimum, and HTTPS only. Cloud Run ingress is
  `internal-and-cloud-load-balancing`, so the `run.app` URL is closed to
  the internet. Cloudflare proxies the API host and adds a secret
  `X-Origin-Auth` header; the API trusts `CF-Connecting-IP` only when that
  header matches (ADR 0006, client IP behind Cloudflare).
- **Direct VPC egress with all traffic through a VPC**: an egress firewall
  on the instance's network tag denies private and special-purpose IPv4
  ranges, allows TCP 80 and 443 to anywhere and port 53 only to the
  configured resolvers (`1.1.1.1`, `9.9.9.10`), and denies everything else.
  The subnet has no IPv6, so there is no IPv6 egress at all. **Cloud NAT**
  with one reserved address gives the scanner a fixed source IP that can be
  published.
- **Identities**: the runtime service account has no project roles, only
  access to the origin secret. The deploy workflow authenticates with
  **Workload Identity Federation** (no service account keys), limited to
  this repository's numeric ID, `refs/heads/main`, `push` and
  `workflow_dispatch` runs and the deploy and rollback workflow files, and
  may only replace this one service, push to its Artifact Registry
  repository and act as the runtime account.
- **Configuration as code, split by owner**: Terraform in `infra/gcp/`
  creates the project-level resources and a placeholder service
  (`ignore_changes = all`); the deploy workflow owns the service spec in
  `deploy/cloudrun/service.yaml` and replaces it on each deploy.
- **Logs** go to a log bucket in europe-west1 with 14-day retention; the
  `_Default` sink is disabled and Cloud Run's request logs (which contain
  the caller's address) are excluded.

## Alternatives considered

- **Render** (Frankfurt, about USD 7 a month). The simplest to run, and
  the fallback if this setup fails. No egress firewall, a shared outbound
  address, conflicting documentation on how `X-Forwarded-For` is built, no
  keyless deploys, and logs probably processed in the US.
- **Fly.io** (about USD 4 to 8 a month). No egress firewall; with default
  settings every client shares one rate-limit key; failed health checks do
  not restart a Machine; deploy tokens reach the organisation's private
  network.
- **VPS behind Cloudflare Tunnel** (Hetzner or OVH). The strongest egress
  control (nftables can block the metadata service too) and an EU company,
  but the operating system, Docker and firewall become mine to patch, abuse
  reports come to me directly, and no Hetzner Cloud plan could be ordered
  when this was decided.
- **Cloud Run domain mapping instead of a load balancer.** Saves about
  USD 18 a month, but domain mapping is a preview feature, needs ingress
  open to all (so `run.app` stays reachable), and its certificate is issued
  through an HTTP challenge that a proxied Cloudflare record breaks.
  Cloudflare cannot proxy `run.app` directly on the Free plan (overriding
  the Host header is an Enterprise feature).
- **Autoscaling with minimum and maximum set to 1.** The autoscaler can
  still exceed the maximum for a short time and minimum instances are best
  effort; manual scaling switches the autoscaler off instead. Either way a
  deploy starts the new revision's instance next to the old one.
- **No VPC (Cloud Run's default egress).** Outbound traffic would leave
  from a shared Google address pool, which Google advises against for
  scanning-type traffic, with no network-level deny rules.
- **Serverless VPC Access connector instead of Direct VPC egress.** Google
  reports faster starts with a connector plus Cloud NAT, but a connector is
  a set of VMs that costs more and needs its own sizing. Kept as the fix if
  slow starts become a problem.
- **Cloud Armor** in front of the backend (about USD 7 a month). Not
  needed while Cloudflare filters traffic and only Cloudflare can pass the
  origin check; can be added later.

## Consequences

- Cost is about USD 28 to 34 a month (excluding VAT), mostly the load
  balancer's forwarding rule; see `docs/DEPLOYMENT.md`.
- Instances using Direct VPC egress with Cloud NAT can take 30 seconds or
  more to start, so every deploy and every platform restart has a slow
  start. The startup probe allows 180 seconds.
- Deploys and restarts reset the in-memory limits and cache, as before.
- The metadata server is not covered by the firewall in the same way as
  other addresses (for VMs Google documents it as always reachable). The
  runtime service account's lack of roles is the control; the egress check
  job shows what is reachable.
- The API depends on Cloudflare: the origin secret and the client address
  both come from Cloudflare's request headers.
- Some settings live outside the repository: billing and budget, the state
  bucket, the origin secret's value, and all Cloudflare rules. They are
  listed in `docs/DEPLOYMENT.md`.
- Terraform does not detect changes to the service spec; the deploy
  workflow and `service.yaml` are the source of truth for it.
