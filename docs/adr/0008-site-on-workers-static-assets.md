# 8. Site on Workers static assets

Date: 2026-11-01

## Status

Accepted

## Context

The site is a static export ([ADR 0005](0005-static-frontend-export.md)):
plain files in `frontend/out/` plus `public/_headers`, which carries the
Content Security Policy and the other security headers. v1 was served by a
Cloudflare Pages project that builds from the old repository through
Cloudflare's GitHub app. A Pages project cannot be pointed at another
repository, so the new repository needs a new project either way.

Workers with static assets serve the same kind of site and support
`_headers` and `_redirects` natively, as Pages does; Cloudflare documents a
migration path from Pages. Requests for static assets are free and
unlimited, and do not invoke a Worker script.

The API deploys from GitHub Actions after CI passes
([ADR 0007](0007-api-on-cloud-run.md)). Building the site on Cloudflare
would mean a second build environment with its own Node and pnpm versions,
its own copy of `NEXT_PUBLIC_API_URL`, and repository access for a
third-party app.

## Decision

- The site is the Worker **`webriskaudit-web`** with static assets only and
  no Worker script, configured in `frontend/wrangler.jsonc`: assets from
  `./out`, `not_found_handling: "404-page"` (the export's `404.html` with
  status 404), `html_handling: "auto-trailing-slash"` (`/privacy-policy`
  serves `privacy-policy.html`), `preview_urls: false`, and
  `send_metrics: false`.
- The `deploy-site` job in `.github/workflows/ci.yml` builds the site after
  every CI job (and the API deploy) has passed, with `NEXT_PUBLIC_API_URL`
  from a repository variable, refuses a build whose `_headers` do not allow
  that URL in `connect-src`, runs `wrangler deploy` through
  `cloudflare/wrangler-action` with a pinned wrangler version, and checks
  the deployed headers and pages (`deploy/checks/site_smoke.sh`).
- It authenticates with an account API token limited to Workers Scripts:
  Edit, stored as the `production` environment's secret
  `CLOUDFLARE_API_TOKEN`. Cloudflare gets no access to the repository.
- The Worker is served on `workers.dev` until the cutover. The
  `webriskaudit.com` custom domain is then added in the dashboard, after
  the old Pages project gives it up, and a follow-up change adds it to
  `wrangler.jsonc` and turns `workers_dev` off.
- `public/_headers` stays the single source of the site's headers;
  `nginx.conf` mirrors it for the Docker image.

## Consequences

- One build environment: the deployed site is built from the lock file by
  the same pinned actions as CI, only after tests, lint and the other jobs
  pass, and a deploy cannot pair the site with a different API origin than
  its CSP allows.
- A long-lived Cloudflare token lives in GitHub. It can only edit Workers
  scripts in this account and expires after a year (docs/DEPLOYMENT.md,
  rotation).
- `_headers` applies to static asset responses only. Adding a Worker script
  later (for example for server-side rendering) would need the headers set
  in that script too.
- Rollback is a dashboard click or `wrangler rollback`; there is no build
  to repeat.
- `wrangler-action` installs wrangler with `pnpm add` at deploy time, so
  wrangler's own dependencies are resolved then rather than locked, and
  Dependabot does not update the `wranglerVersion` input; it is checked by
  hand every three months.
- The cutover is a manual step with a short window in which the old Pages
  project no longer serves the domain and the Worker does not yet.
