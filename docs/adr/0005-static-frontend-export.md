# 5. Static frontend export

Date: 2026-11-01

## Status

Accepted

## Context

The website is a form, a report view, a sample report and a privacy note.
All scanning happens in the API. The site does not need server-side
rendering, API routes or server actions, and every server process that runs
for it would be one more thing to patch, monitor and secure.

v1 already built the site with Next.js `output: 'export'`, but the build
ignored TypeScript errors (`typescript.ignoreBuildErrors: true`), the
`pnpm lint` script had no ESLint installed, a `start` script pointed at
`next start` (which cannot serve a static export), and the pages loaded
Google Analytics, Vercel Analytics, a cookie banner and a Calendly widget for
the sales funnel.

## Decision

- The site stays a Next.js static export (`output: 'export'`, unoptimized
  images). `pnpm build` writes plain files to `frontend/out/`, which any
  static host can serve; webriskaudit.com serves them through Cloudflare.
- The browser calls the API directly at `NEXT_PUBLIC_API_URL`, which is
  inlined at build time. Without it, a development build falls back to
  `http://localhost:8000` and a production build treats the API as
  unavailable and offers the bundled sample report, labelled as
  illustrative.
- The build type-checks and lints (CI runs `pnpm lint`, `tsc --noEmit`,
  the vitest suite with `pnpm test`, a check that `lib/api-types.ts` still
  matches `backend/openapi.json` (`pnpm gen:api`), and `pnpm build`), and the
  `start` script is removed.
- No analytics, tracking, cookies or third-party scripts
  ([ADR 0003](0003-no-personal-data.md)).

## Consequences

- The website has no server-side attack surface of its own; its security
  rests on the static host and on the API.
- The API must allow the site's origin through CORS and sees each visitor's
  address (through the proxy). There is no server-side proxy that could hide
  the API or add secrets, so the API cannot rely on secrets held by the site.
- The API URL is fixed per build; pointing the site at another API means
  rebuilding it.
- Response headers for the site, including its own Content Security Policy,
  have to be set on the static host or CDN, because Next.js header
  configuration does not apply to a static export.
- Next.js emits inline scripts and a static export cannot add a per-request
  nonce, so a strict CSP for the site needs script hashes. They change with
  every build, so `pnpm build` computes them from the exported HTML and fills
  them into `script-src` (`frontend/scripts/csp-hashes.mjs`), which has no
  `'unsafe-inline'`. An inline script added after the build, such as by an
  edge feature, is blocked.
- Reports cannot be server-rendered or shared by URL; that would need a
  server or a stored report, which [ADR 0003](0003-no-personal-data.md) rules
  out for now.
