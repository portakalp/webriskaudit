# syntax=docker/dockerfile:1

# Image of the WebRiskAudit site: the Next.js static export served by nginx
# on port 8080, built from frontend/:
#   docker build --build-arg NEXT_PUBLIC_API_URL=http://localhost:8000 -t webriskaudit-web frontend
#   docker run --rm -p 3000:8080 webriskaudit-web
# Base images are pinned by tag and digest; update both together.

# --- Build: static export into /app/out -------------------------------------
FROM node:22.23.4-trixie-slim@sha256:2117f713a417f3aff682ac8f5bc2ebbdf1beed51f36e67ab1e0fd3866b6d2d8f AS build

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    NEXT_TELEMETRY_DISABLED=1

WORKDIR /app

# Corepack installs the pnpm version named by "packageManager" in package.json.
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack install
RUN --mount=type=cache,id=pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --store-dir /pnpm/store

COPY . .

# Base URL of the API. Next.js inlines it into the JavaScript, so it is fixed
# at build time; an empty value builds a site that offers the sample report only.
ARG NEXT_PUBLIC_API_URL=https://api.webriskaudit.com
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

# _headers is for Workers static assets; nginx.conf sends those headers here.
RUN pnpm build && rm -f out/_headers

# Let the CSP's connect-src allow the API origin baked into the build.
RUN api_origin="$(node -p 'const u = process.env.NEXT_PUBLIC_API_URL; u ? new URL(u).origin : ""')" \
    && sed "s|\${API_ORIGIN}|${api_origin}|" nginx.conf > nginx.rendered.conf

# --- Runtime: nginx as an unprivileged user ----------------------------------
FROM nginxinc/nginx-unprivileged:1.31.7-alpine-slim@sha256:a8cb0f33d51fa107c96fd2bd3a71aaf564ec131e9d2bdf8700944f0ed8b170d7 AS runtime

COPY --from=build /app/nginx.rendered.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/out /usr/share/nginx/webriskaudit
RUN nginx -t

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --start-interval=1s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/"]
