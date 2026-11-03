# syntax=docker/dockerfile:1

# Image of the WebRiskAudit API, built from backend/:
#   docker build -t webriskaudit-api --build-arg REVISION="$(git rev-parse HEAD)" backend
#   docker run --rm -p 8000:8000 webriskaudit-api
# Settings are environment variables, listed in .env.example. The start command
# also reads PORT (default 8000; the healthcheck calls the same port) and
# GRACEFUL_SHUTDOWN_SECONDS (default 8). Base images are pinned by tag and
# digest; update both together.

FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

# --- Build: install the locked dependencies and the project into /app/.venv --
FROM python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS build

COPY --from=uv /uv /usr/local/bin/uv

# Compile bytecode now, because the runtime user cannot write it; copy from the
# cache mount instead of hard-linking; use the image's Python only.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first, so this layer is reused until uv.lock changes.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --no-install-project

# --no-editable installs the package into site-packages, so the runtime stage
# needs the virtual environment only.
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# --- Runtime -----------------------------------------------------------------
FROM python:3.15.0-slim-trixie@sha256:f5b92f2a669a4c347044f29367f31983280b648250ca94dea66f98c53bc87e58 AS runtime

# Unprivileged user; a UID above 10000 is unlikely to match a user on the host.
RUN groupadd --gid 10001 webriskaudit \
    && useradd --uid 10001 --gid webriskaudit --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin webriskaudit

# Owned by root, so the service cannot modify its own code.
COPY --from=build /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --start-interval=1s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % (os.environ.get('PORT') or '8000'), timeout=4)"]

# The commit the image is built from, shown by GET / as "revision". Last, so a
# new commit does not invalidate the layers above.
ARG REVISION=""
LABEL org.opencontainers.image.source="https://github.com/portakalp/webriskaudit" \
      org.opencontainers.image.revision="${REVISION}"
ENV WEBRISKAUDIT_REVISION="${REVISION}"

# One worker per container: the rate limit and the report cache live in
# process memory, so --workers 1 also overrides a platform's WEB_CONCURRENCY.
# "exec" makes uvicorn PID 1, so it receives SIGTERM; in-flight requests get
# GRACEFUL_SHUTDOWN_SECONDS to finish (Cloud Run kills the container 10 s
# after SIGTERM). X-Forwarded-For is never trusted (--no-proxy-headers):
# behind a proxy, the client address comes from CLIENT_IP_HEADER with origin
# authentication (docs/adr/0006-client-ip-behind-cloudflare.md). The access
# log is off because it records client addresses. WebSocket support is off
# (--ws none) because no route uses it and uvicorn logs the client address
# and raw path of every WebSocket handshake; an upgrade request is then
# handled as plain HTTP, so origin authentication refuses it.
CMD ["/bin/sh", "-c", "exec uvicorn webriskaudit.api:app --host 0.0.0.0 --port \"${PORT:-8000}\" --workers 1 --no-proxy-headers --ws none --no-access-log --timeout-graceful-shutdown \"${GRACEFUL_SHUTDOWN_SECONDS:-8}\""]
