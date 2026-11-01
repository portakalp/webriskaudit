# syntax=docker/dockerfile:1

# Image of the WebRiskAudit API, built from backend/:
#   docker build -t webriskaudit-api backend
#   docker run --rm -p 8000:8000 webriskaudit-api
# Settings are environment variables, listed in .env.example. Base images are
# pinned by tag and digest; update both together.

FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv

# --- Build: install the locked dependencies and the project into /app/.venv --
FROM python:3.12.16-slim-trixie@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07 AS build

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
FROM python:3.12.16-slim-trixie@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07 AS runtime

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
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"]

# One worker per container: the rate limit and the report cache live in
# process memory. "exec" makes uvicorn PID 1, so it receives SIGTERM.
# X-Forwarded-For is never trusted (--no-proxy-headers): behind a proxy, the
# client address comes from CLIENT_IP_HEADER with origin authentication
# (docs/adr/0006-client-ip-behind-cloudflare.md).
CMD ["/bin/sh", "-c", "exec uvicorn webriskaudit.api:app --host 0.0.0.0 --port 8000 --no-proxy-headers"]
