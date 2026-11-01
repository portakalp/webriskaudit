# Common tasks for WebRiskAudit. Run "make" to list them.
# Backend commands use uv in backend/, frontend commands pnpm in frontend/.

.DEFAULT_GOAL := help
.PHONY: help install lint typecheck test openapi dev-api dev-web build up down

help: ## List the targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / { printf "  %-10s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

install: ## Install backend and frontend dependencies from the lockfiles
	cd backend && uv sync --locked
	cd frontend && pnpm install --frozen-lockfile

lint: ## Lint and check formatting (ruff, ESLint)
	cd backend && uv run ruff check . && uv run ruff format --check .
	cd frontend && pnpm lint

typecheck: ## Type-check (mypy --strict, tsc)
	cd backend && uv run mypy
	cd frontend && pnpm exec tsc --noEmit

test: ## Run the backend and frontend tests
	cd backend && uv run pytest
	cd frontend && pnpm test

openapi: ## Regenerate backend/openapi.json and frontend/lib/api-types.ts
	cd backend && uv run python scripts/export_openapi.py
	cd frontend && pnpm gen:api

dev-api: ## Run the API with auto-reload on http://localhost:8000
	cd backend && uv run uvicorn webriskaudit.api:app --reload --port 8000

dev-web: ## Run the site in development mode on http://localhost:3000
	cd frontend && pnpm dev

build: ## Build both Docker images
	docker compose build

up: ## Build and start the Docker stack, wait until it is healthy
	docker compose up --build --detach --wait
	@echo "Site: http://localhost:3000  API: http://localhost:8000"

down: ## Stop the Docker stack and remove its containers
	docker compose down
