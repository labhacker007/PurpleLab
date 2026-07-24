DEV  := docker compose -f docker-compose.yml -f docker-compose.dev.yml
PROD := docker compose -f docker-compose.yml

# Enable BuildKit for all builds (pip + npm cache mounts require it)
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# ── Dev workflow (hot-reload) ─────────────────────────────────────────────────

dev-build:           ## Build dev images (run once, or after package.json / requirements.txt change)
	$(DEV) build frontend

dev:                 ## Start all services in dev mode (HMR + uvicorn --reload)
	$(DEV) up -d

dev-down:            ## Stop dev services
	$(DEV) down

dev-logs:            ## Tail backend + frontend dev logs
	$(DEV) logs -f backend frontend

dev-restart-backend: ## Restart only the backend (after requirements.txt change)
	$(DEV) restart backend

dev-restart-frontend:## Restart only the frontend dev server
	$(DEV) restart frontend

# ── Production builds ─────────────────────────────────────────────────────────
#
# Optimized build strategy:
#   - backend image is shared by celery_worker + celery_beat (no duplicate builds)
#   - pip uses a BuildKit cache mount → unchanged packages are never re-downloaded
#   - npm uses a BuildKit cache mount + npm ci → faster, deterministic installs
#
#   Only rebuild what changed:
#     make build-backend   → requirements.txt or Python code changed
#     make build-frontend  → package.json or TypeScript code changed
#     make build           → rebuild both (full release)
#     make build-hard      → full rebuild with no cache (use when layers are corrupted)

build-backend:       ## Rebuild backend image only (fast: uses pip cache)
	$(PROD) build backend

build-frontend:      ## Rebuild frontend image only (fast: uses npm cache)
	$(PROD) build frontend

build:               ## Rebuild both backend + frontend (uses layer cache)
	$(PROD) build backend frontend

build-hard:          ## Full rebuild from scratch with no cache (slowest — use sparingly)
	$(PROD) build --no-cache backend frontend

# ── Start / Stop ──────────────────────────────────────────────────────────────

up:                  ## Start production stack
	$(PROD) up -d

down:                ## Stop production stack
	$(PROD) down

restart:             ## Restart all production services
	$(PROD) restart

logs:                ## Tail production logs
	$(PROD) logs -f

# ── Maintenance ───────────────────────────────────────────────────────────────

migrate:             ## Run Alembic migrations
	docker exec purplelab-backend alembic upgrade head

shell-backend:       ## Open shell in backend container
	docker exec -it purplelab-backend bash

shell-db:            ## Open psql shell
	docker exec -it purplelab-db psql -U purplelab -d purplelab

test:                ## Run backend test suite
	docker exec purplelab-backend python -m pytest tests/ -v

# ── Release workflow ──────────────────────────────────────────────────────────

release:             ## Full release: rebuild → up → migrate
	$(PROD) build backend frontend
	$(PROD) up -d
	docker exec purplelab-backend alembic upgrade head
	@echo "PurpleLab released and running"

.PHONY: dev-build dev dev-down dev-logs dev-restart-backend dev-restart-frontend \
        build-backend build-frontend build build-hard \
        up down restart logs migrate shell-backend shell-db test release
