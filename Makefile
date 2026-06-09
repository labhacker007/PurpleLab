DEV  := docker compose -f docker-compose.yml -f docker-compose.dev.yml
PROD := docker compose -f docker-compose.yml

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

# ── Production workflow ───────────────────────────────────────────────────────

up:                  ## Start production stack
	$(PROD) up -d

down:                ## Stop production stack
	$(PROD) down

build:               ## Full production rebuild from scratch
	$(PROD) build

logs:                ## Tail production logs
	$(PROD) logs -f

restart:             ## Restart all production services
	$(PROD) restart

# ── Maintenance ───────────────────────────────────────────────────────────────

migrate:             ## Run Alembic migrations
	docker exec purplelab-backend alembic upgrade head

shell-backend:       ## Open shell in backend container
	docker exec -it purplelab-backend bash

shell-db:            ## Open psql shell
	docker exec -it purplelab-db psql -U purplelab -d purplelab

test:                ## Run backend test suite
	docker exec purplelab-backend python -m pytest tests/ -v

.PHONY: dev-build dev dev-down dev-logs dev-restart-backend dev-restart-frontend \
        up down build logs restart migrate shell-backend shell-db test
