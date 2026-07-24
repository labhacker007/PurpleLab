# PurpleLab — Installation & Build Guide

**Optimized for fast iteration. First install ~5 min. Subsequent rebuilds <60s.**

---

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Docker Desktop | 24.x+ | BuildKit must be enabled (default in 24+) |
| Docker Compose | V2 (`docker compose`) | Included with Docker Desktop |
| RAM | 4 GB free | Backend 2 GB limit, frontend 512 MB |
| Disk | 5 GB free | Images + PostgreSQL data |

> **Windows users:** Use Git Bash or WSL2 to run `purplelab.sh`. PowerShell works for `docker` commands directly.

---

## Quick Start (First Time)

```bash
git clone https://github.com/labhacker007/PurpleLab.git
cd PurpleLab

# One command: builds images, starts services, runs migrations
bash purplelab.sh release
```

Services will be available at:
- **Backend API** → `http://localhost:8002`
- **Frontend** → `http://localhost:3002`
- **API Docs** → `http://localhost:8002/docs`

---

## Build Commands

### Recommended: selective builds (fastest)

Only rebuild what actually changed:

```bash
# Python code or requirements.txt changed → backend only (~30–60s with cache)
bash purplelab.sh build backend

# TypeScript or package.json changed → frontend only (~60–90s with cache)
bash purplelab.sh build frontend

# Both changed → rebuild both
bash purplelab.sh build

# Full rebuild with no cache (use when layers are corrupted or dep tree broken)
bash purplelab.sh build --no-cache
```

### Alternative: Makefile

```bash
make build-backend    # backend only
make build-frontend   # frontend only
make build            # both (uses cache)
make build-hard       # both, no cache
make release          # build + up + migrate
```

---

## Why Builds Are Fast

### 1. BuildKit cache mounts

The backend Dockerfile uses a BuildKit pip cache:

```dockerfile
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt
```

The frontend Dockerfile uses a BuildKit npm cache:

```dockerfile
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline
```

**Effect:** On a rebuild where `requirements.txt` or `package-lock.json` hasn't changed, the install step completes in seconds instead of minutes. Packages are stored in a Docker-managed cache volume that persists between builds.

### 2. Shared backend image

`celery_worker` and `celery_beat` do **not** have their own `build:` config — they use `image: purplelab-backend`, which is the image already built for the backend service. This eliminates two redundant full pip install runs.

**Before:** 4 images built (backend + celery_worker + celery_beat + frontend)  
**After:** 2 images built (backend + frontend); worker and beat reuse backend

### 3. Deterministic npm installs

The frontend uses `npm ci` (not `npm install`). `npm ci`:
- Reads `package-lock.json` directly — no dependency resolution
- Fails loudly if lockfile is out of sync (prevents silent version drift)
- Is ~30% faster than `npm install` for the same packages

### 4. Layer ordering

Both Dockerfiles copy dependency files first (`requirements.txt` / `package-lock.json`), install deps, then copy application code. This means code changes don't invalidate the pip/npm layer.

```
COPY requirements.txt .          ← layer A: only changes when deps change
RUN pip install ...              ← layer B: cached unless layer A changed
COPY . .                         ← layer C: changes every code edit (cheap)
```

---

## Typical Build Times

| Scenario | Time |
|----------|------|
| First install (no cache) | ~5–8 min |
| Code change, deps unchanged | ~10–30s (cache hit) |
| `requirements.txt` changed | ~2–3 min (pip re-installs changed packages only) |
| `package-lock.json` changed | ~2–4 min (npm re-installs changed packages only) |
| `--no-cache` full rebuild | ~5–8 min |

---

## Service Architecture

```
docker compose up -d starts 6 containers:

  purplelab-db        PostgreSQL 16  → port 5433
  purplelab-redis     Redis 7        → port 6380
  purplelab-backend   FastAPI        → port 8002  (built from backend/Dockerfile)
  purplelab-worker    Celery worker  → (reuses purplelab-backend image)
  purplelab-beat      Celery beat    → (reuses purplelab-backend image)
  purplelab-frontend  Next.js 15     → port 3002  (built from frontend-next/Dockerfile)
```

---

## Environment Configuration

On first run, `purplelab.sh` auto-generates `.env` with secure random passwords:

```bash
POSTGRES_PASSWORD=<random-24-char>
ENCRYPTION_KEY=<random-fernet-key>
PURPLELAB_MCP_API_KEY=purplelab-<random-32-char>
PURPLELAB_BACKEND_PORT=8002
PURPLELAB_FRONTEND_PORT=3002
```

Add your LLM API key for agentic features:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

---

## Day-to-Day Workflow

```bash
# Start/stop
bash purplelab.sh up
bash purplelab.sh down

# After changing Python code (no dep changes)
docker restart purplelab-backend purplelab-worker purplelab-beat

# After changing requirements.txt
bash purplelab.sh build backend
bash purplelab.sh up

# After changing frontend TypeScript
bash purplelab.sh build frontend
bash purplelab.sh up

# Run migrations
bash purplelab.sh migrate

# View logs
bash purplelab.sh logs
bash purplelab.sh logs backend

# Health check
bash purplelab.sh status

# Full teardown and rebuild from scratch
bash purplelab.sh reset-all    # destroys data — asks for confirmation
bash purplelab.sh release
```

---

## Joti Integration

PurpleLab connects to Joti (port 8000) via the shared `joti_default` Docker network. The network is created automatically on first `purplelab.sh up`.

To enable Joti → PurpleLab auto-registration:

```bash
# .env
JOTI_BASE_URL=http://host.docker.internal:8000
JOTI_API_KEY=<your-joti-api-key>
PURPLELAB_MCP_AUTO_REGISTER_JOTI=true
```

---

## Troubleshooting

**Build fails with "cache mount not supported"**  
→ BuildKit is not enabled. Set `DOCKER_BUILDKIT=1` before running docker commands, or upgrade Docker Desktop to 24+.

**`npm ci` fails with "lockfile mismatch"**  
→ Run `npm install` locally in `frontend-next/` to update `package-lock.json`, commit it, then rebuild.

**Container exits immediately after start**  
→ Check logs: `bash purplelab.sh logs backend`  
→ Most common cause: missing `.env` or wrong `DATABASE_URL`. Run `bash purplelab.sh heal`.

**Port conflict (8002 or 3002 already in use)**  
→ Edit `.env`: change `PURPLELAB_BACKEND_PORT` and `PURPLELAB_FRONTEND_PORT`.

**Old images still running after build**  
→ `docker compose up -d` replaces containers with the new image. If it still shows old code, check `docker compose ps` — the container may not have been recreated. Run `docker compose up -d --force-recreate`.
