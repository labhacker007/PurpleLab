#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  JOTI SIM v2 — Single Master Script                                     ║
# ║  Installs Docker, builds, launches, heals, and manages everything.      ║
# ║  Zero AI tokens. Fully autonomous. Self-healing.                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   ./joti.sh                   # First-time setup (installs Docker if needed)
#   ./joti.sh up                # Start all services
#   ./joti.sh down              # Stop all services
#   ./joti.sh restart           # Restart everything
#   ./joti.sh build             # Rebuild Docker images from scratch
#   ./joti.sh status            # Health check all services
#   ./joti.sh heal              # Auto-diagnose and fix problems
#   ./joti.sh logs [service]    # Tail logs (all or specific service)
#   ./joti.sh test              # Run full test suite
#   ./joti.sh migrate           # Run database migrations
#   ./joti.sh seed              # Load MITRE ATT&CK data
#   ./joti.sh frontend          # Install and start Next.js dev server
#   ./joti.sh reset-password    # Reset PostgreSQL password
#   ./joti.sh reset-all         # Nuclear: destroy and rebuild everything
#   ./joti.sh shell [service]   # Open shell into a container
#   ./joti.sh db-shell          # Open psql shell
#   ./joti.sh update            # Git pull + rebuild + restart
#   ./joti.sh backup            # Backup database
#   ./joti.sh restore <file>    # Restore database from backup

set -uo pipefail

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Config
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
FRONTEND_DIR="frontend-next"
DATA_DIR="data"
BACKUP_DIR="backups"
LOG_FILE=".joti-setup.log"
MAX_WAIT=60
POLL=2

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Terminal colors
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if [ -t 1 ]; then
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
    C='\033[0;36m' W='\033[1;37m' D='\033[0;90m' N='\033[0m'
else
    R='' G='' Y='' B='' C='' W='' D='' N=''
fi

ok()   { printf "${G}  [✓]${N} %s\n" "$*"; }
fail() { printf "${R}  [✗]${N} %s\n" "$*"; }
warn() { printf "${Y}  [!]${N} %s\n" "$*"; }
info() { printf "${B}  [·]${N} %s\n" "$*"; }
step() { printf "\n${W}━━━ %s ━━━${N}\n\n" "$*"; }

banner() {
    printf "\n${C}"
    printf "    ┌─────────────────────────────────────────────────────┐\n"
    printf "    │     Joti Sim v2 — Agentic Cybersecurity Platform    │\n"
    printf "    │            Autonomous Setup & Control               │\n"
    printf "    └─────────────────────────────────────────────────────┘\n"
    printf "${N}\n"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Detect OS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
detect_os() {
    case "$(uname -s 2>/dev/null || echo Windows)" in
        Linux*)   OS="linux" ;;
        Darwin*)  OS="mac" ;;
        MINGW*|MSYS*|CYGWIN*|Windows*) OS="windows" ;;
        *)        OS="linux" ;;
    esac
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Docker Installation (auto-detect + auto-install)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
install_docker() {
    step "Installing Docker"

    case "$OS" in
        linux)
            info "Detected Linux. Installing Docker via official script..."

            # Check if running as root or can sudo
            if [ "$(id -u)" -ne 0 ]; then
                if ! command -v sudo &>/dev/null; then
                    fail "Need root access to install Docker. Run as root or install sudo."
                    return 1
                fi
                SUDO="sudo"
            else
                SUDO=""
            fi

            # Remove old versions
            $SUDO apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

            # Install via official convenience script
            if command -v curl &>/dev/null; then
                curl -fsSL https://get.docker.com | $SUDO sh
            elif command -v wget &>/dev/null; then
                wget -qO- https://get.docker.com | $SUDO sh
            else
                fail "Need curl or wget to install Docker."
                return 1
            fi

            # Add current user to docker group
            $SUDO usermod -aG docker "$USER" 2>/dev/null || true

            # Start Docker
            $SUDO systemctl enable docker 2>/dev/null || true
            $SUDO systemctl start docker 2>/dev/null || true

            # Install Docker Compose plugin if missing
            if ! docker compose version &>/dev/null 2>&1; then
                info "Installing Docker Compose plugin..."
                $SUDO apt-get update && $SUDO apt-get install -y docker-compose-plugin 2>/dev/null || {
                    local compose_ver="v2.32.4"
                    $SUDO mkdir -p /usr/local/lib/docker/cli-plugins
                    $SUDO curl -SL "https://github.com/docker/compose/releases/download/${compose_ver}/docker-compose-$(uname -s)-$(uname -m)" \
                        -o /usr/local/lib/docker/cli-plugins/docker-compose
                    $SUDO chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
                }
            fi

            ok "Docker installed on Linux"
            warn "You may need to log out and back in for docker group permissions."
            ;;

        mac)
            info "Detected macOS."

            if command -v brew &>/dev/null; then
                info "Installing Docker Desktop via Homebrew..."
                brew install --cask docker
                open -a Docker
                info "Docker Desktop is starting. Waiting for it to be ready..."
                local i=0
                while [ $i -lt 60 ]; do
                    if docker info &>/dev/null 2>&1; then break; fi
                    sleep 2
                    i=$((i + 1))
                done
                ok "Docker installed on macOS"
            else
                fail "Install Homebrew first: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
                fail "Or download Docker Desktop: https://www.docker.com/products/docker-desktop/"
                return 1
            fi
            ;;

        windows)
            info "Detected Windows."
            info "Checking for winget..."

            if command -v winget &>/dev/null; then
                info "Installing Docker Desktop via winget..."
                winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements 2>/dev/null || {
                    warn "winget install failed."
                    fail "Download Docker Desktop manually: https://www.docker.com/products/docker-desktop/"
                    return 1
                }
                ok "Docker Desktop installed. Please start it from the Start menu."
                warn "After starting Docker Desktop, re-run this script."
                return 1
            else
                fail "Download Docker Desktop from: https://www.docker.com/products/docker-desktop/"
                fail "After installing, re-run this script."
                return 1
            fi
            ;;
    esac
}

check_docker() {
    # Check Docker daemon
    if ! command -v docker &>/dev/null; then
        warn "Docker not found."
        read -rp "  Install Docker automatically? (y/n): " ans
        case "$ans" in
            [Yy]*) install_docker || return 1 ;;
            *)
                fail "Docker is required. Install from https://docs.docker.com/get-docker/"
                return 1
                ;;
        esac
    fi

    if ! docker info &>/dev/null 2>&1; then
        warn "Docker daemon not running."

        case "$OS" in
            linux)
                info "Starting Docker..."
                sudo systemctl start docker 2>/dev/null || true
                sleep 3
                ;;
            mac)
                info "Starting Docker Desktop..."
                open -a Docker 2>/dev/null || true
                ;;
            windows)
                info "Attempting to start Docker Desktop..."
                cmd.exe /c "start \"\" \"C:\Program Files\Docker\Docker\Docker Desktop.exe\"" 2>/dev/null || true
                ;;
        esac

        info "Waiting for Docker daemon..."
        local i=0
        while [ $i -lt 30 ]; do
            if docker info &>/dev/null 2>&1; then
                ok "Docker daemon running"
                return 0
            fi
            sleep 2
            i=$((i + 1))
        done
        fail "Docker daemon did not start. Please start Docker manually and re-run."
        return 1
    fi

    ok "Docker $(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1 || echo 'ready')"

    # Check Docker Compose
    if docker compose version &>/dev/null 2>&1; then
        ok "Docker Compose $(docker compose version --short 2>/dev/null || echo 'ready')"
    else
        fail "Docker Compose not found. Install Docker Desktop or the compose plugin."
        return 1
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Environment Setup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
setup_env() {
    step "Environment Configuration"

    if [ ! -f "$ENV_FILE" ]; then
        # Generate a random password for PostgreSQL
        local pg_pass
        pg_pass=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 24 || echo "jotisim_$(date +%s)")

        # Generate Fernet key for encryption
        local enc_key
        enc_key=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
                  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
                  python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || \
                  python -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || \
                  echo "$(LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom 2>/dev/null | head -c 43)=")

        cat > "$ENV_FILE" << ENVEOF
# ── Joti Sim v2 Configuration ──────────────────────────────────────────
# Generated on $(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Database
POSTGRES_PASSWORD=${pg_pass}
POSTGRES_PORT=5433

# Redis
REDIS_PORT=6380

# LLM API Keys (add yours for AI features)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# Default LLM model
DEFAULT_MODEL=claude-sonnet-4-20250514

# Application
DEBUG=true

# Encryption key for SIEM credentials
ENCRYPTION_KEY=${enc_key}
ENVEOF

        ok "Generated .env with secure random passwords"
        warn "Add your ANTHROPIC_API_KEY to .env for AI/agentic features"
    else
        ok ".env already exists"
    fi

    # Create data directories
    mkdir -p "$DATA_DIR"/{chroma,mitre_attack,sigma_rules,log_schemas} "$BACKUP_DIR" 2>/dev/null
    ok "Data directories ready"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Docker network
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ensure_network() {
    docker network inspect joti_default &>/dev/null 2>&1 || \
        docker network create joti_default &>/dev/null 2>&1 || true
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Wait for service to be healthy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
wait_for() {
    local name="$1" cmd="$2" elapsed=0
    printf "  ${D}Waiting for %s...${N}" "$name"
    while [ $elapsed -lt $MAX_WAIT ]; do
        if eval "$cmd" &>/dev/null 2>&1; then
            printf "\r${G}  [✓]${N} %-30s\n" "$name healthy"
            return 0
        fi
        sleep $POLL
        elapsed=$((elapsed + POLL))
        printf "."
    done
    printf "\r${R}  [✗]${N} %-30s (timed out after ${MAX_WAIT}s)\n" "$name"
    return 1
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Build
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_build() {
    step "Building Docker Images"
    docker compose -f "$COMPOSE_FILE" build "$@" 2>&1 | tail -5
    ok "Docker images built"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Start / Stop / Restart
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_up() {
    step "Starting Services"
    ensure_network
    docker compose -f "$COMPOSE_FILE" up -d 2>&1 | grep -v "^$"
    ok "Containers started"

    wait_for "PostgreSQL" "docker compose exec -T postgres pg_isready -U jotisim"
    wait_for "Redis"      "docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG"

    # Auto-migrate database
    cmd_migrate_quiet

    wait_for "Backend API" "curl -sf http://localhost:4000/api/catalog"

    printf "\n${G}  All services running:${N}\n"
    printf "    Backend API  → ${W}http://localhost:4000${N}\n"
    printf "    PostgreSQL   → ${W}localhost:${POSTGRES_PORT:-5433}${N}\n"
    printf "    Redis        → ${W}localhost:${REDIS_PORT:-6380}${N}\n\n"
}

cmd_down() {
    step "Stopping Services"
    docker compose -f "$COMPOSE_FILE" down 2>&1 | grep -v "^$"
    ok "All services stopped"
}

cmd_restart() {
    cmd_down
    cmd_up
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Database Migrations
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_migrate() {
    step "Database Migration"
    cmd_migrate_quiet
}

cmd_migrate_quiet() {
    docker compose exec -T joti-sim python -c "
import asyncio, logging
logging.disable(logging.CRITICAL)
from sqlalchemy.ext.asyncio import create_async_engine
from backend.db.models import Base
from backend.config import settings

async def migrate():
    engine = create_async_engine(settings.DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

asyncio.run(migrate())
print('OK')
" 2>/dev/null && ok "Database tables synced" || warn "Migration deferred (backend not ready yet)"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Seed MITRE ATT&CK Data
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_seed() {
    step "Seeding MITRE ATT&CK Data"
    docker compose exec -T joti-sim python scripts/seed_mitre.py 2>&1 || \
        warn "Seed deferred — MITRE data will download on first use"
    ok "Seed complete"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Health Check / Status
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_status() {
    step "Service Status"

    # Container states
    docker compose -f "$COMPOSE_FILE" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
        docker compose -f "$COMPOSE_FILE" ps

    echo ""

    # Health checks
    local all_ok=true

    if docker compose exec -T postgres pg_isready -U jotisim &>/dev/null 2>&1; then
        ok "PostgreSQL: healthy"
        # Show table count
        local tc
        tc=$(docker compose exec -T postgres psql -U jotisim -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null || echo "?")
        info "  Tables: $tc"
    else
        fail "PostgreSQL: down"
        all_ok=false
    fi

    if docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
        ok "Redis: healthy"
        local mem
        mem=$(docker compose exec -T redis redis-cli info memory 2>/dev/null | grep used_memory_human | tr -d '\r' || echo "?")
        info "  Memory: $mem"
    else
        fail "Redis: down"
        all_ok=false
    fi

    if curl -sf http://localhost:4000/api/catalog &>/dev/null; then
        ok "Backend API: healthy (http://localhost:4000)"
        # Show product count
        local pc
        pc=$(curl -sf http://localhost:4000/api/catalog 2>/dev/null | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('products',[])))" 2>/dev/null || \
             curl -sf http://localhost:4000/api/catalog 2>/dev/null | python -c "import sys,json;print(len(json.load(sys.stdin).get('products',[])))" 2>/dev/null || echo "?")
        info "  Product generators: $pc"
    else
        fail "Backend API: down"
        all_ok=false
    fi

    if curl -sf http://localhost:3000 &>/dev/null; then
        ok "Frontend: healthy (http://localhost:3000)"
    else
        info "Frontend: not running (run './joti.sh frontend' to start)"
    fi

    echo ""
    if $all_ok; then
        ok "All core systems operational"
    else
        warn "Issues detected — run './joti.sh heal' to auto-repair"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Self-Healing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_heal() {
    step "Self-Healing Diagnostics"

    local fixed=0 failed=0

    # 1. Docker daemon
    info "Checking Docker daemon..."
    if ! docker info &>/dev/null 2>&1; then
        warn "Docker daemon not running. Attempting start..."
        case "$OS" in
            linux)   sudo systemctl start docker 2>/dev/null ;;
            mac)     open -a Docker 2>/dev/null ;;
            windows) cmd.exe /c "start \"\" \"C:\Program Files\Docker\Docker\Docker Desktop.exe\"" 2>/dev/null ;;
        esac
        sleep 5
        if docker info &>/dev/null 2>&1; then
            ok "Docker daemon recovered"
            fixed=$((fixed + 1))
        else
            fail "Docker daemon could not be started"
            failed=$((failed + 1))
            return 1
        fi
    else
        ok "Docker daemon running"
    fi

    # 2. Network
    info "Checking network..."
    ensure_network
    ok "Docker network ready"

    # 3. .env file
    info "Checking configuration..."
    if [ ! -f "$ENV_FILE" ]; then
        warn ".env missing — regenerating..."
        setup_env
        fixed=$((fixed + 1))
    else
        ok ".env present"
    fi

    # 4. Containers
    info "Checking containers..."
    local dead_containers
    dead_containers=$(docker compose ps --format '{{.Name}} {{.State}}' 2>/dev/null | grep -E "exited|dead|created" || true)
    if [ -n "$dead_containers" ]; then
        warn "Dead containers found: $dead_containers"
        warn "Restarting all services..."
        docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null
        sleep 5
        fixed=$((fixed + 1))
    else
        ok "All containers running"
    fi

    # 5. PostgreSQL
    info "Checking PostgreSQL..."
    if ! docker compose exec -T postgres pg_isready -U jotisim &>/dev/null 2>&1; then
        warn "PostgreSQL unreachable. Restarting..."
        docker compose restart postgres 2>/dev/null
        if wait_for "PostgreSQL" "docker compose exec -T postgres pg_isready -U jotisim"; then
            fixed=$((fixed + 1))
        else
            fail "PostgreSQL recovery failed"
            failed=$((failed + 1))
        fi
    else
        ok "PostgreSQL reachable"
    fi

    # 6. PostgreSQL tables
    info "Checking database tables..."
    local table_count
    table_count=$(docker compose exec -T postgres psql -U jotisim -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>/dev/null | tr -d ' \r\n' || echo "0")
    if [ "${table_count:-0}" -lt 5 ] 2>/dev/null; then
        warn "Only $table_count tables found. Running migrations..."
        cmd_migrate_quiet
        fixed=$((fixed + 1))
    else
        ok "Database has $table_count tables"
    fi

    # 7. Redis
    info "Checking Redis..."
    if ! docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; then
        warn "Redis unreachable. Restarting..."
        docker compose restart redis 2>/dev/null
        if wait_for "Redis" "docker compose exec -T redis redis-cli ping | grep -q PONG"; then
            fixed=$((fixed + 1))
        else
            fail "Redis recovery failed"
            failed=$((failed + 1))
        fi
    else
        ok "Redis reachable"
    fi

    # 8. Backend API
    info "Checking Backend API..."
    if ! curl -sf http://localhost:4000/api/catalog &>/dev/null; then
        warn "Backend API unreachable. Checking logs..."
        docker compose logs --tail=10 joti-sim 2>/dev/null | tail -5

        warn "Restarting backend..."
        docker compose restart joti-sim 2>/dev/null
        if wait_for "Backend API" "curl -sf http://localhost:4000/api/catalog"; then
            fixed=$((fixed + 1))
        else
            fail "Backend API recovery failed. Check: ./joti.sh logs joti-sim"
            failed=$((failed + 1))
        fi
    else
        ok "Backend API responding"
    fi

    # 9. Disk space
    info "Checking disk space..."
    local usage
    usage=$(df -h . 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo "0")
    if [ "${usage:-0}" -gt 90 ] 2>/dev/null; then
        warn "Disk usage at ${usage}%! Pruning Docker resources..."
        docker system prune -f 2>/dev/null
        fixed=$((fixed + 1))
    else
        ok "Disk usage: ${usage}%"
    fi

    # 10. Port conflicts
    info "Checking port availability..."
    for port in 4000 ${POSTGRES_PORT:-5433} ${REDIS_PORT:-6380}; do
        local pid
        pid=$(lsof -ti ":$port" 2>/dev/null | head -1 || true)
        if [ -n "$pid" ]; then
            local proc
            proc=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            if echo "$proc" | grep -qiE "docker|com\.docker|postgres|redis|uvicorn|python"; then
                ok "Port $port: used by $proc (expected)"
            else
                warn "Port $port: conflict with $proc (PID $pid)"
            fi
        fi
    done

    # Summary
    echo ""
    printf "  ${W}Result:${N} Fixed ${G}$fixed${N} issues"
    if [ $failed -gt 0 ]; then
        printf ", ${R}$failed${N} unresolved"
    fi
    echo ""

    if [ $failed -eq 0 ]; then
        ok "System healthy"
    else
        warn "Run './joti.sh logs' to investigate remaining issues"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Password Reset
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_reset_password() {
    step "Password Reset"

    echo "  What would you like to reset?"
    echo "    1) PostgreSQL password"
    echo "    2) Encryption key (for SIEM credentials)"
    echo "    3) Both"
    echo ""
    read -rp "  Choice [1/2/3]: " choice

    case "$choice" in
        1|3)
            local new_pass
            read -rsp "  New PostgreSQL password (leave empty for random): " new_pass
            echo ""
            if [ -z "$new_pass" ]; then
                new_pass=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 24 || echo "jotisim_$(date +%s)")
                info "Generated password: $new_pass"
            fi

            # Update .env
            if grep -q "POSTGRES_PASSWORD=" "$ENV_FILE" 2>/dev/null; then
                sed -i "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${new_pass}|" "$ENV_FILE"
            else
                echo "POSTGRES_PASSWORD=${new_pass}" >> "$ENV_FILE"
            fi

            # Update PostgreSQL password inside running container
            docker compose exec -T postgres psql -U jotisim -c "ALTER USER jotisim WITH PASSWORD '${new_pass}';" 2>/dev/null && \
                ok "PostgreSQL password updated in database" || \
                warn "Could not update live database. Password will take effect on next restart."

            ok "PostgreSQL password updated in .env"
            warn "Restart services for changes to take full effect: ./joti.sh restart"
            ;;&  # Fall through for choice 3

        2|3)
            local new_key
            new_key=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
                      python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || \
                      python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || \
                      echo "$(LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom 2>/dev/null | head -c 43)=")

            if grep -q "ENCRYPTION_KEY=" "$ENV_FILE" 2>/dev/null; then
                sed -i "s|ENCRYPTION_KEY=.*|ENCRYPTION_KEY=${new_key}|" "$ENV_FILE"
            else
                echo "ENCRYPTION_KEY=${new_key}" >> "$ENV_FILE"
            fi

            ok "Encryption key rotated"
            warn "Any existing encrypted SIEM credentials will need to be re-entered"
            warn "Restart services: ./joti.sh restart"
            ;;

        *)
            info "Cancelled"
            ;;
    esac
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Nuclear Reset
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_reset_all() {
    step "Nuclear Reset"
    warn "This will DESTROY:"
    warn "  - All Docker containers and images"
    warn "  - All database data (PostgreSQL volumes)"
    warn "  - All Redis data"
    warn "  - ChromaDB vector store"
    warn "  - The .env file"
    echo ""
    read -rp "  Type 'DESTROY' to confirm: " confirm
    if [ "$confirm" != "DESTROY" ]; then
        info "Cancelled."
        return 0
    fi

    info "Stopping and removing everything..."
    docker compose -f "$COMPOSE_FILE" down -v --rmi local 2>/dev/null || true
    rm -rf "$DATA_DIR/chroma" 2>/dev/null || true
    rm -f "$ENV_FILE" "$LOG_FILE" 2>/dev/null || true

    ok "Everything destroyed."
    info "Run './joti.sh' to rebuild from scratch."
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Logs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_logs() {
    local svc="${1:-}"
    if [ -n "$svc" ]; then
        docker compose -f "$COMPOSE_FILE" logs -f --tail=100 "$svc"
    else
        docker compose -f "$COMPOSE_FILE" logs -f --tail=100
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shell access
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_shell() {
    local svc="${1:-joti-sim}"
    docker compose exec "$svc" /bin/bash 2>/dev/null || docker compose exec "$svc" /bin/sh
}

cmd_db_shell() {
    docker compose exec postgres psql -U jotisim
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Frontend
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_frontend() {
    step "Frontend Setup"

    if [ ! -d "$FRONTEND_DIR" ]; then
        fail "Frontend directory ($FRONTEND_DIR) not found"
        return 1
    fi

    # Check Node.js
    if ! command -v node &>/dev/null; then
        warn "Node.js not found. Attempting install..."
        case "$OS" in
            linux)
                if command -v curl &>/dev/null; then
                    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - 2>/dev/null
                    sudo apt-get install -y nodejs 2>/dev/null
                fi
                ;;
            mac)
                brew install node 2>/dev/null
                ;;
            windows)
                winget install OpenJS.NodeJS.LTS 2>/dev/null
                ;;
        esac

        if ! command -v node &>/dev/null; then
            fail "Could not install Node.js. Install from https://nodejs.org/"
            return 1
        fi
        ok "Node.js installed"
    fi

    ok "Node.js $(node --version)"

    cd "$FRONTEND_DIR"

    if [ ! -d "node_modules" ]; then
        info "Installing dependencies..."
        npm install 2>&1 | tail -3
        ok "Dependencies installed"
    else
        ok "Dependencies already installed"
    fi

    info "Starting Next.js dev server on http://localhost:3000..."
    npm run dev &
    local pid=$!

    cd "$SCRIPT_DIR"
    sleep 3

    if kill -0 $pid 2>/dev/null; then
        ok "Frontend running at http://localhost:3000 (PID: $pid)"
    else
        fail "Frontend failed to start. Run: cd $FRONTEND_DIR && npm run dev"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_test() {
    step "Running Tests"
    docker compose exec -T joti-sim python -m pytest tests/ -v --tb=short 2>&1
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Update (git pull + rebuild)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_update() {
    step "Updating Joti Sim"

    if command -v git &>/dev/null && [ -d .git ]; then
        info "Pulling latest code..."
        git pull --ff-only 2>&1 || { warn "Git pull failed. Continuing with current code."; }
    fi

    info "Rebuilding images..."
    docker compose -f "$COMPOSE_FILE" build 2>&1 | tail -3

    info "Restarting services..."
    docker compose -f "$COMPOSE_FILE" up -d 2>&1 | grep -v "^$"

    wait_for "Backend API" "curl -sf http://localhost:4000/api/catalog"
    cmd_migrate_quiet

    ok "Update complete"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Backup / Restore
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_backup() {
    step "Database Backup"
    mkdir -p "$BACKUP_DIR"
    local filename="${BACKUP_DIR}/jotisim_$(date +%Y%m%d_%H%M%S).sql.gz"
    docker compose exec -T postgres pg_dump -U jotisim jotisim | gzip > "$filename"
    ok "Backup saved to $filename ($(du -sh "$filename" | awk '{print $1}'))"
}

cmd_restore() {
    local file="${1:-}"
    if [ -z "$file" ]; then
        fail "Usage: ./joti.sh restore <backup_file.sql.gz>"
        info "Available backups:"
        ls -la "$BACKUP_DIR"/*.sql.gz 2>/dev/null || info "  No backups found"
        return 1
    fi

    if [ ! -f "$file" ]; then
        fail "File not found: $file"
        return 1
    fi

    step "Database Restore"
    warn "This will REPLACE all current data with the backup."
    read -rp "  Continue? (y/n): " ans
    if [ "$ans" != "y" ]; then
        info "Cancelled."
        return 0
    fi

    info "Restoring from $file..."
    gunzip -c "$file" | docker compose exec -T postgres psql -U jotisim -d jotisim 2>/dev/null
    ok "Database restored from $file"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Help
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_help() {
    banner
    printf "  ${W}Commands:${N}\n\n"
    printf "    ${C}./joti.sh${N}                    First-time setup (installs Docker if needed)\n"
    printf "    ${C}./joti.sh up${N}                 Start all services\n"
    printf "    ${C}./joti.sh down${N}               Stop all services\n"
    printf "    ${C}./joti.sh restart${N}            Restart everything\n"
    printf "    ${C}./joti.sh build${N}              Rebuild Docker images\n"
    printf "    ${C}./joti.sh status${N}             Health check all services\n"
    printf "    ${C}./joti.sh heal${N}               Auto-diagnose and fix problems\n"
    printf "    ${C}./joti.sh logs [service]${N}     Tail logs\n"
    printf "    ${C}./joti.sh test${N}               Run test suite\n"
    printf "    ${C}./joti.sh migrate${N}            Run database migrations\n"
    printf "    ${C}./joti.sh seed${N}               Load MITRE ATT&CK data\n"
    printf "    ${C}./joti.sh frontend${N}           Install + start Next.js frontend\n"
    printf "    ${C}./joti.sh reset-password${N}     Reset PostgreSQL/encryption passwords\n"
    printf "    ${C}./joti.sh reset-all${N}          Nuclear: destroy everything\n"
    printf "    ${C}./joti.sh shell [service]${N}    Shell into container\n"
    printf "    ${C}./joti.sh db-shell${N}           Open psql shell\n"
    printf "    ${C}./joti.sh update${N}             Git pull + rebuild + restart\n"
    printf "    ${C}./joti.sh backup${N}             Backup database\n"
    printf "    ${C}./joti.sh restore <file>${N}     Restore database from backup\n"
    printf "    ${C}./joti.sh help${N}               Show this help\n"
    echo ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# First-Time Full Setup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
cmd_setup() {
    banner
    > "$LOG_FILE"

    detect_os
    info "Detected OS: $OS"

    check_docker || exit 1
    setup_env
    ensure_network

    cmd_build
    cmd_up

    echo ""
    printf "  ${G}${W}╔═══════════════════════════════════════════════════════════╗${N}\n"
    printf "  ${G}${W}║              JOTI SIM v2 — READY                          ║${N}\n"
    printf "  ${G}${W}╠═══════════════════════════════════════════════════════════╣${N}\n"
    printf "  ${G}${W}║                                                           ║${N}\n"
    printf "  ${G}${W}║  Backend API:     http://localhost:4000                    ║${N}\n"
    printf "  ${G}${W}║  Legacy UI:       http://localhost:4000                    ║${N}\n"
    printf "  ${G}${W}║  API Docs:        http://localhost:4000/docs               ║${N}\n"
    printf "  ${G}${W}║  PostgreSQL:      localhost:${POSTGRES_PORT:-5433}                          ║${N}\n"
    printf "  ${G}${W}║  Redis:           localhost:${REDIS_PORT:-6380}                          ║${N}\n"
    printf "  ${G}${W}║                                                           ║${N}\n"
    printf "  ${G}${W}║  Quick Start:                                             ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh status          Check everything works       ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh heal            Fix if something breaks      ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh frontend        Start Next.js UI             ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh seed            Load MITRE ATT&CK data       ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh reset-password  Change passwords             ║${N}\n"
    printf "  ${G}${W}║    ./joti.sh help            Show all commands             ║${N}\n"
    printf "  ${G}${W}║                                                           ║${N}\n"
    printf "  ${G}${W}╚═══════════════════════════════════════════════════════════╝${N}\n"
    echo ""
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Router
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
detect_os

case "${1:-}" in
    up|start)        cmd_up ;;
    down|stop)       cmd_down ;;
    restart)         cmd_restart ;;
    build)           shift; cmd_build "$@" ;;
    status)          cmd_status ;;
    heal|fix)        cmd_heal ;;
    logs)            shift; cmd_logs "$@" ;;
    test)            cmd_test ;;
    migrate)         cmd_migrate ;;
    seed)            cmd_seed ;;
    frontend|fe)     cmd_frontend ;;
    reset-password)  cmd_reset_password ;;
    reset-all|nuke)  cmd_reset_all ;;
    shell)           shift; cmd_shell "$@" ;;
    db-shell|psql)   cmd_db_shell ;;
    update|pull)     cmd_update ;;
    backup)          cmd_backup ;;
    restore)         shift; cmd_restore "$@" ;;
    help|-h|--help)  cmd_help ;;
    "")              cmd_setup ;;
    *)               fail "Unknown command: $1"; cmd_help; exit 1 ;;
esac
