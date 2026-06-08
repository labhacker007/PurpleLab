# PurpleLab Codebase Audit Report

**Date:** 2026-06-08  
**Scope:** Full codebase audit — backend, agent tools, pipeline engine, scoring, API surface  
**Audited by:** Automated deep-code analysis + manual review  
**Status:** 9 critical/high findings, 3 medium findings, 37 API modules with ~90% untested surface

---

## Executive Summary

The PurpleLab simulation platform has a solid architectural foundation: the simulation execution engine, DES/IHDS scoring formulas, and pipeline execution DAG are all correctly designed. However, three critical runtime bugs will cause `AttributeError` crashes in production, one critical security vulnerability exposes API keys in plaintext, and several declared features (SIEM push operations, TIP integration, gap-triggered simulation) return hardcoded or stub responses. Test coverage covers approximately 10% of the API surface.

**Immediate action required before any production deployment:**
1. Fix `Environment.status` / `Environment.config` attribute errors
2. Encrypt API keys in `model_config.py`
3. Replace 47 hardcoded `localhost:8000` URLs with configuration

---

## Critical Issues

### C-1 — Environment Model Missing Attributes
**Severity:** CRITICAL — Runtime crash  
**Files:** `backend/agent/tools/platform_tools.py` lines 49, 67  
**Status:** Will crash on every call to `list_environments()` and `get_environment()`

**What's wrong:**

The `Environment` SQLAlchemy model (`backend/db/models.py`, lines 82–102) defines these columns:

```
id, name, description, siem_platform, edr_persona, siem_persona, idp_persona,
firewall_persona, network_persona, log_sources, settings, created_at, updated_at
```

The agent tools reference two columns that do not exist:

```python
# platform_tools.py line 49 — inside _list_environments()
"status": e.status,       # AttributeError: 'Environment' has no attribute 'status'

# platform_tools.py line 67 — inside _get_environment()
"status": env.status,     # AttributeError
"config": env.config,     # AttributeError
```

**Fix options (pick one):**
- Option A: Add `status = Column(String(32), default="active")` and `config = Column(JSON, default={})` to the `Environment` model + create Alembic migration
- Option B: Remove `status` and `config` from the tool return dict; substitute `settings` for `config`

**Recommended fix:** Option A — these fields are semantically meaningful for environment lifecycle management.

---

### C-2 — API Keys Stored in Plaintext
**Severity:** CRITICAL — Security vulnerability (CWE-312: Cleartext Storage of Sensitive Information)  
**Files:** `backend/api/v2/model_config.py` line 263  
**Status:** Every provider API key (Anthropic, OpenAI, Google, etc.) stored unencrypted in PostgreSQL

**What's wrong:**

```python
# model_config.py line 263
existing.encrypted_key = req.api_key   # TODO: encrypt with Fernet
```

The column is named `encrypted_key` but stores raw plaintext. The SIEM module correctly implements Fernet encryption (`backend/api/v2/siem.py` lines 99–137) — the same pattern was never applied here.

**Fix:**

```python
from cryptography.fernet import Fernet
import os

def _get_fernet():
    key = os.environ.get("SECRET_KEY_FERNET")
    if not key:
        raise RuntimeError("SECRET_KEY_FERNET not set")
    return Fernet(key.encode())

# In create/update endpoint:
existing.encrypted_key = _get_fernet().encrypt(req.api_key.encode()).decode()

# In read/use endpoint:
raw_key = _get_fernet().decrypt(existing.encrypted_key.encode()).decode()
```

**Note:** Requires migrating existing plaintext keys on deploy. Add a one-time migration script that reads, re-encrypts, and saves all existing keys.

---

### C-3 — 47 Hardcoded `localhost:8000` URLs in Production Code
**Severity:** CRITICAL — Breaks all deployment outside localhost  
**Files:**
- `backend/agent/pipeline/blocks.py` — 11 instances (all 12 pipeline block functions)
- `backend/agent/tools/platform_tools.py` — 26 instances (all platform tool functions)
- `backend/mcp/server.py` — 2 instances

**What's wrong:**

Every pipeline block and agent tool makes HTTP calls like:

```python
r = await http.post("http://localhost:8000/api/v2/environments", json=payload)
r = await http.get("http://localhost:8000/api/v2/scenarios", params=params)
r = await http.post("http://localhost:8000/api/v2/use-cases", json=payload)
```

This architecture creates a **circular HTTP loop**: API request → pipeline block → HTTP back to same API. It also:
- Makes blocks impossible to unit test without a live server
- Fails on any deployment where the service isn't at `localhost:8000` (Docker networking, cloud deployment, tests)
- Adds ~5–20ms latency per block for a local TCP round-trip

**Fix:** Introduce a base URL config:

```python
# backend/core/config.py
import os
PURPLELAB_API_BASE = os.getenv("PURPLELAB_API_BASE", "http://localhost:8000")
```

Then in blocks.py and platform_tools.py:

```python
from backend.core.config import PURPLELAB_API_BASE
r = await http.post(f"{PURPLELAB_API_BASE}/api/v2/environments", json=payload)
```

**Long-term fix:** Convert blocks to call service functions directly instead of HTTP, eliminating the circular dependency. See M-1 below.

---

## High Severity Issues

### H-1 — DES/IHDS Scoring Returns Hardcoded Demo Data
**Severity:** HIGH — Feature non-functional  
**Files:** `backend/api/v2/log_sources.py` lines 688–719; `backend/scoring/des.py`; `backend/scoring/ihds.py`

**What's wrong:**

The scoring formulas are mathematically complete and correct:
- `des.py`: 5-component weighted geometric mean (breadth, depth, freshness, pass_rate, signal)
- `ihds.py`: Multiplicative composite (Intel × Hunt × Detection × 100)

But the API endpoints that call them feed hardcoded demo rule data:

```python
# log_sources.py line 693
# TODO: load from database when persistence is wired
# Using demo data for now
demo_rules = [
    RuleSummary(rule_id="demo-1", technique_id="T1059", ...),
    RuleSummary(rule_id="demo-2", technique_id="T1078", ...),
]
```

**What's needed:**
1. Query `ImportedRule` table for all active rules associated with the org
2. Query `RuleTestResult` table for recent test outcomes (pass/fail per rule)
3. Compute per-rule freshness from `last_tested_at`
4. Feed real data into the scoring functions

**Gap analysis endpoint** (`GET /api/v2/scoring/gaps`) has the same problem — returns hardcoded technique gaps instead of computing them from the difference between `ImportedRule` coverage and all ATT&CK techniques in scope.

---

### H-2 — SIEM Tools Raise `NotImplementedError`
**Severity:** HIGH — Agent cannot deploy rules or test connections  
**Files:** `backend/agent/tools/siem_tools.py` lines 167–250

Three critical agent tools always return failure:

```python
# siem_tools.py ~line 200
try:
    result = await siem_service.test_connection(connection_id)
except NotImplementedError:
    return {"status": "not_yet_implemented", "message": "..."}

# ~line 237
try:
    result = await siem_service.push_logs(connection_id, log_data)
except NotImplementedError:
    return {"status": "not_yet_implemented", "message": "..."}

# ~line 250
try:
    result = await siem_service.push_rule(connection_id, rule_yaml)
except NotImplementedError:
    return {"status": "not_yet_implemented", "message": "..."}
```

The `ConnectionManager` class the tools call has these methods as stubs. Until implemented, the agent pipeline step `deploy_to_siem` will always appear to fail.

**Implementation needed:** HTTP client calls to the configured SIEM connector (Splunk REST API, Sentinel Log Analytics API, Elastic API) using stored credentials from the SIEM connection record.

---

### H-3 — TIP Search Endpoint is a Permanent Stub
**Severity:** HIGH — Feature non-functional  
**Files:** `backend/api/v2/threat_profiles.py` lines 173–190

```python
@router.get("/tip-search")
async def tip_search(...) -> dict[str, Any]:
    return {
        "results": [],
        "total": 0,
        "message": "Connect TIP integration to enable live search",
        "tip_connected": False,
    }
```

This always returns empty. Intended to search Joti (the connected TIP) for TTPs, actors, or IOCs matching a query.

**Implementation needed:** HTTP call to Joti's `/api/threat-actors` and `/api/intelligence` endpoints using the stored Joti API connection. Joti's API is documented in `c:/Projects/Joti/CLAUDE.md`.

---

### H-4 — 30+ Silent `except Exception: pass` Blocks
**Severity:** HIGH — Makes production debugging impossible  
**Files:** `backend/api/v2/dashboard.py` (20+ blocks), `backend/api/v2/admin.py` (~10 blocks)

```python
# dashboard.py — repeated pattern across every metric
try:
    result["active_sessions"] = await db.scalar(select(func.count()).select_from(SimulationSession).where(...))
except Exception:
    pass   # returns 0 silently — no log, no trace, no alert
```

When a metric query fails (missing column, DB connectivity issue, schema drift), the dashboard returns zeros with no indication anything is wrong. This has already hidden at least one bug (the `KnowledgeEntry` reference — see M-2).

**Fix:** Replace `pass` with at minimum `logger.warning("dashboard_metric_error metric=%s err=%s", metric_name, exc, exc_info=True)`.

---

### H-5 — ~90% of API Surface Has Zero Tests
**Severity:** HIGH — No regression safety net  

**What has tests** (in `tests/integration/test_api_legacy.py`):
- Sessions CRUD + start/stop
- Events list with pagination
- Preview (product simulation)
- Catalog (product listing)

**What has zero tests** (~37 API modules, ~150+ endpoints):
- All admin endpoints
- All dashboard endpoints
- All threat profile endpoints
- All scoring endpoints (DES, IHDS, gaps, leaderboard)
- All use case endpoints
- All pipeline endpoints
- All SIEM endpoints
- All rules/sigma endpoints
- All environment endpoints
- All AI engine / model config endpoints
- All HITL endpoints
- All agent tool functions (40+)

---

## Medium Severity Issues

### M-1 — Pipeline Blocks Make HTTP Instead of Direct Service Calls
**Severity:** MEDIUM — Structural, works but fragile  
**Files:** `backend/agent/pipeline/blocks.py` — all 12 block functions

All blocks use `httpx.AsyncClient` to call the same service. The correct architecture is to import and call the service/database layer directly:

```python
# Current (wrong)
async def _blk_create_environment(name, ...):
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.post("http://localhost:8000/api/v2/environments", json={"name": name})

# Correct
from backend.services.environment_service import create_environment
async def _blk_create_environment(name, ...):
    env = await create_environment(name=name, ...)
    return {"environment_id": str(env.id), "environment_name": env.name}
```

This removes the circular loop, eliminates network latency per block, and makes blocks testable without a running server.

---

### M-2 — `KnowledgeEntry` Model Reference on Missing Model
**Severity:** MEDIUM — Silent dashboard failure  
**Files:** `backend/api/v2/dashboard.py` lines 144–149

```python
if hasattr(m, "KnowledgeEntry"):
    result["knowledge_entries_count"] = await db.scalar(
        select(func.count()).select_from(m.KnowledgeEntry)
    )
```

`KnowledgeEntry` does not exist. The correct model is `KnowledgeDocument`. Because this is guarded by `hasattr`, it silently returns 0 rather than crashing. Fix: replace `m.KnowledgeEntry` with `m.KnowledgeDocument`.

---

### M-3 — `deploy_to_siem` Pipeline Block Hardcodes `siem_platform: 'splunk'`
**Severity:** MEDIUM — Incorrect for non-Splunk deployments  
**Files:** `backend/agent/pipeline/blocks.py` — `_blk_deploy_to_siem`

When `siem_connection_id` is not provided, the block falls back to a hardcoded `siem_platform: 'splunk'`. Multi-SIEM deployments using Sentinel or Elastic will silently get a Splunk deployment attempt.

---

## Remediation Priority & Effort

| # | Issue | Severity | Est. Effort | Owner |
|---|-------|----------|-------------|-------|
| C-1 | Environment model missing attrs | CRITICAL | 2h | Backend |
| C-2 | API key encryption | CRITICAL | 3h | Backend/Security |
| C-3 | Hardcoded localhost URLs | CRITICAL | 2h | Backend |
| H-1 | Scoring reads demo data | HIGH | 1 day | Backend |
| H-2 | SIEM tools NotImplementedError | HIGH | 3 days | Backend |
| H-3 | TIP search stub | HIGH | 2 days | Backend/Integration |
| H-4 | Silent exception handlers | HIGH | 2h | Backend |
| H-5 | 90% zero test coverage | HIGH | ongoing | All |
| M-1 | Blocks use HTTP not services | MEDIUM | 2 days | Backend |
| M-2 | KnowledgeEntry wrong model | MEDIUM | 30 min | Backend |
| M-3 | deploy_to_siem hardcoded siem | MEDIUM | 1h | Backend |

**Total estimate to reach production-safe state:** ~2 weeks focused effort.  
**Pre-release minimum:** C-1, C-2, C-3, H-4 (one day of work).

---

## Test Coverage Expansion Plan

Target coverage progression:

| Phase | Target | What to cover |
|-------|--------|---------------|
| Phase 1 (week 1) | 30% | All scoring endpoints, environment CRUD, use case CRUD |
| Phase 2 (week 2) | 50% | Threat profiles, pipeline validate/run, SIEM connection management |
| Phase 3 (week 3) | 70% | Agent tools (with mocked HTTP), dashboard, admin |
| Phase 4 (week 4) | 80% | HITL, knowledge, notifications, full E2E pipeline flow |

The new pipeline tests (`backend/tests/test_pipeline_*.py`, 327 tests) serve as the template pattern for all new test files.
