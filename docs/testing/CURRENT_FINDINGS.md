# Joti Sim — Current Findings Report

**Date**: 2026-03-28
**Reviewer**: Testing Agent
**Codebase version**: `b0957ab` (main branch)

---

## Bugs Found

### BUG-001: Event log buffer trimming only happens inside `_send_event`
**Severity**: Low
**Location**: `backend/engine.py`, lines 221-222

The event log buffer cap (500 entries) is only enforced inside `_send_event`. If events are appended to `event_log` from any other code path, the buffer can grow unbounded. The trimming logic should be extracted to a dedicated method called after every append.

### BUG-002: `update_session` calls `stop_session`/`start_session` synchronously but `start_session` creates async scheduler
**Severity**: Medium
**Location**: `backend/engine.py`, lines 106-116

`update_session` calls `self.stop_session()` and `self.start_session()` within a synchronous method. While `start_session` is also synchronous, it creates an `AsyncIOScheduler` and schedules async jobs (`_send_event`). If `update_session` is called while events are being sent, there is a potential race condition where the old scheduler's jobs may still be executing when the new scheduler starts.

### BUG-003: `_send_event` can fail with KeyError if session is deleted mid-flight
**Severity**: Low
**Location**: `backend/engine.py`, lines 204-206

If a session is deleted while `_send_event` is executing, `self.stats[session_id]` will raise `KeyError` because `delete_session` pops the session from `self.stats`. The code does use `.get()` in some places but directly indexes `self.stats[session_id]` on lines 204 and 206.

### BUG-004: Sentinel severity mapping collapses "critical" and "high" to the same value
**Severity**: Low (design choice, but worth noting)
**Location**: `backend/generators/sentinel.py`, line 33

Both "critical" and "high" map to "High" in the `SEVERITY_MAP`. This means downstream consumers cannot distinguish between critical and high-severity Sentinel alerts. This matches Sentinel's real 3-tier severity model (High/Medium/Low), but it means the simulator's "critical" config has reduced fidelity for Sentinel.

### BUG-005: Defender severity mapping also collapses "critical" and "high"
**Severity**: Low (same pattern as BUG-004)
**Location**: `backend/generators/defender_endpoint.py`, line 33

Same issue as Sentinel — Defender for Endpoint uses High/Medium/Low (no "Critical" tier), so both internal "critical" and "high" map to "High".

---

## Security Vulnerabilities

### SEC-001: CORS configured with wildcard allow_origins=["*"]
**Severity**: Medium
**Location**: `backend/main.py`, lines 19-24

The CORS middleware allows all origins, all methods, and all headers. This is acceptable for local development but must be restricted before any production or shared deployment. Any website can make API calls to the Joti Sim backend.

**Recommendation**: Use explicit origin allowlist in production:
```python
allow_origins=["http://localhost:3000", "https://joti-sim.internal.company.com"]
```

### SEC-002: No authentication on any API endpoint
**Severity**: High (for any non-local deployment)
**Location**: `backend/main.py` (all routes)

All API endpoints are completely open. Anyone with network access can:
- Create/start/stop/delete simulation sessions
- Generate unlimited webhook traffic to any target URL
- Use the platform as an amplification vector (send webhook POST requests to arbitrary URLs)

**Recommendation**: Implement at minimum API key authentication before any shared deployment.

### SEC-003: Target URL is not validated — open SSRF vector
**Severity**: High
**Location**: `backend/engine.py`, line 199

The `_send_event` method POSTs event payloads to `target_url` without any validation. A user could set `target_url` to an internal service (e.g., `http://169.254.169.254/latest/meta-data/` on AWS) to perform Server-Side Request Forgery.

**Recommendation**: Validate target URLs against an allowlist or block private/internal IP ranges.

### SEC-004: Frontend renders user-supplied data without escaping
**Severity**: Medium
**Location**: `frontend/index.html`, line 345

The `renderEventLog` function uses template literals to inject `e.title`, `e.product_label`, and other event data directly into `innerHTML`. If a generator produces a title containing HTML (e.g., from a manipulated session name), it could execute in the browser context.

**Current risk**: Low, because titles come from server-controlled data pools, not user input. But if custom generators or user-supplied alert titles are added, this becomes exploitable.

**Recommendation**: Use `textContent` instead of `innerHTML` for user-derived fields, or sanitize with a library.

### SEC-005: No rate limiting on session creation or event generation
**Severity**: Low (for local use), Medium (for shared deployment)
**Location**: `backend/main.py`

There is no limit on:
- Number of sessions that can be created
- Events per minute (capped at 120 per product, but unlimited products per session)
- API request rate

**Recommendation**: Add rate limiting middleware (e.g., `slowapi`) and cap total products per session.

---

## Code Quality Issues

### CQ-001: Global singleton `engine` makes testing harder
**Location**: `backend/engine.py`, line 248

The module-level `engine = SimulationEngine()` singleton means the API routes share state across tests. The test suite creates fresh `SimulationEngine()` instances via fixtures for unit tests, but integration tests using the FastAPI `TestClient` share the singleton.

**Recommendation**: Use dependency injection (FastAPI's `Depends`) to provide the engine instance, making it swappable in tests.

### CQ-002: No input validation on `product_type` in session creation
**Location**: `backend/main.py`, line 77 and `backend/engine.py`, line 139

When creating a session, there is no validation that `product_type` refers to a registered generator. An invalid `product_type` silently results in no generator being created (the `if gen_cls:` check on line 139 skips it), which means the product appears in the session but never generates events.

**Recommendation**: Validate `product_type` against `GENERATOR_REGISTRY` at session creation time and return 422 if invalid.

### CQ-003: HTTP client in engine is never closed
**Location**: `backend/engine.py`, line 80

`self._http = httpx.AsyncClient(timeout=10.0)` is created but never explicitly closed. The `httpx.AsyncClient` should be closed when the engine shuts down to release connections.

**Recommendation**: Add a `shutdown()` method that calls `await self._http.aclose()` and register it with FastAPI's `on_event("shutdown")`.

### CQ-004: Event severity extraction in `_send_event` is fragile
**Location**: `backend/engine.py`, lines 183-186

The severity extraction chain uses `or` with multiple fallback paths:
```python
severity = event.get("urgency") or event.get("result", {}).get("severity") or \
           event.get("event", {}).get("SeverityName", "").lower() or "medium"
```
This works for the current generators but is brittle. If a generator returns `{"urgency": ""}` (empty string), the fallback chain breaks because empty string is falsy.

**Recommendation**: Have each generator return a standardized `_sim_severity` field alongside the vendor payload, or use a severity extraction method per generator class.

---

## Performance Concerns

### PERF-001: Event log is a plain list with linear scan for session filtering
**Location**: `backend/engine.py`, line 231

`get_event_log` filters by session_id using a list comprehension over the entire log. With 500 entries max, this is fine, but if the buffer is increased or multiple consumers poll frequently, this becomes expensive.

### PERF-002: `renderCanvas()` in frontend re-renders all nodes on every mouse move
**Location**: `frontend/index.html`, lines 246-252

During node dragging, every `mousemove` event triggers a full `renderCanvas()` which rebuilds all DOM nodes. For a handful of nodes this is fine, but with many products it would cause jank.

---

## Recommendations for Development Agent

1. **Highest priority**: Fix SEC-003 (SSRF via target_url) before any shared deployment
2. **High priority**: Add API key authentication (SEC-002) for non-localhost deployments
3. **Medium priority**: Fix BUG-003 (KeyError on session deletion during event send)
4. **Medium priority**: Validate product_type at session creation (CQ-002)
5. **Low priority**: Extract event log trimming to a method (BUG-001)
6. **Low priority**: Close httpx.AsyncClient on shutdown (CQ-003)
7. **Future**: Add rate limiting, restrict CORS for production, sanitize frontend innerHTML
