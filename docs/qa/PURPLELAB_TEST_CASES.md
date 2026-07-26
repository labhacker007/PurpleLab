# PurpleLab Test Cases

**Version:** 1.0 | **Date:** 2026-07-25 | **Platform:** PurpleLab Cybersecurity Simulation Platform
**Stack:** FastAPI + SQLAlchemy async + PostgreSQL 5434 + Python 3.11

This document contains 100+ test cases covering functional, security, integration, performance, and regression testing for the PurpleLab simulation platform.

---

## Table of Contents

1. [Functional Tests (TC-F-001 to TC-F-040)](#functional-tests)
2. [Security Tests (TC-S-001 to TC-S-025)](#security-tests)
3. [Integration Tests (TC-I-001 to TC-I-020)](#integration-tests)
4. [Performance Tests (TC-P-001 to TC-P-010)](#performance-tests)
5. [Regression Tests (TC-R-001 to TC-R-010)](#regression-tests)

---

## Functional Tests

### TC-F-001: Create Session with attack_chain Simulation Mode
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** PurpleLab API running on port 8002. No active sessions.
**Steps:**
1. POST `/api/v2/sessions` with body:
   ```json
   {
     "name": "Test Attack Chain Session",
     "simulation_mode": "attack_chain",
     "attack_chains": ["lateral_movement", "initial_access"],
     "event_count": 50
   }
   ```
2. Capture the returned session `id`.
3. GET `/api/v2/sessions/{id}` to verify the stored record.
**Expected Result:** Response is 201 or 200. Returned object contains `id` (UUID), `name`, `status` = `stopped`, `config.simulation_mode` = `attack_chain`, `config.attack_chains` = `["lateral_movement", "initial_access"]`, `config.event_count` = 50, `events_sent` = 0, `errors` = 0.
**Notes:** `event_count` is clamped to range 10–2000. Requests below 10 or above 2000 should be rejected or coerced.

---

### TC-F-002: Create Session with threat_actor Simulation Mode
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/sessions` with body:
   ```json
   {
     "name": "APT29 Simulation",
     "simulation_mode": "threat_actor",
     "threat_actor_name": "APT29",
     "threat_actor_ttps": ["T1566.001", "T1078", "T1021.001"],
     "event_count": 100,
     "auto_start": false
   }
   ```
2. GET `/api/v2/sessions/{id}` to verify.
**Expected Result:** Session created with `status` = `stopped`. `config.threat_actor_name` = `APT29`, `config.threat_actor_ttps` contains the three technique IDs. Session is not started automatically because `auto_start` = false.
**Notes:** `threat_actor_id` and `threat_actor_name` are both accepted. The config JSONB column stores all these fields.

---

### TC-F-003: Create Session with ttps Simulation Mode
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/sessions` with body:
   ```json
   {
     "name": "TTP Simulation",
     "simulation_mode": "ttps",
     "technique_ids": ["T1059.001", "T1003.001", "T1486"],
     "event_count": 75
   }
   ```
2. GET `/api/v2/sessions/{id}` to verify.
**Expected Result:** Session created with `config.simulation_mode` = `ttps`, `config.technique_ids` containing the three techniques, `status` = `stopped`.
**Notes:** technique_ids maps directly to the `config` JSONB. technique_ids are used by the generator to select event templates.

---

### TC-F-004: Create Session with mcp_ingest Simulation Mode
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** PurpleLab API running. An MCP server accessible at a test URL.
**Steps:**
1. POST `/api/v2/sessions` with body:
   ```json
   {
     "name": "MCP Ingest Session",
     "simulation_mode": "mcp_ingest",
     "mcp_server_url": "http://test-mcp-server:8080",
     "mcp_api_key": "test-key-abc",
     "mcp_tool": "siem_search_events",
     "event_count": 20
   }
   ```
2. GET `/api/v2/sessions/{id}` to confirm stored config.
**Expected Result:** Session created. `config.mcp_server_url`, `config.mcp_api_key`, and `config.mcp_tool` are stored in the JSONB config. `status` = `stopped`.
**Notes:** The `api_key` may be stored as `mcp_api_key` or `api_key` depending on the schema. Verify exact field name in response.

---

### TC-F-005: Create Session with auto_start=true
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/sessions` with body:
   ```json
   {
     "name": "Auto Start Session",
     "simulation_mode": "ttps",
     "technique_ids": ["T1059.001"],
     "event_count": 10,
     "auto_start": true
   }
   ```
2. Immediately GET `/api/v2/sessions/{id}`.
**Expected Result:** Session is created and immediately transitions to `running` status. `events_sent` begins incrementing without requiring a separate start call.
**Notes:** The session start is triggered inline during creation when `auto_start` = true. There is no separate start endpoint in v2 — start is controlled via `auto_start` or a dedicated start action.

---

### TC-F-006: List Sessions with Status Filter
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** At least one `running` session and one `stopped` session exist.
**Steps:**
1. GET `/api/v2/sessions?status=running`
2. GET `/api/v2/sessions?status=stopped`
3. GET `/api/v2/sessions` (no filter)
**Expected Result:** First call returns only sessions with `status=running`. Second call returns only `stopped` sessions. Third call returns all sessions. Each response includes pagination metadata.
**Notes:** Accepted status values: `stopped`, `running`, `paused`.

---

### TC-F-007: List Sessions with Pagination
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** At least 10 sessions exist in the database.
**Steps:**
1. GET `/api/v2/sessions?skip=0&limit=5`
2. GET `/api/v2/sessions?skip=5&limit=5`
3. Compare the `id` values across both pages.
**Expected Result:** First page returns 5 sessions. Second page returns the next 5. No `id` value appears on both pages. Total count in response is consistent across pages.
**Notes:** `skip` and `limit` are the pagination parameters per the API spec.

---

### TC-F-008: Get Session with recent_events
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session exists with at least 5 generated events.
**Steps:**
1. GET `/api/v2/sessions/{id}` and inspect the response for `recent_events` field.
**Expected Result:** The session detail response includes a `recent_events` array containing the most recent events. Each event object has `id`, `product_type`, `severity`, `title`, `payload`, `target_url`, `status_code`, `success`.
**Notes:** The number of events returned in `recent_events` is implementation-defined. Typically the last 5 or 10 events.

---

### TC-F-009: Update (Rename) a Session
**Priority:** Low
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `stopped` session exists with a known `id`.
**Steps:**
1. PATCH or PUT `/api/v2/sessions/{id}` with body `{"name": "Renamed Session"}`.
2. GET `/api/v2/sessions/{id}` to verify the new name.
**Expected Result:** Session name is updated to `"Renamed Session"`. All other fields (status, config, events_sent) remain unchanged.
**Notes:** Only `name` updates are expected here. Updating config fields on a running session is not expected to be allowed.

---

### TC-F-010: Delete a Session
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `stopped` session exists with a known `id`.
**Steps:**
1. DELETE `/api/v2/sessions/{id}`.
2. GET `/api/v2/sessions/{id}`.
**Expected Result:** DELETE returns `{"status": "deleted", "id": "<session_id>"}`. Subsequent GET returns 404.
**Notes:** If the session is `running`, it should be stopped before deletion. See TC-S-014 for that case.

---

### TC-F-011: Start a Session
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `stopped` session exists.
**Steps:**
1. POST `/api/v2/sessions/{id}/start` (or equivalent start endpoint).
2. GET `/api/v2/sessions/{id}` within 2 seconds.
**Expected Result:** Session `status` transitions from `stopped` to `running`. `events_sent` begins to increment on subsequent GETs. `last_event_at` is populated.
**Notes:** If the platform uses `auto_start` only and has no separate start endpoint, document accordingly. Confirm by checking the routes file.

---

### TC-F-012: Stop a Session and Verify Joti Push
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `running` session exists. Joti integration is configured (JOTI_BASE_URL + JOTI_API_KEY set). Mock or log the outbound Joti call.
**Steps:**
1. POST `/api/v2/sessions/{id}/stop`.
2. Observe backend logs for the Joti push attempt.
3. GET `/api/v2/sessions/{id}`.
**Expected Result:** Session `status` transitions to `stopped`. Backend logs show `POST {JOTI_BASE_URL}/api/v2/simulations` was called with payload containing `session_id`, `session_name`, `technique_ids`, `severity`, `events_generated`, `hit`, `summary`. Session status is `stopped` regardless of Joti push success.
**Notes:** Joti push is called non-fatally — failure is logged at debug level and does not affect session stop.

---

### TC-F-013: Stop a Session When Joti Push Fails (Non-Fatal)
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `running` session exists. JOTI_BASE_URL points to an unreachable endpoint.
**Steps:**
1. POST `/api/v2/sessions/{id}/stop`.
2. Check backend logs.
3. GET `/api/v2/sessions/{id}`.
**Expected Result:** Session `status` is `stopped`. Backend logs show a debug-level log entry about the Joti push failure (e.g., connection error). No 500 error is returned from the stop endpoint. The stop operation completes successfully.
**Notes:** `push_simulation_result` is called non-fatally. The session transitions to `stopped` whether or not Joti is reachable.

---

### TC-F-014: Reject Start on Already-Running Session
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A `running` session exists.
**Steps:**
1. POST `/api/v2/sessions/{id}/start` (or equivalent) on the already-running session.
**Expected Result:** API returns 409 Conflict or 400 Bad Request with a message indicating the session is already running. Session status remains `running` and events continue.
**Notes:** The `already_running` check prevents duplicate generator tasks from spawning.

---

### TC-F-015: Get Session Stats — events_per_minute
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session that has been running for at least 60 seconds with events generated.
**Steps:**
1. GET `/api/v2/sessions/{id}/stats`.
2. Inspect the `events_per_minute` field.
**Expected Result:** `events_per_minute` is a numeric value calculated from the `created_at` timestamp range of events (not a fixed rate). The value is reasonable given the session's event count and duration.
**Notes:** EPM is calculated from actual event timestamps (`created_at` range) — not from `events_sent` / elapsed_time. If only one event exists, EPM = 0 or null is acceptable.

---

### TC-F-016: Get Session Stats — by_severity Breakdown
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with events of mixed severities (critical, high, medium, low, info).
**Steps:**
1. GET `/api/v2/sessions/{id}/stats`.
2. Inspect `by_severity` in the response.
**Expected Result:** `by_severity` is a dict (or list) with counts for each severity level. Valid severity values: `critical`, `high`, `medium`, `low`, `info`. Counts sum to total events in the session.
**Notes:** Severity is a field on `GeneratedEvent`. All five severity levels may be present.

---

### TC-F-017: Get Session Stats — top_techniques
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with events whose titles contain technique references.
**Steps:**
1. GET `/api/v2/sessions/{id}/stats`.
2. Inspect `top_techniques` in the response.
**Expected Result:** `top_techniques` is a list of `{technique_id, count}` objects ranked by frequency. Technique IDs are extracted from the event `title` field, not from the `payload` JSONB.
**Notes:** The implementation extracts technique IDs from the `title` field specifically. This is an important implementation detail — do not assume payload-based extraction.

---

### TC-F-018: Get Session Stats — by_source
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with events from multiple product types.
**Steps:**
1. GET `/api/v2/sessions/{id}/stats`.
2. Inspect `by_source` in the response.
**Expected Result:** `by_source` maps `product_type` values (e.g., `crowdstrike`, `splunk`, `okta`, `windows_event_log`) to their event counts. All unique `product_type` values from session events appear as keys.
**Notes:** `product_type` is the `GeneratedEvent.product_type` field, which maps to the log source/vendor.

---

### TC-F-019: Get Session Events with Pagination
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with at least 10 events.
**Steps:**
1. GET `/api/v2/sessions/{id}/events?skip=0&limit=5`.
2. GET `/api/v2/sessions/{id}/events?skip=5&limit=5`.
3. Verify no overlap in returned event `id` values.
**Expected Result:** Each page returns up to 5 events. Combined results cover 10 unique events. `limit` param maximum is 500.
**Notes:** The `limit` parameter is enforced between 1 and 500 by the API.

---

### TC-F-020: Get Session Events with Severity Filter
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with events of mixed severities.
**Steps:**
1. GET `/api/v2/sessions/{id}/events?severity=critical`.
2. Verify all returned events have `severity` = `critical`.
3. Repeat with `severity=high`, `severity=low`.
**Expected Result:** Only events matching the requested severity are returned. Other severity events are excluded.
**Notes:** Valid severity filter values: `critical`, `high`, `medium`, `low`, `info`.

---

### TC-F-021: Session Events SSE Stream — Done Signal
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session that will stop while an SSE client is connected.
**Steps:**
1. Connect to GET `/api/v2/sessions/{id}/events/stream` with `Accept: text/event-stream`.
2. Wait for the session to stop (or manually stop it).
3. Observe the SSE stream after the session stops.
**Expected Result:** After the session stops, the stream emits `data: {"type": "done"}` and then closes.
**Notes:** The done signal is `'{"type": "done"}'` — a JSON object with a `type` field equal to the string `"done"`.

---

### TC-F-022: Session Events SSE Stream — Heartbeat
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session that is running but not generating events rapidly.
**Steps:**
1. Connect to GET `/api/v2/sessions/{id}/events/stream`.
2. Wait for 5 idle polling intervals (5 × 1.5s = 7.5s without new events).
3. Observe the stream output.
**Expected Result:** After 5 consecutive idle polls (no new events), the SSE stream emits a heartbeat comment: `: heartbeat`. This is an SSE comment, not a `data:` event. The stream does not close during idle periods.
**Notes:** The heartbeat format is `: heartbeat\n\n` — SSE comment syntax. The poll interval is 1.5 seconds. Heartbeat fires after every 5th consecutive idle poll.

---

### TC-F-023: MCP Resolve — Extract Technique IDs
**Priority:** High
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with `simulation_mode` = `mcp_ingest` and `mcp_server_url` configured. MCP server returns events with technique ID fields.
**Steps:**
1. Start the session.
2. POST `/api/v2/sessions/{id}/resolve-mcp`.
3. Check the response.
**Expected Result:** PurpleLab sends a JSON-RPC call to `mcp_server_url`. Response includes extracted technique IDs. The endpoint checks `technique_id`, `mitre_technique`, and `tags` fields in the returned MCP events to extract ATT&CK technique IDs.
**Notes:** Three MCP tools are supported: `siem_search_events`, `siem_get_alerts`, `edr_get_detections`. The tool used is whatever is stored in `config.mcp_tool`.

---

### TC-F-024: MCP Resolve — HTTP Error Returns 502
**Priority:** Medium
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with `mcp_server_url` pointing to an unreachable server.
**Steps:**
1. POST `/api/v2/sessions/{id}/resolve-mcp` with a session whose `mcp_server_url` is unreachable.
**Expected Result:** API returns 502 Bad Gateway with a descriptive error message indicating the MCP server could not be reached.
**Notes:** `httpx` errors (connection error, timeout) are caught and surfaced as 502, not 500.

---

### TC-F-025: MCP Resolve — Unknown mcp_tool
**Priority:** Low
**Category:** Functional
**Component:** Sessions
**Preconditions:** A session with `mcp_tool` set to an unsupported value (e.g., `"unknown_tool"`).
**Steps:**
1. POST `/api/v2/sessions/{id}/resolve-mcp`.
**Expected Result:** API returns 400 Bad Request indicating the specified tool is not supported. Valid tools listed: `siem_search_events`, `siem_get_alerts`, `edr_get_detections`.
**Notes:** The three valid tools are hardcoded in the resolve-mcp handler.

---

### TC-F-026: Create a Use Case
**Priority:** High
**Category:** Functional
**Component:** UseCases
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/use-cases` (or `/use-cases`) with body:
   ```json
   {
     "name": "Credential Dumping Detection",
     "description": "Detects LSASS memory access via T1003.001",
     "technique_ids": ["T1003.001"],
     "tactic": "credential_access",
     "severity": "high",
     "tags": ["windows", "lsass"]
   }
   ```
2. GET the use case by the returned `id`.
**Expected Result:** Use case created with all provided fields. `is_active` = true (default), `is_builtin` = false (user-created), `last_validated_at` = null (not yet validated), `sim_metadata` = null.
**Notes:** `tags` is stored as JSONB. `technique_ids` is JSONB.

---

### TC-F-027: List Use Cases with Filters
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** Multiple use cases exist with varying `tactic`, `severity`, `is_active`, and `is_builtin` values.
**Steps:**
1. GET `/use-cases?tactic=credential_access`.
2. GET `/use-cases?severity=high`.
3. GET `/use-cases?is_active=true`.
4. GET `/use-cases?is_builtin=true`.
**Expected Result:** Each filter returns only matching use cases. Filters can be combined. `is_active=false` returns deactivated use cases only.
**Notes:** Filter parameter names and exact accepted values should match what the API accepts.

---

### TC-F-028: Update a Use Case
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists with a known `id`.
**Steps:**
1. PATCH `/use-cases/{id}` with body `{"description": "Updated description", "severity": "critical"}`.
2. GET `/use-cases/{id}` to verify.
**Expected Result:** `description` and `severity` are updated. `technique_ids`, `tactic`, `tags`, and `is_builtin` remain unchanged.
**Notes:** Partial updates (PATCH) should only modify provided fields.

---

### TC-F-029: Delete a Use Case
**Priority:** Low
**Category:** Functional
**Component:** UseCases
**Preconditions:** A non-builtin use case exists.
**Steps:**
1. DELETE `/use-cases/{id}`.
2. GET `/use-cases/{id}`.
**Expected Result:** Delete returns 200 or 204. Subsequent GET returns 404.
**Notes:** Built-in use cases (`is_builtin=true`) may be protected from deletion. Verify expected behavior.

---

### TC-F-030: Get Use Case Coverage Summary
**Priority:** High
**Category:** Functional
**Component:** UseCases
**Preconditions:** Multiple use cases exist, some with passing runs, some with no runs.
**Steps:**
1. GET `/use-cases/coverage`.
**Expected Result:** Returns a coverage summary including total use cases, covered technique IDs, uncovered technique IDs, pass rate, and breakdown by tactic. The `UseCaseService.get_coverage_summary()` logic is applied.
**Notes:** Coverage is computed from `UseCaseRun` history. Use cases with no runs count as uncovered.

---

### TC-F-031: Get Failing Use Cases
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** At least one use case with a `failed` run and one with no runs. At least one use case with a `passed` run.
**Steps:**
1. GET `/use-cases/failing`.
**Expected Result:** Returns use cases that either have no passing run in history or have never been run. Use cases with at least one `passed` `UseCaseRun` are excluded.
**Notes:** A use case counts as "failing" if it has never been run OR has runs but none with `status=passed`.

---

### TC-F-032: Run a Use Case — Pending Run Created First
**Priority:** High
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists. Celery worker is running.
**Steps:**
1. POST `/use-cases/{id}/run`.
2. Immediately query the `UseCaseRun` records for this use case.
**Expected Result:** A `UseCaseRun` record is created with `status=pending` and `triggered_by=manual` before the Celery task executes. The Celery task `run_use_case_task` is dispatched asynchronously. The API response returns immediately (non-blocking) with the pending run ID.
**Notes:** The pending run is created synchronously in the route handler before `Celery.delay()` is called. This ensures the run is visible immediately even if Celery is slow.

---

### TC-F-033: Run All Use Cases via Celery
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** Multiple use cases exist. Celery worker is running.
**Steps:**
1. POST `/use-cases/run-all`.
**Expected Result:** `run_all_use_cases_task.delay()` is dispatched to Celery. Response returns immediately. Each active use case eventually gets a `UseCaseRun` record created.
**Notes:** This dispatches a single Celery task that internally iterates all active use cases.

---

### TC-F-034: Get Use Case Run History
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case has at least 3 completed runs.
**Steps:**
1. GET `/use-cases/{id}/runs` or equivalent run history endpoint.
**Expected Result:** Returns all `UseCaseRun` records for this use case, sorted by most recent first. Each run includes `id`, `status`, `triggered_by`, `events_generated`, `rules_tested`, `rules_fired`, `pass_rate`, `run_details`.
**Notes:** Valid `triggered_by` values: `manual`, `pipeline`, `scheduled`, `agent`.

---

### TC-F-035: Simulate Identity Action on Use Case — Valid Action
**Priority:** High
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists with `"identity"` in `tags`. At least one `SimulatedUser` exists (or will be auto-seeded).
**Steps:**
1. POST `/use-cases/{id}/simulate-identity` with body:
   ```json
   {
     "action": "disable_user",
     "dry_run": false
   }
   ```
**Expected Result:** An Okta event is generated (`user.lifecycle.deactivate`). The simulated user's identity state is set to `DISABLED`. Response indicates success with the action taken and event generated.
**Notes:** If no `SimulatedUser` records exist, the endpoint auto-seeds one before running the action. Valid actions: `lock_user`, `unlock_user`, `disable_user`, `enable_user`, `revoke_sessions`, `force_mfa`, `force_pw_reset`.

---

### TC-F-036: Simulate Identity Action — Invalid Action Returns 400
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists with `"identity"` in `tags`.
**Steps:**
1. POST `/use-cases/{id}/simulate-identity` with body:
   ```json
   {
     "action": "nuke_account",
     "dry_run": false
   }
   ```
**Expected Result:** 400 Bad Request. Response body includes a `valid_actions` list showing the 7 accepted actions: `lock_user`, `unlock_user`, `disable_user`, `enable_user`, `revoke_sessions`, `force_mfa`, `force_pw_reset`.
**Notes:** The `valid_actions` list is explicitly returned in the error response per the implementation.

---

### TC-F-037: Simulate Identity Action — Missing Identity Tag Returns 400
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists WITHOUT `"identity"` in its `tags`.
**Steps:**
1. POST `/use-cases/{id}/simulate-identity` with any valid body.
**Expected Result:** 400 Bad Request with a message indicating this use case does not have the `"identity"` tag required for identity simulation.
**Notes:** The `"identity"` tag check is the gate for this endpoint.

---

### TC-F-038: Simulate Identity Action with dry_run=true
**Priority:** Medium
**Category:** Functional
**Component:** UseCases
**Preconditions:** A use case exists with `"identity"` in `tags`.
**Steps:**
1. POST `/use-cases/{id}/simulate-identity` with body:
   ```json
   {
     "action": "disable_user",
     "dry_run": true
   }
   ```
2. Check that no Okta event is generated and no identity state change occurs in the DB.
**Expected Result:** Response indicates the action would be taken, including what the effect would be, but no state changes occur. No `GeneratedEvent` is created. No identity state is modified.
**Notes:** `dry_run=true` is a preview mode — no side effects.

---

### TC-F-039: List All 10 ITDR Scenarios
**Priority:** High
**Category:** Functional
**Component:** ITDR
**Preconditions:** PurpleLab API running.
**Steps:**
1. GET `/api/v2/itdr/scenarios` or equivalent ITDR list endpoint.
**Expected Result:** Returns exactly 10 scenarios. Each scenario includes `id` (scenario key), `name`, `description`, `technique_id`, and available simulation metadata. Scenarios: `kerberoasting`, `pass_the_hash`, `golden_ticket`, `dcsync`, `mfa_fatigue`, `impossible_travel`, `password_spray`, `credential_stuffing`, `token_theft`, `privileged_account_creation`.
**Notes:** ITDR scenarios are a static in-memory dict — they cannot be created, updated, or deleted via API.

---

### TC-F-040: Get ITDR Scenario Detail — Kerberoasting
**Priority:** High
**Category:** Functional
**Component:** ITDR
**Preconditions:** PurpleLab API running.
**Steps:**
1. GET `/api/v2/itdr/scenarios/kerberoasting` or equivalent.
2. Verify the returned `technique_id`.
3. Request the Sigma YAML for this scenario.
4. Request the SPL hunt query.
5. Request the KQL hunt query.
**Expected Result:** Scenario detail contains `technique_id` = `T1558.003`. Sigma YAML endpoint returns a valid YAML string for Kerberoasting detection. SPL query is returned as a string. KQL query is returned as a string.
**Notes:** All 10 ITDR technique IDs are hardcoded: kerberoasting=T1558.003, pass_the_hash=T1550.002, golden_ticket=T1558.001, dcsync=T1003.006, mfa_fatigue=T1621, impossible_travel=T1550.004, password_spray=T1110.003, credential_stuffing=T1110.004, token_theft=T1528, privileged_account_creation=T1136.001.

---

## Security Tests

### TC-S-001: Session Event Isolation — Cross-Session Access
**Priority:** High
**Category:** Security
**Component:** Sessions
**Preconditions:** Two sessions (A and B) exist, each with events.
**Steps:**
1. Record the event `id` values from session A via `GET /api/v2/sessions/{session_A_id}/events`.
2. Attempt to access session A's events via session B's endpoint: `GET /api/v2/sessions/{session_B_id}/events`.
3. Attempt direct event lookup if a per-event endpoint exists.
**Expected Result:** Session B's events endpoint returns only session B's events. Session A's event IDs do not appear. There is no endpoint that returns events across all sessions without a session_id scoping parameter.
**Notes:** This is the core isolation guarantee — each session is a separate simulation context.

---

### TC-S-002: Vendor API Without session_id Returns Empty Results
**Priority:** High
**Category:** Security
**Component:** Vendor
**Preconditions:** At least one session with events exists.
**Steps:**
1. Call the Splunk search endpoint without a `session_id` query parameter.
2. Call the CrowdStrike devices list endpoint without `session_id`.
3. Call the XSIAM incidents endpoint without `session_id`.
**Expected Result:** All three calls return empty result sets (no events, no devices, no incidents) rather than cross-session data or 500 errors. The vendor APIs treat missing `session_id` as a request for an empty context.
**Notes:** This prevents data leakage across simulations. An empty session_id or absent session_id should not cause a server error.

---

### TC-S-003: CrowdStrike OAuth2 — Missing Authorization Header Returns 401
**Priority:** High
**Category:** Security
**Component:** Vendor
**Preconditions:** PurpleLab's CrowdStrike emulation endpoint is accessible.
**Steps:**
1. POST the CrowdStrike OAuth2 token endpoint without an `Authorization` header.
2. POST the endpoint with an `Authorization` header containing invalid credentials.
**Expected Result:** Both requests return HTTP 401 Unauthorized. No token is issued. The `_FAKE_TOKEN` value is not exposed in the error response.
**Notes:** The fake token is `"cs-sim-token-" + uuid`. It should only be returned upon successful fake auth, not in error responses.

---

### TC-S-004: SPL Injection — Special Characters in Search Query
**Priority:** High
**Category:** Security
**Component:** Vendor
**Preconditions:** Splunk emulation endpoint is accessible.
**Steps:**
1. POST a Splunk search with an SPL query containing injection characters:
   ```
   index=main | eval x="'; DROP TABLE events;--"
   ```
2. POST a search with a query containing nested quotes and backslashes.
**Expected Result:** Both requests return a valid JSON response (empty results or an error about the query). No server error (500). No SQL injection occurs (the backend uses parameterized queries for DB access). JSON structure in the response is valid.
**Notes:** Splunk search uses in-memory `_jobs` dict. The query string is stored as-is for the job but not executed as SQL.

---

### TC-S-005: Session ID Validation — Invalid UUID Returns 400
**Priority:** Medium
**Category:** Security
**Component:** Sessions
**Preconditions:** None.
**Steps:**
1. GET `/api/v2/sessions/not-a-uuid`.
2. GET `/api/v2/sessions/123`.
3. GET `/api/v2/sessions/../../etc/passwd`.
**Expected Result:** All requests return 400 Bad Request or 422 Unprocessable Entity indicating the session ID is not a valid UUID. No 500 errors. No path traversal succeeds.
**Notes:** Session IDs are UUIDs. Invalid UUID formats should be caught by FastAPI's path parameter validation.

---

### TC-S-006: Joti Audit Event Endpoint — Accept Batch
**Priority:** High
**Category:** Security
**Component:** Joti
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/joti/audit-events` with body:
   ```json
   {
     "events": [
       {"joti_event_id": "evt-001", "event_type": "auth", "action": "login", "user_email": "user@test.com", "ip_address": "1.2.3.4", "resource_type": "session", "resource_id": "123"},
       {"joti_event_id": "evt-002", "event_type": "auth", "action": "logout", "user_email": "user@test.com", "ip_address": "1.2.3.4", "resource_type": "session", "resource_id": "123"}
     ]
   }
   ```
2. Query the database to confirm both events are stored as `JotiAuditEvent` records.
**Expected Result:** 200 response. Both events are stored in the database with correct field mapping. `received_at` is set to the current timestamp.
**Notes:** The `X-Joti-Token` header may be required for auth. Verify the auth mechanism on this endpoint.

---

### TC-S-007: Joti Audit Event Endpoint — Empty Events Array
**Priority:** Low
**Category:** Security
**Component:** Joti
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST `/api/v2/joti/audit-events` with body `{"events": []}`.
**Expected Result:** 200 response. No database writes. No error.
**Notes:** An empty batch is a valid no-op. It should not cause a 500 or 422 error.

---

### TC-S-008: Block IOC with Empty ioc_value
**Priority:** Medium
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. POST the action executor endpoint with action `block_ioc` and an empty `ioc_value`:
   ```json
   {"action": "block_ioc", "ioc_value": "", "ioc_type": "ip"}
   ```
**Expected Result:** 400 Bad Request or graceful error response. No server error. No state mutation occurs. The firewall state machine is not modified.
**Notes:** An empty IOC value is not a valid target. The validator should reject it before processing.

---

### TC-S-009: XSIAM Query — Missing execution_id Returns Empty Data
**Priority:** Medium
**Category:** Security
**Component:** Vendor
**Preconditions:** XSIAM emulation endpoint accessible.
**Steps:**
1. GET or POST the XSIAM `get_query_results` endpoint with a `query_id` that does not exist in `_xql_jobs`.
2. GET with an `execution_id` that does not exist.
**Expected Result:** Both return an empty result set (empty `data` array) rather than a 500 error or an error that leaks internal state. HTTP status is 200.
**Notes:** XSIAM accepts both `query_id` and `execution_id` as equivalent. Non-existent IDs should return empty, not error.

---

### TC-S-010: Deploy Detection with Empty sigma_yaml
**Priority:** Low
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. Execute a `deploy_detection` action with:
   ```json
   {
     "action": "deploy_detection",
     "name": "Test Detection",
     "sigma_yaml": "",
     "query_spl": "index=main sourcetype=crowdstrike",
     "technique_ids": ["T1059.001"]
   }
   ```
2. Check the `DeployedDetection` record in the database.
**Expected Result:** The `DeployedDetection` is stored successfully. `sigma_yaml` is stored as an empty string (the column is optional/nullable). No validation error for empty `sigma_yaml`.
**Notes:** `sigma_yaml` is an optional column on `DeployedDetection`. A detection can be defined by SPL/KQL queries alone.

---

### TC-S-011: ITDR Simulate — Unknown scenario_id Returns 404
**Priority:** Medium
**Category:** Security
**Component:** ITDR
**Preconditions:** PurpleLab API running.
**Steps:**
1. POST the ITDR simulate endpoint with `scenario_id` = `"nonexistent_scenario"`.
**Expected Result:** 404 Not Found. The response indicates the scenario does not exist. The list of valid scenario IDs may be included in the error.
**Notes:** ITDR scenarios are a static in-memory dict. Unknown keys must return 404, not a KeyError 500.

---

### TC-S-012: Use Case simulate-identity Without identity Tag Returns 400
**Priority:** High
**Category:** Security
**Component:** UseCases
**Preconditions:** A use case exists with `tags = ["windows", "edr"]` (no `"identity"` tag).
**Steps:**
1. POST `/use-cases/{id}/simulate-identity` with a valid action.
**Expected Result:** 400 Bad Request. The error message states that the use case must have the `"identity"` tag to use this endpoint.
**Notes:** This is a repeated check from TC-F-037 with a security framing — ensuring attackers cannot trigger identity simulation on arbitrary use cases.

---

### TC-S-013: MCP Resolve Without mcp_server_url in Config Returns 400
**Priority:** Medium
**Category:** Security
**Component:** Sessions
**Preconditions:** A session exists with `simulation_mode` = `ttps` (no `mcp_server_url` in config).
**Steps:**
1. POST `/api/v2/sessions/{id}/resolve-mcp`.
**Expected Result:** 400 Bad Request. Error indicates `mcp_server_url` is not configured for this session.
**Notes:** The resolve-mcp endpoint should validate that the session has an MCP URL before attempting any outbound connection.

---

### TC-S-014: Delete Running Session — Stops First Then Deletes
**Priority:** High
**Category:** Security
**Component:** Sessions
**Preconditions:** A `running` session exists.
**Steps:**
1. DELETE `/api/v2/sessions/{id}` where the session is `running`.
2. Check backend logs.
3. Verify the session is no longer accessible.
**Expected Result:** The session is stopped first (generator is shut down cleanly), then the session record and associated events are deleted. Backend logs show the stop action before deletion. No orphaned background tasks remain.
**Notes:** Directly deleting a running session without stopping it could leave a generator task running. The stop-then-delete sequence is the correct implementation.

---

### TC-S-015: Defender isolate — Machine ID Not Found Fallback
**Priority:** Medium
**Category:** Security
**Component:** Vendor
**Preconditions:** A session with at least one active `SimulatedEndpoint` exists. Defender state machine has at least one hostname registered.
**Steps:**
1. Call the Defender isolate endpoint with a `machine_id` value that does not correspond to any `uuid.uuid5(NAMESPACE_DNS, f"mde:{session_id}:{hostname}")` in the state machine.
**Expected Result:** The Defender emulation falls back to using the first available host in the current session's machine snapshot rather than returning a 404 or 500. A machine isolation event is still generated.
**Notes:** This fallback behavior ensures the isolation action completes even with an unrecognized machine_id, matching real Defender's eventual-consistency behavior.

---

### TC-S-016: CrowdStrike Token — Fake Token Format Not Leaked
**Priority:** Medium
**Category:** Security
**Component:** Vendor
**Preconditions:** CrowdStrike OAuth2 endpoint accessible.
**Steps:**
1. Authenticate successfully and capture the token.
2. Verify the token format.
3. Attempt to use an expired or incorrect fake token.
**Expected Result:** Successful auth returns `"cs-sim-token-" + uuid4` format. Requests with an incorrect token receive 401. The token format itself does not expose session information.
**Notes:** The token value is `_FAKE_TOKEN = "cs-sim-token-" + uuid`. It is not session-scoped — it is a global fake token for the emulation layer.

---

### TC-S-017: XSIAM Token Format and Auth
**Priority:** Medium
**Category:** Security
**Component:** Vendor
**Preconditions:** XSIAM emulation endpoint accessible.
**Steps:**
1. Authenticate to XSIAM and capture the token.
2. Verify the format of the returned token.
3. Make a subsequent XSIAM API call with the token.
**Expected Result:** Token format is `"xsiam-sim-{uuid.hex[:20]}"`. The token is accepted for subsequent XSIAM API calls in the same session.
**Notes:** XSIAM token is returned as a simulation token, not a real Cortex XSIAM JWT.

---

### TC-S-018: Defender Token Format
**Priority:** Low
**Category:** Security
**Component:** Vendor
**Preconditions:** Defender emulation endpoint accessible.
**Steps:**
1. Authenticate to the Defender emulation and capture the token.
2. Verify the format.
**Expected Result:** Token format is `"mde-sim-token-{uuid.hex[:20]}"`.
**Notes:** MDE = Microsoft Defender for Endpoint. The token is a simulation token, not a real Azure AD JWT.

---

### TC-S-019: Splunk Job ID Entropy
**Priority:** Low
**Category:** Security
**Component:** Vendor
**Preconditions:** Splunk emulation accessible.
**Steps:**
1. Submit two Splunk search jobs with the same SPL query but different session_ids.
2. Capture the job IDs.
3. Verify job ID format.
**Expected Result:** Job ID format is `"sim_" + md5(f"{session_id}:{search}:{time}")[:16]`. Two different sessions with the same search query produce different job IDs. The MD5 input includes session_id for isolation.
**Notes:** The job ID is deterministic for the same session_id + search + time combination. This is intentional for idempotency.

---

### TC-S-020: ITDR Simulate dry_run Default Behavior
**Priority:** High
**Category:** Security
**Component:** ITDR
**Preconditions:** A valid ITDR scenario (e.g., `kerberoasting`) exists.
**Steps:**
1. POST the ITDR simulate endpoint WITHOUT specifying `dry_run` parameter.
2. Observe whether any state changes occur.
**Expected Result:** The default behavior when `dry_run` is not specified should be documented. If the default is `dry_run=true`, no events are generated. If the default is `dry_run=false`, events are generated. Verify against the actual implementation.
**Notes:** The admin guide notes that `dry_run=true` may be the default. Always test the default to avoid unintended event generation during testing.

---

### TC-S-021: Block IOC — IP Type Sets Firewall State
**Priority:** High
**Category:** Security
**Component:** Actions
**Preconditions:** A running session with a registered IP in the state machine.
**Steps:**
1. Execute `block_ioc` action with `ioc_type=ip` and a valid IP value.
2. Check the firewall state for that IP.
**Expected Result:** Firewall state is set to `BLOCKED`. A firewall block event is generated. An EDR event is NOT generated for IP-type IOCs.
**Notes:** IP/IPv4/IPv6 type IOCs go to the firewall state machine. Non-IP types (domain, hash, etc.) generate EDR events instead.

---

### TC-S-022: Block IOC — Domain Type Generates EDR Event
**Priority:** High
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. Execute `block_ioc` action with `ioc_type=domain` and `ioc_value="malicious-domain.com"`.
2. Check the generated event type.
**Expected Result:** An EDR event is generated (not a firewall state change). The domain is not added to the firewall state machine.
**Notes:** Domain, hash, and other non-IP IOC types route to the EDR event path, not the firewall path.

---

### TC-S-023: Kill Process — Node Marked Terminated in Threat Graph
**Priority:** Medium
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists. Threat graph has at least one process node.
**Steps:**
1. Execute `kill_process` action with a process target.
2. Check the threat graph state for that process node.
**Expected Result:** An EDR event is generated with appropriate process kill telemetry. The process node in the threat graph is marked as `terminated`. No further events are generated from that node.
**Notes:** The `kill_process` action both generates an event AND modifies the threat graph state.

---

### TC-S-024: Inject Alert Stored as GeneratedEvent
**Priority:** Medium
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. Execute `inject_alert` action with:
   ```json
   {
     "action": "inject_alert",
     "title": "Custom Alert: Suspicious PowerShell",
     "severity": "high",
     "product_type": "custom_siem"
   }
   ```
2. Check the `GeneratedEvent` records for the session.
**Expected Result:** A `GeneratedEvent` record is created with the provided title, severity, and product_type. The event appears in subsequent calls to `GET /api/v2/sessions/{id}/events`.
**Notes:** `inject_alert` stores directly as a `GeneratedEvent` in the database.

---

### TC-S-025: Response Action Logged with Persona Key
**Priority:** Low
**Category:** Security
**Component:** Actions
**Preconditions:** A running session exists. Response actions are being tracked.
**Steps:**
1. Execute any response action (e.g., `isolate_host`).
2. Query `ResponseAction` records for this session.
**Expected Result:** A `ResponseAction` record is created containing `session_id`, `action_type`, `actor`, `target`, `params`, `result`, and `persona_key`. The `persona_key` field identifies which simulated persona triggered the action.
**Notes:** `ResponseAction` is the audit trail for all SOAR-style actions within a session.

---

## Integration Tests

### TC-I-001: Full Session Lifecycle — Create → Start → Stop with Joti Push Mock
**Priority:** High
**Category:** Integration
**Component:** Sessions / Joti
**Preconditions:** PurpleLab running. Joti mock server captures outbound requests at a configurable endpoint.
**Steps:**
1. POST `/api/v2/sessions` with `simulation_mode=ttps`, `technique_ids=["T1059.001"]`, `event_count=20`, `auto_start=false`.
2. POST start action on the session.
3. Wait 5 seconds for events to generate.
4. POST stop action on the session.
5. Check mock Joti server for the received push.
6. GET final session stats.
**Expected Result:** Session transitions stopped → running → stopped. At least some events are generated. Mock Joti server receives POST to `/api/v2/simulations` with body containing `session_id`, `session_name`, `technique_ids`, `severity`, `events_generated` (matches stats), `hit` (bool), `summary` (string).
**Notes:** The Joti push payload fields must match exactly: `session_id`, `session_name`, `technique_ids`, `severity`, `events_generated`, `hit`, `summary`.

---

### TC-I-002: CrowdStrike Isolate Host Updates EDR State Machine
**Priority:** High
**Category:** Integration
**Component:** Vendor / Actions
**Preconditions:** A running session with a `SimulatedEndpoint` in state `COMPROMISED`.
**Steps:**
1. Call the CrowdStrike Devices Actions v2 endpoint: POST `/devices/actions/v2?action_name=contain` with the device ID.
2. Wait for state change.
3. Call `GET /devices/v2` and check the device status.
**Expected Result:** The targeted `SimulatedEndpoint` transitions from `COMPROMISED` to `ISOLATED`. The CrowdStrike device detail shows `status: "contained"`. An EDR containment event is generated with `containment_status=contained`.
**Notes:** CrowdStrike device IDs are computed as `uuid.uuid5(NAMESPACE_DNS, f"{session_id}:{hostname}")`.

---

### TC-I-003: XSIAM Isolate Host Updates EDR State Machine
**Priority:** High
**Category:** Integration
**Component:** Vendor / Actions
**Preconditions:** A running session with a `SimulatedEndpoint` in state `AT_RISK` or `COMPROMISED`.
**Steps:**
1. POST to XSIAM `/endpoints/isolate` with the endpoint identifier.
2. Check the EDR state for the targeted endpoint.
**Expected Result:** The targeted endpoint transitions to `ISOLATED`. An appropriate containment event is generated in the session. The XSIAM incidents list reflects the isolation.
**Notes:** XSIAM token format: `"xsiam-sim-{uuid.hex[:20]}"`.

---

### TC-I-004: Defender Isolate Host Updates EDR State Machine
**Priority:** High
**Category:** Integration
**Component:** Vendor / Actions
**Preconditions:** A running session with a `SimulatedEndpoint`. Defender machine_id known.
**Steps:**
1. POST to Defender `/api/machines/{machine_id}/isolate`.
2. Check the EDR state for the targeted machine.
**Expected Result:** The machine transitions to `ISOLATED`. Defender riskScore for that machine transitions from `High` to whatever reflects the isolated state. An isolation event is generated.
**Notes:** Defender machine_id = `uuid.uuid5(NAMESPACE_DNS, f"mde:{session_id}:{hostname}")`.

---

### TC-I-005: Joti Audit Event Receipt Stores JotiAuditEvent in DB
**Priority:** High
**Category:** Integration
**Component:** Joti
**Preconditions:** PurpleLab running. Joti configured to forward audit events to PurpleLab.
**Steps:**
1. POST `/api/v2/joti/audit-events` with a batch of 3 audit events.
2. Query the database for `JotiAuditEvent` records matching the provided `joti_event_id` values.
**Expected Result:** All 3 events are stored. Each `JotiAuditEvent` record has `joti_event_id`, `event_type`, `action`, `user_email`, `ip_address`, `resource_type`, `resource_id`, `correlation_id`, `details`, `created_at_joti`, and `received_at` populated correctly.
**Notes:** `received_at` is the PurpleLab server time when the batch was received.

---

### TC-I-006: Use Case Run — Pending UseCaseRun Created Before Celery Dispatch
**Priority:** High
**Category:** Integration
**Component:** UseCases
**Preconditions:** A use case exists. Celery worker is running but possibly slow.
**Steps:**
1. POST `/use-cases/{id}/run`.
2. Within 100ms, GET all `UseCaseRun` records for this use case.
**Expected Result:** A `UseCaseRun` record with `status=pending` exists immediately after the POST response. The Celery task has not yet completed (possibly not even started).
**Notes:** The pending run creation is synchronous. This is critical for the UI to show "run in progress" immediately.

---

### TC-I-007: EDR State Machine — ONLINE to AT_RISK via T1059
**Priority:** High
**Category:** Integration
**Component:** Sessions
**Preconditions:** A running session with an endpoint in `ONLINE` state.
**Steps:**
1. Generate or wait for an event with a technique ID in `{T1059, T1078, T1021, T1105, T1547}` targeting this endpoint.
2. Check the endpoint state after the event.
**Expected Result:** The endpoint transitions from `ONLINE` to `AT_RISK`. An EDR alert event is generated as a secondary event. No Windows EventLog or auto-isolation events at this stage.
**Notes:** `anomaly_detected` trigger fires on T1059, T1078, T1021, T1105, T1547. Secondary events: EDR alert always fires; Windows EventLog fires only at COMPROMISED/ISOLATED.

---

### TC-I-008: EDR State Machine — AT_RISK to COMPROMISED via T1003
**Priority:** High
**Category:** Integration
**Component:** Sessions
**Preconditions:** An endpoint is in `AT_RISK` state within a running session.
**Steps:**
1. Generate or wait for an event with technique T1003 targeting this endpoint.
2. Check the endpoint state.
3. Check for secondary events.
**Expected Result:** Endpoint transitions from `AT_RISK` to `COMPROMISED`. `confirmed_detection` trigger fires (T1003 is in `{T1003, T1055, T1041, T1486}`). Secondary events: EDR alert event + Windows EventLog event (Windows EventLog fires at COMPROMISED stage).
**Notes:** Windows EventLog secondary events fire at COMPROMISED and ISOLATED states only.

---

### TC-I-009: EDR State Machine — COMPROMISED to ISOLATED via isolation_requested
**Priority:** High
**Category:** Integration
**Component:** Sessions
**Preconditions:** An endpoint is in `COMPROMISED` state.
**Steps:**
1. Trigger the `isolation_requested` event (e.g., via `isolate_host` action or CrowdStrike contain).
2. Check the endpoint state.
3. Check for the auto-isolation secondary event.
**Expected Result:** Endpoint transitions from `COMPROMISED` to `ISOLATED`. An auto-isolation event is generated as a secondary event. An EDR alert event is also generated. A Windows EventLog event is generated (ISOLATED is one of the states that triggers Windows EventLog secondary events).
**Notes:** At ISOLATED state: EDR alert + Windows EventLog + auto-isolation event are all generated.

---

### TC-I-010: EDR State Machine — False Positive Returns AT_RISK to ONLINE
**Priority:** High
**Category:** Integration
**Component:** Sessions
**Preconditions:** An endpoint is in `AT_RISK` state.
**Steps:**
1. Trigger a `false_positive` event on the endpoint in `AT_RISK` state.
2. Check the endpoint state.
**Expected Result:** Endpoint transitions from `AT_RISK` back to `ONLINE`. No containment-related secondary events are generated. The state machine correctly handles the false positive path.
**Notes:** The false_positive trigger is specifically an AT_RISK → ONLINE transition. It is not valid from COMPROMISED or ISOLATED states.

---

### TC-I-011: EDR State Machine — High-Fidelity Source Triggers confirmed_detection Directly
**Priority:** High
**Category:** Integration
**Component:** Sessions
**Preconditions:** A running session with an ONLINE endpoint. Generator uses a high-fidelity source (`crowdstrike`, `edr`, or `crowdstrike_edr`).
**Steps:**
1. Generate an event from a high-fidelity source (product_type in `{crowdstrike, edr, crowdstrike_edr}`) targeting the ONLINE endpoint.
2. Check the endpoint state after the event.
**Expected Result:** The endpoint transitions ONLINE → COMPROMISED directly, skipping AT_RISK. The `confirmed_detection` trigger fires for high-fidelity sources regardless of technique ID.
**Notes:** High-fidelity sources always fire `confirmed_detection`. This is a key behavioral distinction — CrowdStrike detections are treated as confirmed, not anomaly alerts.

---

### TC-I-012: Block IOC (IP Type) Sets Firewall State to BLOCKED
**Priority:** High
**Category:** Integration
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. POST `block_ioc` action with `ioc_type=ipv4`, `ioc_value="192.168.1.100"`.
2. Check the firewall state machine for that IP.
3. Check generated events.
**Expected Result:** Firewall state for `192.168.1.100` is set to `BLOCKED`. A firewall block event is generated with appropriate fields. An EDR event is NOT generated for this IP-type IOC.
**Notes:** Valid IP types triggering firewall: `ip`, `ipv4`, `ipv6`.

---

### TC-I-013: Block IOC (Domain Type) Generates EDR Event (Not Firewall)
**Priority:** High
**Category:** Integration
**Component:** Actions
**Preconditions:** A running session exists.
**Steps:**
1. POST `block_ioc` action with `ioc_type=domain`, `ioc_value="evil-domain.com"`.
2. Check the firewall state machine.
3. Check generated events.
**Expected Result:** The firewall state machine is NOT modified. An EDR event is generated recording the domain block. The event's `product_type` reflects an EDR source.
**Notes:** This test confirms the routing logic: IP → firewall state, non-IP → EDR event.

---

### TC-I-014: Session Stop Triggers push_simulation_result with Correct Payload
**Priority:** High
**Category:** Integration
**Component:** Sessions / Joti
**Preconditions:** A running session exists. JotiClient is configured with a mock endpoint.
**Steps:**
1. Stop the session.
2. Capture the outbound POST to the Joti mock endpoint.
3. Verify the payload structure.
**Expected Result:** POST body contains exactly: `session_id` (UUID string), `session_name` (string), `technique_ids` (list), `severity` (string), `events_generated` (int matching session.events_sent), `hit` (bool), `summary` (string). The Joti client sends `Authorization: Bearer {api_key}` and `X-Source: purplelab` headers.
**Notes:** `get_joti_client()` returns None if JOTI_BASE_URL or JOTI_API_KEY is not set, so ensure both are configured for this test.

---

### TC-I-015: SPL Saved Search Creates DeployedDetection via execute_action
**Priority:** Medium
**Category:** Integration
**Component:** Vendor / Actions
**Preconditions:** A running session exists. Splunk emulation accessible.
**Steps:**
1. Create a Splunk saved search via the appropriate Splunk endpoint.
2. Check the `DeployedDetection` records in the database.
**Expected Result:** A `DeployedDetection` record is created in the database with `status=deployed`. The detection is linked to the current session. `sigma_yaml` may be empty; `query_spl` is populated from the saved search.
**Notes:** This integration is triggered via `execute_action` when a saved search creation implies a deployed detection.

---

### TC-I-016: XSIAM get_query_results Accepts Both query_id and execution_id
**Priority:** High
**Category:** Integration
**Component:** Vendor
**Preconditions:** An XQL job has been submitted and its ID is known.
**Steps:**
1. Submit an XQL query and capture the returned `query_id`.
2. GET results using `?query_id={id}`.
3. GET results using `?execution_id={id}` (same value).
4. Compare the two responses.
**Expected Result:** Both parameter names return the same result set. The `_xql_jobs` dict lookup succeeds with either parameter name.
**Notes:** XSIAM accepts both `query_id` and `execution_id` as equivalent parameters for fetching XQL results.

---

### TC-I-017: CrowdStrike Detection IDs Only Include High/Critical Events
**Priority:** High
**Category:** Integration
**Component:** Vendor
**Preconditions:** A session with events of all severity levels (critical, high, medium, low, info).
**Steps:**
1. List CrowdStrike detections for the session.
2. Note all returned detection IDs.
3. Cross-reference with the session events.
**Expected Result:** CrowdStrike detections only include events with `severity=high` or `severity=critical`. Medium, low, and info severity events do not appear as CrowdStrike detections. Detection ID format: `"ldt:{id_no_hyphens}:1"`.
**Notes:** The CrowdStrike emulation filters to high/critical severity to match real CrowdStrike detection behavior.

---

### TC-I-018: Defender Machine riskScore Mapping
**Priority:** High
**Category:** Integration
**Component:** Vendor
**Preconditions:** A session with endpoints in various EDR states (compromised, at_risk, online).
**Steps:**
1. GET Defender machines for the session.
2. Check `riskScore` for each machine.
**Expected Result:** Machine in `COMPROMISED` state → `riskScore: "High"`. Machine in `AT_RISK` state → `riskScore: "Medium"`. Machine in any other state (ONLINE, ISOLATED, REMEDIATED) → `riskScore: "Low"`.
**Notes:** The riskScore mapping is deterministic: compromised=High, at_risk=Medium, else=Low.

---

### TC-I-019: Splunk Server Info Returns Correct Version String
**Priority:** Low
**Category:** Integration
**Component:** Vendor
**Preconditions:** Splunk emulation accessible.
**Steps:**
1. GET the Splunk server info endpoint (typically `/services/server/info`).
2. Check the `version` field.
**Expected Result:** Returns `version: "9.1.0 (PurpleLab Emulation)"`. The response mimics the Splunk server info REST response format.
**Notes:** This allows SIEM tools configured to point at PurpleLab to identify the Splunk version.

---

### TC-I-020: ITDR Dispatch Exercise Sends POST to /v2/scenarios
**Priority:** Medium
**Category:** Integration
**Component:** ITDR
**Preconditions:** PurpleLab API running. Monitor outbound calls.
**Steps:**
1. Trigger ITDR scenario simulation for `kerberoasting` with `dry_run=false`.
2. Check that the exercise dispatch includes the correct endpoint and payload.
**Expected Result:** PurpleLab sends a POST to `/v2/scenarios` with `name` = `"ITDR: kerberoasting"` (or equivalent). The dispatch uses the scenario name prefixed with `"ITDR: "`.
**Notes:** This naming convention distinguishes ITDR exercises from regular use case runs in the scenario audit trail.

---

## Performance Tests

### TC-P-001: List Sessions with 1000 Sessions in DB
**Priority:** Medium
**Category:** Performance
**Component:** Sessions
**Preconditions:** Database populated with 1000 session records via seed script.
**Steps:**
1. GET `/api/v2/sessions?limit=50` and measure response time.
2. Repeat 5 times and average.
**Expected Result:** Average response time < 500ms. Pagination is used; the endpoint does NOT return all 1000 records at once.
**Notes:** The query must use `LIMIT`/`OFFSET` efficiently. Ensure a database index exists on `status` and `created_at`.

---

### TC-P-002: Session Events Endpoint with 10,000 Events, limit=500
**Priority:** High
**Category:** Performance
**Component:** Sessions
**Preconditions:** A single session with 10,000 `GeneratedEvent` records in the database.
**Steps:**
1. GET `/api/v2/sessions/{id}/events?limit=500` and measure response time.
2. Repeat 5 times and average.
**Expected Result:** Average response time < 1 second. Returns exactly 500 events. The query uses a database index on `session_id`.
**Notes:** `GeneratedEvent` records should be indexed on `(session_id, created_at)` for efficient pagination.

---

### TC-P-003: Session Stats with 5000 Events
**Priority:** Medium
**Category:** Performance
**Component:** Sessions
**Preconditions:** A session with 5000 `GeneratedEvent` records.
**Steps:**
1. GET `/api/v2/sessions/{id}/stats` and measure response time.
2. Repeat 5 times and average.
**Expected Result:** Average response time < 2 seconds. The stats aggregation (by_severity, by_source, top_techniques, events_per_minute) completes within the time limit.
**Notes:** Stats aggregation may use SQL GROUP BY which is fast, or Python-side aggregation which is slower. If stats are slow, recommend SQL aggregation.

---

### TC-P-004: CrowdStrike List Devices with 50 Hostnames in State Machine
**Priority:** Medium
**Category:** Performance
**Component:** Vendor
**Preconditions:** A session with 50 `SimulatedEndpoint` records, all registered in the CrowdStrike state machine.
**Steps:**
1. GET the CrowdStrike devices endpoint with the session_id.
2. Measure response time.
3. Repeat 10 times.
**Expected Result:** Average response time < 200ms. All 50 devices are returned in a single response (or properly paginated).
**Notes:** The CrowdStrike state machine is in-memory. With 50 entries the dict lookup is O(n) but should still be fast.

---

### TC-P-005: SPL Search with 1000 Stored Events
**Priority:** Medium
**Category:** Performance
**Component:** Vendor
**Preconditions:** A session with 1000 GeneratedEvent records of varying `product_type` values.
**Steps:**
1. Submit an SPL search that matches a common `product_type` (e.g., `sourcetype=crowdstrike`).
2. Check job status and retrieve results.
3. Measure end-to-end time.
**Expected Result:** Job creation < 100ms. Result retrieval < 1 second total. Returns matching events within the limit.
**Notes:** Splunk `_jobs` dict stores results in-memory. With 1000 events, the filter is an in-memory list comprehension.

---

### TC-P-006: XSIAM XQL Query with 200 Events (Limit)
**Priority:** Medium
**Category:** Performance
**Component:** Vendor
**Preconditions:** A session with at least 500 events.
**Steps:**
1. Submit an XQL query with a `limit` of 200.
2. Retrieve the results.
3. Measure total time.
**Expected Result:** Response time < 500ms. Returns exactly 200 events. XQL job is stored in `_xql_jobs` dict.
**Notes:** XSIAM XQL results are stored in-memory. The limit parameter caps the result set.

---

### TC-P-007: Defender List Alerts with 50 Events
**Priority:** Medium
**Category:** Performance
**Component:** Vendor
**Preconditions:** A session with 50+ high/critical severity events.
**Steps:**
1. GET Defender alerts for the session.
2. Measure response time.
3. Repeat 5 times.
**Expected Result:** Average response time < 500ms. Only high/critical events are returned. Defender alert filtering happens efficiently.
**Notes:** Defender only returns high/critical severity events as alerts. Medium/low/info are excluded.

---

### TC-P-008: SSE Stream First Event Delivery Latency
**Priority:** High
**Category:** Performance
**Component:** Sessions
**Preconditions:** No sessions running.
**Steps:**
1. Create a session with `event_count=10` and `auto_start=false`.
2. Connect to the SSE stream: GET `/api/v2/sessions/{id}/events/stream`.
3. Start the session.
4. Measure time from session start until first SSE `data:` event is received by the client.
**Expected Result:** First event is delivered within 3 seconds of session start. The SSE polling interval is 1.5 seconds, so one full poll cycle plus processing should be < 3 seconds.
**Notes:** The SSE endpoint polls every 1.5 seconds. Worst case delivery latency is 1.5s (one poll interval).

---

### TC-P-009: Use Cases List with 500 Use Cases
**Priority:** Low
**Category:** Performance
**Component:** UseCases
**Preconditions:** Database populated with 500 use case records.
**Steps:**
1. GET `/use-cases` with default pagination.
2. Measure response time.
3. GET with `limit=50` and measure again.
**Expected Result:** Default paginated response < 500ms. The response does not return all 500 records without pagination.
**Notes:** Use cases should be paginated. Returning 500 records in a single response without pagination would likely be slower than the threshold.

---

### TC-P-010: Concurrent Session Isolation — 10 Sessions Running Simultaneously
**Priority:** High
**Category:** Performance
**Component:** Sessions
**Preconditions:** No sessions running.
**Steps:**
1. Create and start 10 sessions simultaneously, each with `event_count=100` and different `technique_ids`.
2. After 30 seconds, GET events for each session.
3. Verify that session A's events contain only session A's events, and so on for all 10.
4. Stop all sessions.
**Expected Result:** All 10 sessions run without errors. Each session's events are scoped correctly (no cross-session events). Total events across all sessions = sum of individual session events_sent. No database connection pool exhaustion.
**Notes:** This tests both isolation and concurrency. The database `session_id` FK on `GeneratedEvent` is the isolation boundary.

---

## Regression Tests

### TC-R-001: XSIAM Quota Endpoint Returns Correct Fields
**Priority:** High
**Category:** Regression
**Component:** Vendor
**Preconditions:** XSIAM emulation accessible.
**Steps:**
1. GET the XSIAM quota endpoint.
2. Verify all three required fields are present.
**Expected Result:** Response contains exactly: `fixed_quota` (number), `additional_purchased_quota` (number), `license_quota` (number). No extra fields added. No fields missing.
**Notes:** This is a regression check — the XSIAM quota structure must not drift from these three fields as the simulator evolves.

---

### TC-R-002: Session Name Auto-Generation
**Priority:** Medium
**Category:** Regression
**Component:** Sessions
**Preconditions:** None.
**Steps:**
1. POST `/api/v2/sessions` with `"name": "Untitled Session"`.
2. POST `/api/v2/sessions` with `"name": ""` (empty string).
3. Check the names in the created session records.
**Expected Result:** Both cases result in the session being assigned an auto-generated name (not "Untitled Session" or empty). The auto-generated name is unique and descriptive (e.g., includes a timestamp or sequential number).
**Notes:** The name auto-generation logic is triggered when name is "Untitled Session" or empty. This prevents a database of sessions all named "Untitled Session".

---

### TC-R-003: SSE Heartbeat Format is SSE Comment Syntax
**Priority:** High
**Category:** Regression
**Component:** Sessions
**Preconditions:** A running session with low event generation rate.
**Steps:**
1. Connect to the SSE stream.
2. Wait for a heartbeat to be emitted (5 consecutive idle polls = ~7.5s).
3. Capture the raw SSE bytes.
**Expected Result:** Heartbeat raw text is exactly `: heartbeat\n\n` — an SSE comment line (colon prefix) followed by double newline. It is NOT `data: {"type": "heartbeat"}\n\n`. SSE clients will ignore SSE comment lines, which is the intended behavior.
**Notes:** Using comment syntax for heartbeats is important — it prevents SSE clients from treating the heartbeat as a data event.

---

### TC-R-004: Splunk Job ID Format
**Priority:** High
**Category:** Regression
**Component:** Vendor
**Preconditions:** Splunk emulation accessible. A session exists.
**Steps:**
1. Submit a Splunk search job.
2. Capture the returned `sid` (search ID / job ID).
3. Verify the format.
**Expected Result:** Job ID starts with `"sim_"` followed by exactly 16 hexadecimal characters (the first 16 chars of the MD5 digest of `f"{session_id}:{search}:{time}"`). Total length: 20 characters (`"sim_"` + 16 hex chars).
**Notes:** The format `"sim_" + md5(...)[:16]` is fixed. Changes to this format break integrations that parse job IDs.

---

### TC-R-005: CrowdStrike Device ID Derivation
**Priority:** High
**Category:** Regression
**Component:** Vendor
**Preconditions:** A session with a known `session_id` and a `SimulatedEndpoint` with known `hostname`.
**Steps:**
1. List CrowdStrike devices for the session.
2. Capture the `device_id` for a specific hostname.
3. Compute the expected device_id manually: `str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{session_id}:{hostname}"))`.
4. Compare.
**Expected Result:** The returned `device_id` matches the manually computed `uuid.uuid5(NAMESPACE_DNS, f"{session_id}:{hostname}")` exactly.
**Notes:** Device IDs are deterministic. Re-running a session with the same session_id and hostname must produce the same device_id. This matters for any tooling that caches device IDs.

---

### TC-R-006: Defender Machine ID Derivation
**Priority:** High
**Category:** Regression
**Component:** Vendor
**Preconditions:** A session with a known `session_id` and a `SimulatedEndpoint` with known `hostname`.
**Steps:**
1. List Defender machines for the session.
2. Capture the `id` for a specific hostname.
3. Compute the expected machine_id: `str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:{hostname}"))`.
4. Compare.
**Expected Result:** The returned machine `id` matches the manually computed value. Note the `"mde:"` prefix — this distinguishes Defender IDs from CrowdStrike IDs for the same hostname.
**Notes:** The `"mde:"` prefix in the UUID input is intentional — it prevents namespace collisions between CrowdStrike and Defender device IDs for the same session/hostname.

---

### TC-R-007: Benign Events Produce No Secondary Events
**Priority:** High
**Category:** Regression
**Component:** Sessions
**Preconditions:** An endpoint in any state within a running session.
**Steps:**
1. Generate or inject an event that is marked as benign (`_benign=True` in the event generator).
2. Count the total number of events generated by the session before and after.
**Expected Result:** The benign event itself is generated (1 event added). No secondary events (EDR alert, Windows EventLog, auto-isolation) are generated as a result of the benign event. The endpoint state does NOT change.
**Notes:** Benign events are informational only. They model normal/expected behavior that should not trigger the state machine.

---

### TC-R-008: State Transition Events Produce No Secondary Events
**Priority:** High
**Category:** Regression
**Component:** Sessions
**Preconditions:** An endpoint that will undergo a state transition.
**Steps:**
1. Trigger a state transition event (internally marked `_state_transition=True`).
2. Count secondary events generated.
**Expected Result:** The state transition event records the state change. No additional secondary events are generated from the `_state_transition` event itself. (Secondary events are generated by the preceding primary event that caused the transition, not by the transition record itself.)
**Notes:** This prevents infinite loops: a secondary event triggering another state transition which generates another secondary event, etc.

---

### TC-R-009: JotiClient Returns None When JOTI_BASE_URL is Empty String
**Priority:** High
**Category:** Regression
**Component:** Joti
**Preconditions:** Set `JOTI_BASE_URL` environment variable to `""` (empty string). Set `JOTI_API_KEY` to any value.
**Steps:**
1. Call `get_joti_client()` from the PurpleLab backend.
2. Inspect the return value.
**Expected Result:** `get_joti_client()` returns `None`. The empty string is treated the same as an unset variable. No JotiClient is instantiated with an empty base URL.
**Notes:** The check is for both `JOTI_BASE_URL` being absent OR being an empty string. This prevents requests being sent to `http:///api/v2/simulations`.

---

### TC-R-010: Session Delete Returns Correct Response Structure
**Priority:** Medium
**Category:** Regression
**Component:** Sessions
**Preconditions:** A `stopped` session exists with a known `id`.
**Steps:**
1. DELETE `/api/v2/sessions/{id}`.
2. Capture the full response body.
**Expected Result:** Response body is exactly `{"status": "deleted", "id": "<session_id>"}`. The `id` field contains the session UUID that was deleted (as a string). HTTP status is 200.
**Notes:** The response structure `{"status": "deleted", "id": ...}` is fixed. Changes to the key names or status value string would be a breaking change.

---

*End of Test Cases — 105 tests total across 5 categories*

| Category | Count | ID Range |
|----------|-------|----------|
| Functional | 40 | TC-F-001 to TC-F-040 |
| Security | 25 | TC-S-001 to TC-S-025 |
| Integration | 20 | TC-I-001 to TC-I-020 |
| Performance | 10 | TC-P-001 to TC-P-010 |
| Regression | 10 | TC-R-001 to TC-R-010 |
| **Total** | **105** | |
