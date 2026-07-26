# PurpleLab User and Admin Guide

**Version:** 1.0 | **Date:** 2026-07-26 | **Platform:** PurpleLab Cybersecurity Simulation Platform
**Stack:** FastAPI + SQLAlchemy async + PostgreSQL (port 5434) + Python 3.11

---

## Table of Contents

**Part 1: User Guide**
1. [Getting Started](#1-getting-started)
2. [Creating Your First Session](#2-creating-your-first-session)
3. [Simulation Modes](#3-simulation-modes)
4. [Starting and Monitoring a Session](#4-starting-and-monitoring-a-session)
5. [Running a Use Case](#5-running-a-use-case)
6. [Identity Simulation](#6-identity-simulation)
7. [ITDR Scenarios](#7-itdr-scenarios)
8. [Connecting Vendor Tools](#8-connecting-vendor-tools)
9. [Connecting to Joti TIP](#9-connecting-to-joti-tip)

**Part 2: Admin Guide**
1. [Configuration](#1-configuration)
2. [Session Management](#2-session-management)
3. [Use Case Library](#3-use-case-library)
4. [ITDR Scenario Library](#4-itdr-scenario-library)
5. [Vendor API State](#5-vendor-api-state)
6. [Database Migrations](#6-database-migrations)
7. [Log Sources and Monitoring](#7-log-sources-and-monitoring)
8. [Joti Audit Event Forwarding](#8-joti-audit-event-forwarding)
9. [Troubleshooting](#9-troubleshooting)

---

# Part 1: User Guide

## 1. Getting Started

### What PurpleLab Is

PurpleLab is a cybersecurity simulation platform designed for purple team exercises. It generates realistic security telemetry — endpoint detection events, identity events, network events, and SIEM alerts — without requiring live attacks on real infrastructure. The platform emulates the APIs of major security tools (Splunk, CrowdStrike, Microsoft Defender, Cortex XSIAM), so your detection rules and hunt queries can be tested against realistic data in a controlled environment.

PurpleLab serves two primary audiences:

- **Security Engineers and Threat Hunters** who want to validate that detection rules fire correctly against known attack techniques, measure detection coverage gaps, and run ITDR scenarios against identity simulation.
- **SOC Analysts and Purple Team Leads** who want to run use case libraries against simulated environments, score detection efficacy, and push simulation results into a threat intelligence platform like Joti.

### Prerequisites

- Docker and Docker Compose installed on the host.
- Network access to the PurpleLab backend (default internal port: 8002).
- An HTTP client (curl, Postman, or any REST client).
- Optional: Joti TIP instance for integrated threat intelligence workflows.

### Accessing the API

PurpleLab exposes a REST API. The internal port is typically 8002, though your deployment may expose it differently. Check `docker-compose.yml` for the published port.

To verify the API is running:

```
GET /health
```

Expected response: `{"status": "ok"}` or equivalent.

All API paths in this guide use the `/api/v2/` prefix unless otherwise noted. The full base URL in a default local deployment is `http://localhost:8002`.

---

## 2. Creating Your First Session

A **session** is the core unit of work in PurpleLab. It represents a single simulation run — a bounded period during which the platform generates security events according to a chosen simulation mode.

### Minimal Session Creation

The simplest way to start is with the `attack_chain` mode. This generates a realistic sequence of events representing a multi-stage intrusion.

```
POST /api/v2/sessions
Content-Type: application/json

{
  "name": "My First Simulation",
  "simulation_mode": "attack_chain",
  "attack_chains": ["initial_access", "lateral_movement"],
  "event_count": 50
}
```

**Required fields:**
- `simulation_mode` — one of `attack_chain`, `threat_actor`, `ttps`, `mcp_ingest`
- `event_count` — number of events to generate, between 10 and 2000

**Optional fields:**
- `name` — human-readable name for the session; auto-generated if empty or `"Untitled Session"`
- `auto_start` — set to `true` to start generating events immediately on creation (default: false)

**Response:** The API returns the created session object including:
- `id` — UUID identifying the session (save this for all subsequent calls)
- `status` — `stopped` (or `running` if auto_start was true)
- `events_sent` — starts at 0
- `errors` — starts at 0

### auto_start Behavior

If you set `"auto_start": true`, the session begins generating events immediately as part of the creation response. You do not need to make a separate start call. This is the recommended approach for quick testing.

If `auto_start` is false (the default), you must explicitly start the session after creation.

---

## 3. Simulation Modes

PurpleLab supports four simulation modes, each targeting a different use case.

### attack_chain

Use this mode when you want to simulate a realistic multi-stage attack campaign following known kill chain patterns. You specify one or more `attack_chains` from the platform's built-in chain library.

```json
{
  "simulation_mode": "attack_chain",
  "attack_chains": ["initial_access", "lateral_movement", "exfiltration"],
  "event_count": 150
}
```

Events are generated in a sequence that mimics how an attacker would progress through the stages, ensuring temporal correlation between events.

### threat_actor

Use this mode when you want to simulate the behavior of a specific known threat actor group. Provide either `threat_actor_id` (a database record ID) or `threat_actor_name` (a string). Combine with `threat_actor_ttps` to specify the technique IDs associated with this actor.

```json
{
  "simulation_mode": "threat_actor",
  "threat_actor_name": "APT29",
  "threat_actor_ttps": ["T1566.001", "T1078", "T1021.001", "T1059.001"],
  "event_count": 100
}
```

The platform generates events biased toward the provided TTPs, simulating how that threat actor would behave in your environment.

### ttps

Use this mode when you want to directly specify ATT&CK technique IDs to simulate, without framing it as a named threat actor campaign. This is the most direct way to test specific detection rules.

```json
{
  "simulation_mode": "ttps",
  "technique_ids": ["T1003.001", "T1059.003", "T1086", "T1486"],
  "event_count": 75
}
```

Events are generated for each specified technique. This mode is ideal for validating that a specific Sigma rule fires when the corresponding technique is executed.

### mcp_ingest

Use this mode when you want PurpleLab to pull technique data from an external MCP (Model Context Protocol) server and use it to drive the simulation. This enables dynamic simulation where the techniques being simulated are informed by live threat intelligence.

```json
{
  "simulation_mode": "mcp_ingest",
  "mcp_server_url": "http://your-mcp-server:8080",
  "mcp_api_key": "your-api-key",
  "mcp_tool": "siem_search_events",
  "event_count": 50
}
```

**Supported MCP tools:**
- `siem_search_events` — queries the MCP server for SIEM events and extracts technique IDs
- `siem_get_alerts` — queries for alerts and extracts technique IDs
- `edr_get_detections` — queries for EDR detections and extracts technique IDs

After starting an `mcp_ingest` session, you can manually trigger a technique resolution:

```
POST /api/v2/sessions/{id}/resolve-mcp
```

This sends a JSON-RPC request to the configured MCP server, retrieves events, and extracts technique IDs from the `technique_id`, `mitre_technique`, and `tags` fields of the returned data.

---

## 4. Starting and Monitoring a Session

### Starting a Session

If you created the session without `auto_start`, start it explicitly:

```
POST /api/v2/sessions/{session_id}/start
```

The session transitions to `running` status and begins generating events.

### Checking Session Status

```
GET /api/v2/sessions/{session_id}
```

The response includes:
- `status` — `stopped`, `running`, or `paused`
- `events_sent` — cumulative count of events successfully generated and stored
- `errors` — count of event generation errors
- `last_event_at` — timestamp of the most recently generated event
- `recent_events` — array of the most recently generated events

### Getting Session Statistics

```
GET /api/v2/sessions/{session_id}/stats
```

The stats response includes:

- `events_per_minute` — calculated from the `created_at` timestamp range across all events in the session. Note: this uses actual event timestamps, not elapsed wall clock time.
- `top_techniques` — technique IDs extracted from event `title` fields, ranked by frequency
- `by_severity` — event counts grouped by severity (`critical`, `high`, `medium`, `low`, `info`)
- `by_source` — event counts grouped by `product_type` (the log source, such as `crowdstrike`, `okta`, `windows_event_log`)

### Fetching Events

```
GET /api/v2/sessions/{session_id}/events?skip=0&limit=100&severity=high
```

Parameters:
- `skip` — number of events to skip (pagination offset)
- `limit` — max events to return, between 1 and 500
- `severity` — optional filter; one of `critical`, `high`, `medium`, `low`, `info`

Each event contains: `id`, `session_id`, `product_type`, `severity`, `title`, `payload` (JSONB), `target_url`, `status_code`, `success`.

### Streaming Events in Real Time

For real-time event monitoring, use the SSE (Server-Sent Events) stream:

```
GET /api/v2/sessions/{session_id}/events/stream
Accept: text/event-stream
```

The stream delivers each new event as a `data:` line as it is generated. The stream polls internally every 1.5 seconds.

**Idle heartbeat:** When no new events are available for 5 consecutive poll cycles (approximately 7.5 seconds), the stream emits a heartbeat:
```
: heartbeat
```
This is an SSE comment line, not a data event. SSE clients will silently ignore it; it exists to keep the connection alive through proxies and load balancers.

**End of stream:** When the session stops, the stream emits:
```
data: {"type": "done"}
```
and then closes the connection.

### Stopping a Session

```
POST /api/v2/sessions/{session_id}/stop
```

The session transitions to `stopped` status. Event generation halts. If Joti TIP is configured, the simulation result is automatically pushed to Joti at this point (see Section 9).

---

## 5. Running a Use Case

Use cases are the structured test library of PurpleLab. Each use case defines a detection scenario tied to ATT&CK techniques, and can be run to produce a scored `UseCaseRun` result.

### Creating a Use Case

```
POST /use-cases
Content-Type: application/json

{
  "name": "LSASS Memory Access Detection",
  "description": "Validates detection of credential dumping via LSASS memory access",
  "technique_ids": ["T1003.001"],
  "tactic": "credential_access",
  "severity": "high",
  "tags": ["windows", "lsass", "credential_access"]
}
```

Fields:
- `technique_ids` — list of ATT&CK technique IDs (JSONB array)
- `tactic` — ATT&CK tactic name
- `severity` — `critical`, `high`, `medium`, or `low`
- `tags` — list of string tags (JSONB array); the `"identity"` tag enables identity simulation (see Section 6)

The created use case has `is_active=true`, `is_builtin=false`, and `last_validated_at=null` initially.

### Running a Use Case

```
POST /use-cases/{id}/run
```

**Important:** A `UseCaseRun` record with `status=pending` and `triggered_by=manual` is created synchronously before the task is dispatched. This means the run is immediately visible even while Celery is processing it. The API returns immediately — you do not wait for the run to complete.

The Celery task `run_use_case_task` then executes asynchronously, simulating events for the use case's technique IDs and evaluating whether any configured detection rules fired.

### Checking Run History

```
GET /use-cases/{id}/runs
```

Returns all `UseCaseRun` records for the use case, most recent first. Each run includes:
- `status` — `pending`, `running`, `passed`, `failed`, `partial`, or `error`
- `triggered_by` — `manual`, `pipeline`, `scheduled`, or `agent`
- `events_generated` — how many events were produced during the run
- `rules_tested` — number of detection rules evaluated
- `rules_fired` — number of rules that fired (detected the simulated technique)
- `pass_rate` — percentage of rules that fired (0.0 to 1.0)
- `run_details` — JSONB with additional run metadata

### Running All Use Cases

To run all active use cases at once:

```
POST /use-cases/run-all
```

This dispatches the Celery task `run_all_use_cases_task`. It is non-blocking — all active use cases will run asynchronously.

### Coverage Summary

```
GET /use-cases/coverage
```

Returns the organization's detection coverage across ATT&CK techniques, based on `UseCaseRun` history. Shows which techniques have passing detections, which are failing, and a breakdown by tactic.

### Finding Failing Use Cases

```
GET /use-cases/failing
```

Returns use cases that have either never been run, or have runs but none with `status=passed`. Use this to identify detection gaps.

---

## 6. Identity Simulation

Identity simulation allows use cases to trigger real identity-related actions against simulated users (Okta events, account lifecycle events). To enable identity simulation for a use case, the use case must have `"identity"` in its `tags` array.

### Simulating an Identity Action

```
POST /use-cases/{id}/simulate-identity
Content-Type: application/json

{
  "action": "disable_user",
  "dry_run": false
}
```

**Valid actions:**

| Action | Effect |
|--------|--------|
| `lock_user` | Locks the simulated user account |
| `unlock_user` | Unlocks the simulated user account |
| `disable_user` | Sets identity state to DISABLED; generates Okta event `user.lifecycle.deactivate` |
| `enable_user` | Sets identity state to REMEDIATED; generates Okta event `user.lifecycle.activate` |
| `revoke_sessions` | Revokes all active sessions for the simulated user |
| `force_mfa` | Forces MFA re-enrollment |
| `force_pw_reset` | Generates Okta event `user.account.reset_password`; returns a `reset_token` (partial) |

**Auto-seeding:** If no `SimulatedUser` records exist when this endpoint is called, PurpleLab automatically seeds a simulated user before running the action.

**Dry run mode:** Set `"dry_run": true` to preview what the action would do without making any state changes or generating events. Use this to validate your request before committing.

**Error responses:**
- `400` — use case does not have the `"identity"` tag
- `400` — invalid action; response includes a `valid_actions` list of all 7 accepted values

---

## 7. ITDR Scenarios

PurpleLab includes 10 built-in Identity Threat Detection and Response (ITDR) scenarios. These are pre-built simulation scenarios targeting specific identity-based ATT&CK techniques.

### Listing All Scenarios

```
GET /api/v2/itdr/scenarios
```

Returns all 10 scenarios. Each scenario includes its ID, name, description, and ATT&CK technique ID.

**Complete ITDR Scenario Library:**

| Scenario ID | Name | Technique ID |
|-------------|------|-------------|
| `kerberoasting` | Kerberoasting | T1558.003 |
| `pass_the_hash` | Pass-the-Hash | T1550.002 |
| `golden_ticket` | Golden Ticket | T1558.001 |
| `dcsync` | DCSync | T1003.006 |
| `mfa_fatigue` | MFA Fatigue | T1621 |
| `impossible_travel` | Impossible Travel | T1550.004 |
| `password_spray` | Password Spray | T1110.003 |
| `credential_stuffing` | Credential Stuffing | T1110.004 |
| `token_theft` | Token Theft | T1528 |
| `privileged_account_creation` | Privileged Account Creation | T1136.001 |

### Getting Scenario Detail

```
GET /api/v2/itdr/scenarios/{scenario_id}
```

Returns the full scenario detail including description, technique ID, and associated simulation metadata.

Example for Kerberoasting:
```
GET /api/v2/itdr/scenarios/kerberoasting
```
Returns `technique_id: "T1558.003"`.

### Downloading Detection Content

**Sigma YAML:**
```
GET /api/v2/itdr/scenarios/{scenario_id}/sigma
```
Returns a Sigma detection rule in YAML format for the scenario's technique.

**SPL Hunt Query:**
```
GET /api/v2/itdr/scenarios/{scenario_id}/hunts/spl
```
Returns a Splunk SPL query for hunting the technique.

**KQL Hunt Query:**
```
GET /api/v2/itdr/scenarios/{scenario_id}/hunts/kql
```
Returns a Microsoft Sentinel KQL query for hunting the technique.

### Simulating a Scenario

**Always start with a dry run to see what would happen:**

```
POST /api/v2/itdr/scenarios/{scenario_id}/simulate
Content-Type: application/json

{
  "dry_run": true
}
```

Review the response to understand what events would be generated. Then run without dry_run:

```
POST /api/v2/itdr/scenarios/{scenario_id}/simulate
Content-Type: application/json

{
  "dry_run": false
}
```

This generates the scenario's events in the current session context. For Kerberoasting (T1558.003), this produces realistic Kerberos service ticket request events with the distinguishing characteristics that detection rules look for.

---

## 8. Connecting Vendor Tools

PurpleLab emulates the APIs of four major security platforms. You configure your SIEM/EDR tools to point at PurpleLab's emulation endpoints, passing your `session_id` as a query parameter to scope the results.

### General Pattern

All vendor emulation endpoints accept `session_id` as a query parameter. Without a `session_id`, the emulation returns empty results (not errors).

### Splunk

Configure a Splunk SDK connection with:
- **Scheme:** http
- **Host:** `<purplelab_host>`
- **Port:** `<vendor_port>` (check your deployment)
- **Token:** any value (authentication is not enforced by the emulation layer)

**Passing session_id:** Include `?session_id={session_id}` on search requests.

**How SPL search works:**
- Searches are stored in an in-memory `_jobs` dict (not the database)
- Job IDs follow the format: `"sim_" + md5(f"{session_id}:{search}:{time}")[:16]`
- The emulation filters events by: `sourcetype` (maps to `product_type`), `host` (maps to `hostname` or `ComputerName` in payload), and quoted keyword matches in event titles

**Splunk server info:** The emulation reports `version: "9.1.0 (PurpleLab Emulation)"` to any tool that queries server metadata.

### CrowdStrike

**Authentication:**
```
POST /oauth2/token
Authorization: Basic <base64(client_id:client_secret)>
```
Returns a fake token: `"cs-sim-token-" + uuid`. Use this token as `Authorization: Bearer {token}` on all subsequent requests.

**Device IDs** are derived as `uuid.uuid5(NAMESPACE_DNS, f"{session_id}:{hostname}")`. These are deterministic — the same session and hostname always produce the same device ID.

**Detection IDs** follow the format `"ldt:{id_without_hyphens}:1"`.

**Important:** CrowdStrike detections only include events with `severity=high` or `severity=critical`. Medium, low, and info events are not exposed as CrowdStrike detections.

**Isolating a host via CrowdStrike:**
```
POST /devices/actions/v2?action_name=contain
```
This updates the EDR state machine, transitioning the endpoint to `ISOLATED`.

### Cortex XSIAM

**Authentication:** Obtain a token via the XSIAM auth endpoint. Token format: `"xsiam-sim-{uuid.hex[:20]}"`.

**XQL queries:** Submit queries and retrieve results using either `query_id` or `execution_id` — both parameter names are accepted interchangeably for result retrieval. Results are stored in-memory in the `_xql_jobs` dict.

**Incidents:** The XSIAM incidents endpoint returns endpoints in `COMPROMISED` or `AT_RISK` state as active incidents.

**Quota endpoint:** Returns `fixed_quota`, `additional_purchased_quota`, and `license_quota` fields.

**Isolating a host via XSIAM:**
```
POST /endpoints/isolate
```
Updates the EDR state machine to `ISOLATED`.

### Microsoft Defender for Endpoint

**Authentication:** Obtain a token via the Defender auth endpoint. Token format: `"mde-sim-token-{uuid.hex[:20]}"`.

**Machine IDs** are derived as `uuid.uuid5(NAMESPACE_DNS, f"mde:{session_id}:{hostname}")`. Note the `"mde:"` prefix, which distinguishes Defender machine IDs from CrowdStrike device IDs for the same session.

**Machine riskScore mapping:**
- `COMPROMISED` state → `riskScore: "High"`
- `AT_RISK` state → `riskScore: "Medium"`
- All other states → `riskScore: "Low"`

**Alerts:** Only `high` and `critical` severity events are exposed as Defender alerts.

**Isolating a machine:**
```
POST /api/machines/{machine_id}/isolate
```
If the `machine_id` is not found in the current session state, the emulation falls back to the first available host in the session snapshot rather than returning a 404.

---

## 9. Connecting to Joti TIP

PurpleLab integrates with Joti Threat Intelligence Platform to push simulation results when sessions stop, and to receive audit events from Joti.

### Configuration

Set two environment variables (see Admin Guide Section 1):
- `JOTI_BASE_URL` — the base URL of your Joti instance (e.g., `http://joti-backend:8000`)
- `JOTI_API_KEY` — a valid Joti API key

If either variable is unset or empty, `get_joti_client()` returns `None` and all Joti integration is silently disabled.

### What Gets Pushed — Simulation Results

When a session stops, PurpleLab automatically posts to Joti:

```
POST {JOTI_BASE_URL}/api/v2/simulations
Authorization: Bearer {JOTI_API_KEY}
X-Source: purplelab

{
  "session_id": "...",
  "session_name": "...",
  "technique_ids": ["T1059.001", "T1003.001"],
  "severity": "high",
  "events_generated": 87,
  "hit": true,
  "summary": "..."
}
```

This push is non-fatal — if Joti is unreachable, the session still stops successfully and the failure is logged at debug level.

### What Gets Received — Audit Events

Joti can forward its audit log to PurpleLab. Configure a PurpleLab SIEM Audit Forwarder in Joti with `target_type=purplelab` pointing to:

```
POST {PURPLELAB_BASE_URL}/api/v2/joti/audit-events
```

Joti sends batches of audit events:
```json
{
  "events": [
    {
      "joti_event_id": "...",
      "event_type": "auth",
      "action": "login",
      "user_email": "analyst@org.com",
      "ip_address": "10.1.1.1",
      "resource_type": "session",
      "resource_id": "abc123",
      "correlation_id": "...",
      "details": {...},
      "created_at_joti": "2026-07-26T10:00:00Z"
    }
  ]
}
```

Each event is stored as a `JotiAuditEvent` record in the PurpleLab database. These are available for correlation with simulation events to understand how SOC analyst actions in Joti relate to PurpleLab simulation activity.

---

# Part 2: Admin Guide

## 1. Configuration

PurpleLab is configured via environment variables. These are typically set in your `docker-compose.yml` or a `.env` file.

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string (must use `postgresql+asyncpg://`) | `postgresql+asyncpg://purplelab:password@postgres:5434/purplelab` |
| `REDIS_URL` | Redis connection string for Celery broker | `redis://redis:6379/0` |
| `BASE_URL` | PurpleLab's own base URL (for self-references) | `http://purplelab:8002` |

### Joti Integration Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `JOTI_BASE_URL` | Base URL of the Joti TIP instance | No (disables integration if absent) |
| `JOTI_API_KEY` | API key for Joti authentication | No (disables integration if absent) |

**Important:** `JOTI_BASE_URL` must be non-empty. An empty string is treated the same as absent — `get_joti_client()` returns `None` in both cases.

### Database Port Note

PurpleLab uses PostgreSQL on port **5434** (not the default 5432). This is intentional to avoid conflicts when PurpleLab is deployed alongside other PostgreSQL instances (such as Joti's database). Ensure your `DATABASE_URL` specifies port 5434 explicitly:

```
postgresql+asyncpg://user:pass@postgres:5434/purplelab
```

### AsyncPG Requirement

The `DATABASE_URL` **must** use the `postgresql+asyncpg://` scheme. PurpleLab's backend uses SQLAlchemy async sessions throughout. Using `postgresql://` (psycopg2) will cause startup failures.

---

## 2. Session Management

### Listing Running Sessions

```
GET /api/v2/sessions?status=running
```

Returns all sessions currently in `running` status. Review this regularly to identify stuck or long-running sessions.

### Understanding events_sent vs errors

- `events_sent` — total number of `GeneratedEvent` records successfully written to the database. This is the authoritative count of useful simulation data.
- `errors` — total number of event generation failures. A small error count is normal (failed outbound HTTP to target_url). High error counts indicate a configuration problem.

A session that shows `events_sent=0` and `errors > 0` after several seconds has a generation problem — check backend logs.

### Stopping a Stuck Session

If a session is `running` but not progressing (events_sent not increasing, last_event_at is stale):

```
POST /api/v2/sessions/{id}/stop
```

This transitions the session to `stopped` and signals the event generator to terminate. If the generator has crashed but the session record still shows `running`, use the stop endpoint — it is idempotent and safe to call even if the generator is no longer active.

### Deleting Sessions

```
DELETE /api/v2/sessions/{id}
```

If the session is `running`, it is stopped first, then deleted along with all associated `GeneratedEvent` records. The response is `{"status": "deleted", "id": "<session_id>"}`.

Be aware that deleting a session permanently removes all generated events for that session from the database. There is no soft delete.

---

## 3. Use Case Library

### Built-in vs User-Created Use Cases

Use cases have an `is_builtin` flag:
- `is_builtin=true` — shipped with PurpleLab; seeded on first run
- `is_builtin=false` — created by your organization

Built-in use cases provide a baseline detection library. They are seeded automatically and may be protected from deletion via the API.

### Seeding Built-in Use Cases

Built-in use cases are seeded on application startup if they do not already exist. If you need to re-seed (e.g., after a database wipe), restart the PurpleLab backend container — the seed logic runs at startup.

### Activating and Deactivating Use Cases

```
PATCH /use-cases/{id}
Content-Type: application/json

{"is_active": false}
```

Deactivated use cases (`is_active=false`) are excluded from `POST /use-cases/run-all`. They still appear in the list endpoint and can be run individually.

### last_validated_at Tracking

The `last_validated_at` field is updated when a use case completes a run with `status=passed`. Use this to identify use cases that have not been validated recently:

```
GET /use-cases?is_active=true
```

Filter locally for `last_validated_at` older than your acceptable staleness threshold (e.g., 30 days).

---

## 4. ITDR Scenario Library

### Static In-Memory Scenarios

All 10 ITDR scenarios are defined in a static in-memory dictionary in the PurpleLab source code. They are **not stored in the database** and **cannot be created, updated, or deleted via the API**.

This is intentional design — ITDR scenarios are curated, versioned content tied to specific ATT&CK technique IDs. Modifications require a code change and container rebuild.

**Scenario IDs are fixed:**
`kerberoasting`, `pass_the_hash`, `golden_ticket`, `dcsync`, `mfa_fatigue`, `impossible_travel`, `password_spray`, `credential_stuffing`, `token_theft`, `privileged_account_creation`

Attempting to GET an unknown scenario ID returns 404. There is no endpoint to create or modify scenarios.

### Adding New ITDR Scenarios

If a new scenario is needed, it must be added to the static scenario dictionary in the backend source code. After adding, rebuild the container image and restart.

---

## 5. Vendor API State

### In-Memory State (Not Persisted)

Two key parts of the vendor API emulation use in-memory state that is lost on restart:

**Splunk:**
- `_jobs` dict — stores submitted search jobs and their results
- `_saved_searches` dict — stores saved searches

**Impact:** If PurpleLab restarts while a Splunk integration is in the middle of polling for results, the job will return empty. Clients must re-submit their searches after a restart.

**EDR State Machine:**
- `_machines` dict — tracks the current EDR state (`ONLINE`, `AT_RISK`, `COMPROMISED`, `ISOLATED`, `REMEDIATED`) for each simulated endpoint, keyed by `{session_id}:{hostname}`

**Impact:** If PurpleLab restarts, all endpoints reset to their initial state (typically `ONLINE`). Any isolation or containment actions taken before the restart are lost.

### EDR State Machine States and Transitions

```
ONLINE → AT_RISK         (via anomaly_detected: T1059, T1078, T1021, T1105, T1547)
AT_RISK → COMPROMISED    (via confirmed_detection: T1003, T1055, T1041, T1486)
AT_RISK → ONLINE         (via false_positive)
COMPROMISED → ISOLATED   (via isolation_requested)
ISOLATED → REMEDIATED    (via remediation_complete)
REMEDIATED → ONLINE      (via reimaged)
ONLINE ↔ OFFLINE         (via offline_event / checkin_received)
```

**High-fidelity sources** (`crowdstrike`, `edr`, `crowdstrike_edr`) always fire `confirmed_detection` regardless of technique ID, transitioning directly to `COMPROMISED`.

**Secondary events on transition:**
- EDR alert event is always generated on any state-changing trigger
- Windows EventLog event is generated only at `COMPROMISED` and `ISOLATED` transitions
- Auto-isolation event is generated only at `ISOLATED` transition

**Benign events** (`_benign=True`) and **state transition records** (`_state_transition=True`) do not generate secondary events and do not trigger state machine transitions.

---

## 6. Database Migrations

PurpleLab uses Alembic for database schema migrations.

### Running Migrations

```bash
alembic upgrade head
```

Run this inside the PurpleLab backend container:

```bash
docker exec -it <purplelab_backend_container> alembic upgrade head
```

### Migration Files

Migration files are located in `alembic/versions/`. Each migration file has:
- `revision` — unique identifier for this migration
- `down_revision` — identifier of the preceding migration
- `upgrade()` — SQL changes to apply
- `downgrade()` — SQL changes to reverse

### Checking Current Schema Version

```bash
alembic current
```

### Rolling Back

```bash
alembic downgrade -1
```

Rolls back one migration. Be careful with rollbacks that drop tables — they are destructive.

### Migration After Code Update

After pulling a new PurpleLab version that includes new migration files, always run `alembic upgrade head` before starting the application. Failure to do so will result in 500 errors when endpoints access new schema elements.

---

## 7. Log Sources and Monitoring

### Checking Backend Logs

```bash
docker logs <purplelab_backend_container> --tail 100
```

Key log patterns to monitor:

**Session event generation:**
```
INFO: Session {session_id}: generated event {event_id} (technique {tech_id})
```

**Generator failure:**
```
ERROR: Session {session_id}: failed to generate event: {error_message}
```
A high rate of these indicates a misconfigured simulation mode or a problem with the event template library.

**Joti push failure (non-fatal):**
```
DEBUG: Failed to push simulation result to Joti: {error}
```
This is debug-level — increase log verbosity to see it if needed.

**EDR state transition:**
```
INFO: EDR state: {hostname} {old_state} -> {new_state} (trigger: {trigger})
```

### Monitoring Session Health

A healthy running session shows:
- `events_sent` increasing every few seconds
- `errors` stable at 0 or very low
- `last_event_at` updated recently

A stuck session shows:
- `events_sent` not increasing
- `last_event_at` stale by more than 30 seconds
- Backend logs may show repeated errors for the session

### Celery Worker Monitoring

Use case runs depend on Celery. To verify the Celery worker is processing tasks:

```bash
docker logs <celery_worker_container> --tail 50
```

Look for task receipt and completion entries. If use case runs are stuck in `pending` status, the Celery worker is likely down or not connected to Redis.

---

## 8. Joti Audit Event Forwarding

### Overview

This integration flows in the opposite direction from simulation result push. Joti sends its audit log events to PurpleLab, allowing PurpleLab to correlate analyst actions with simulation activity.

### Configuration in Joti

In the Joti Admin panel, navigate to Audit Logs > SIEM Forwarding. Create a new forwarder with:
- **Target Type:** `purplelab`
- **Endpoint URL:** `http://<purplelab_host>:8002`
- **Webhook Token:** a shared secret for request authentication

Joti will forward audit events every 60 seconds to:
```
POST {endpoint_url}/api/v2/joti/audit-events
X-Joti-Token: {webhook_token}
```

### Event Storage

Each received event batch is processed and stored as individual `JotiAuditEvent` records in the PurpleLab database. Fields stored:

| Field | Source |
|-------|--------|
| `joti_event_id` | Joti's internal event ID |
| `event_type` | Type of event (auth, access, admin, etc.) |
| `action` | Specific action (login, logout, view, create, etc.) |
| `user_email` | Email of the user who performed the action |
| `ip_address` | IP address of the request |
| `resource_type` | Type of resource acted upon |
| `resource_id` | ID of the specific resource |
| `correlation_id` | Joti correlation ID for tracing |
| `details` | JSONB with full event details |
| `created_at_joti` | Timestamp from Joti when the event occurred |
| `received_at` | PurpleLab timestamp when the batch was received |

### Special Event Handling

When Joti forwards audit events with `event_type=HUNT_TRIGGER` or `event_type=EXTRACTION`, PurpleLab automatically creates corresponding `UseCaseRun` records, linking the Joti analyst activity to PurpleLab simulation runs.

### Empty Batches

An empty `{"events": []}` batch is valid and results in a 200 response with no database writes. This is normal behavior if Joti has no new events since the last forwarding cycle.

---

## 9. Troubleshooting

### EDR State Machine Not Transitioning

**Symptom:** Events are generating but the EDR state (visible via CrowdStrike, Defender, or XSIAM endpoints) is not changing.

**Cause:** The event generator may not be targeting the correct hostname, or the technique ID does not match any state machine trigger.

**Check:**
1. Examine the generated event payload. Is `hostname` or `ComputerName` populated? The state machine keys on hostname — events without a hostname do not trigger state transitions.
2. Check that the technique ID in the event is one of the trigger techniques. For `anomaly_detected`: T1059, T1078, T1021, T1105, T1547. For `confirmed_detection`: T1003, T1055, T1041, T1486.
3. Check if the source is a high-fidelity source (`crowdstrike`, `edr`, `crowdstrike_edr`) — these always trigger `confirmed_detection`.

---

### Splunk Search Returns Empty Results

**Symptom:** SPL search returns no events even though the session has generated events.

**Cause A:** Missing or wrong `session_id` parameter.
**Fix:** Ensure `?session_id={session_id}` is appended to the search request. Without this parameter, the emulation returns an empty result set by design.

**Cause B:** The `sourcetype` filter does not match any `product_type` in the session events.
**Fix:** Verify the event `product_type` values by checking `GET /api/v2/sessions/{id}/stats` → `by_source`. Use those exact values in the `sourcetype=` filter.

**Cause C:** PurpleLab was restarted after the search job was created.
**Fix:** Re-submit the search. The `_jobs` dict is in-memory and is cleared on restart.

---

### CrowdStrike Token Rejected

**Symptom:** API calls return 401 Unauthorized after authenticating.

**Cause A:** The `Authorization` header is missing or malformed on subsequent requests.
**Fix:** Ensure every request includes `Authorization: Bearer {token}` where `{token}` is the value returned by the OAuth2 endpoint (format: `"cs-sim-token-" + uuid`).

**Cause B:** PurpleLab was restarted. The fake token may have been regenerated.
**Fix:** Re-authenticate to get a fresh fake token.

---

### ITDR Simulate Does Nothing

**Symptom:** POST to ITDR simulate returns 200 but no events appear in the session.

**Cause:** `dry_run` defaults to `true`. When `dry_run=true`, no state changes occur and no events are generated — the endpoint only previews the action.

**Fix:** Explicitly pass `"dry_run": false` in the request body to actually generate events.

---

### Use Case Run Stuck in Pending

**Symptom:** `POST /use-cases/{id}/run` returns immediately and a `UseCaseRun` record with `status=pending` is created, but the status never advances to `running`, `passed`, or `failed`.

**Cause:** The Celery worker is not running or not connected to Redis.

**Fix:**
1. Check the Celery worker container: `docker logs <celery_container> --tail 50`
2. Verify Redis is running and accessible from the Celery worker container
3. Verify `REDIS_URL` is correctly set in the Celery worker's environment
4. Restart the Celery worker container: `docker restart <celery_container>`

---

### Joti Push Not Appearing in Joti

**Symptom:** Sessions stop successfully but no simulation results appear in Joti.

**Cause A:** `JOTI_BASE_URL` or `JOTI_API_KEY` is not set (or is an empty string).
**Fix:** Verify both variables are set and non-empty. Restart PurpleLab after setting them.

**Cause B:** The Joti instance is unreachable from PurpleLab's network.
**Fix:** Test network connectivity: `curl -X POST {JOTI_BASE_URL}/api/v2/simulations -H "Authorization: Bearer {JOTI_API_KEY}"` from inside the PurpleLab container. Check DNS and firewall rules.

**Note:** Joti push failures are logged at `DEBUG` level. To see them, increase the log level temporarily.

---

### XSIAM get_query_results Returns 404

**Symptom:** Fetching XQL results returns 404 or empty with a known job ID.

**Cause A:** PurpleLab was restarted. The `_xql_jobs` dict is in-memory and cleared on restart.
**Fix:** Re-submit the XQL query.

**Cause B:** Wrong parameter name. XSIAM accepts both `query_id` and `execution_id` — verify you are using one of these two names.

---

*End of PurpleLab User and Admin Guide*

*For additional assistance, check the PurpleLab test case document (`PURPLELAB_TEST_CASES.md`) for expected API behaviors, or examine backend logs for detailed error information.*
