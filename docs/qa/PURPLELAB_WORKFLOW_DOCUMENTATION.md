# PurpleLab Workflow Documentation

**Version:** 1.0 | **Date:** 2026-07-26

This document describes every major operational workflow in PurpleLab. Each section includes prerequisites, the trigger that initiates the workflow, a step-by-step flow, expected response shapes, and documented failure modes. All details are derived directly from the production codebase in `c:\Projects\purplelab\backend`.

---

## 1. Session Creation

### 1.1 Prerequisites

- PurpleLab backend running and connected to PostgreSQL on port 5434.
- If using `simulation_mode="mcp_ingest"`, an external MCP server must be accessible at the URL that will be provided in the request.
- If using `simulation_mode="threat_actor"`, the threat actor ID must be a valid entry in PurpleLab's threat actor catalogue.

### 1.2 Trigger

An analyst or Joti connector sends `POST /api/v2/sessions` with a JSON body describing the desired simulation.

### 1.3 Simulation Modes

**`attack_chain` (default)**
Uses named attack chain IDs from the product catalogue. The `attack_chains` list in the request body specifies which pre-defined multi-stage attack sequences to execute. The engine will generate events following the sequence defined by each chain.

**`threat_actor`**
Simulates the known TTPs of a named threat actor. Requires `threat_actor_id` (or `threat_actor_name`) and optionally `threat_actor_ttps` (list of technique IDs to override the catalogue defaults). If `threat_actor_ttps` is empty, the engine uses the full known TTP set for that actor.

**`ttps`**
Direct TTP specification. Requires `technique_ids` (list of MITRE ATT&CK technique IDs, e.g., `["T1059.001", "T1003.001", "T1486"]`). The engine generates events for each technique in the list. This is the most commonly used mode for targeted detection validation.

**`mcp_ingest`**
Retrieves events from an external MCP (Model Context Protocol) server before starting generation. Requires `mcp_server_url`, and optionally `mcp_api_key`, `mcp_tool` (default: `siem_search_events`), and `mcp_query`. The session is created in `stopped` status. The caller must then invoke `POST /sessions/{id}/resolve-mcp` to populate technique IDs from the MCP server before starting the session.

### 1.4 Step-by-Step Flow

1. Client sends `POST /api/v2/sessions` with `SessionCreateRequest` body.
2. If `name` is blank or equals `"Untitled Session"`, the API auto-generates a name from the current UTC timestamp and the simulation mode label: `"TTP Simulation — 2026-07-26 10:00"`.
3. The API builds a `merged_config` dict by combining the explicit `config` field from the request body with the structured simulation params (`simulation_mode`, `attack_chains`, `event_count`, `technique_ids`, etc.). Mode-specific fields are only added when their values are non-null.
4. A `SimulationSession` row is inserted into PostgreSQL with `status="stopped"`, `events_sent=0`, `errors=0`. The `config` column stores the `merged_config` as JSONB.
5. If `auto_start=True`, the API immediately updates `status="running"` and calls `session_manager.start_session(session_id, merged_config)`. If the session manager raises an exception, the session remains in `status="running"` in the DB but the engine scheduler may not have started.
6. The API returns the serialized session dict.

### 1.5 Request Body Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `"Untitled Session"` | Human-readable name; auto-generated if blank |
| `config` | dict | `{}` | Extra key-value config merged into JSONB |
| `simulation_mode` | string | `"attack_chain"` | One of: attack_chain, threat_actor, ttps, mcp_ingest |
| `attack_chains` | list[str] | `[]` | Named attack chain IDs for attack_chain mode |
| `event_count` | int | `200` | Total events to generate; range 10–2000 |
| `threat_actor_id` | string | null | Actor ID for threat_actor mode |
| `threat_actor_name` | string | null | Actor name (stored in config) |
| `threat_actor_ttps` | list[str] | `[]` | Override TTP list for threat_actor mode |
| `technique_ids` | list[str] | `[]` | MITRE technique IDs for ttps mode |
| `mcp_server_url` | string | null | External MCP server base URL for mcp_ingest mode |
| `mcp_api_key` | string | null | Optional API key for MCP server (header: X-API-Key) |
| `mcp_tool` | string | `"siem_search_events"` | MCP tool name; also accepted: siem_get_alerts, edr_get_detections |
| `mcp_query` | string | null | Query string passed to the MCP tool |
| `environment_id` | string | null | Optional environment template ID |
| `auto_start` | bool | `false` | Start event generation immediately after creation |

### 1.6 Expected Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "TTP Simulation — 2026-07-26 10:00",
  "status": "stopped",
  "events_sent": 0,
  "errors": 0,
  "config": {
    "simulation_mode": "ttps",
    "technique_ids": ["T1059.001", "T1003.001"],
    "event_count": 200
  },
  "created_at": "2026-07-26T10:00:00.000Z",
  "updated_at": "2026-07-26T10:00:00.000Z"
}
```

### 1.7 Failure Modes

- **DB unavailable:** `POST /sessions` returns 500. No session is created.
- **`auto_start=True` + session manager error:** Session is created and marked `status="running"` in the DB, but event generation does not start. No error is returned to the caller. The session can be stopped and restarted.
- **`mcp_ingest` mode + no `mcp_server_url`:** Session is created successfully but `POST /sessions/{id}/resolve-mcp` will return 400 (`"Session has no mcp_server_url configured."`).
- **`event_count` out of range:** FastAPI returns 422 Unprocessable Entity with Pydantic validation error detail.

---

## 2. Session Start and Stop

### 2.1 Prerequisites

- A session must exist in the DB with the target `session_id`.
- For `start`: session must not already have `status="running"`.

### 2.2 Trigger

- Start: `POST /api/v2/sessions/{session_id}/start`
- Stop: `POST /api/v2/sessions/{session_id}/stop`

### 2.3 Start Flow

1. API fetches the session via `_get_or_404(session_id)`. Returns 404 if not found.
2. If `session.status == "running"`, returns immediately with `{"status": "already_running", "id": session_id}`. No duplicate start.
3. Issues a `UPDATE simulation_sessions SET status='running', updated_at=now()` via async SQLAlchemy.
4. Calls `session_manager.start_session(session_id, session.config)` which:
   - Loads the session into the in-memory write-through cache.
   - Initializes the EDR state machine via `get_machine(session_id)` which creates a fresh `EndpointStateMachine` for this session.
   - Begins scheduling event generation ticks.
5. If `start_session` raises an exception, the exception is caught with a bare `except Exception: pass` — the session DB record stays at `running` but the scheduler may not be active.

### 2.4 Stop Flow

`_do_stop(session_id)` is called internally:

1. Issues `UPDATE simulation_sessions SET status='stopped', stopped_at=now(), updated_at=now()`.
2. Calls `drop_machine(session_id)` on the EDR state machine registry, removing the in-memory `EndpointStateMachine` for this session.
3. Collects `technique_ids` and `events_sent` from the session config and DB row.
4. Calls `joti_client.push_simulation_result({session_name, technique_ids, events_generated, summary})`.
5. **Joti push failure is non-fatal:** any exception from `push_simulation_result()` is caught and logged at debug level. The stop operation completes regardless.
6. Returns `{"status": "stopped", "id": session_id}`.

### 2.5 Joti Push Payload

```json
{
  "session_name": "TTP Simulation — 2026-07-26 10:00",
  "technique_ids": ["T1059.001", "T1003.001"],
  "events_generated": 187,
  "summary": "Simulation completed: 187 events across 2 techniques"
}
```

### 2.6 Failure Modes

- **Session not found:** 404 with `"Session '{id}' not found."`.
- **Stop on already-stopped session:** Returns 200 with `{"status": "stopped"}`. The `_do_stop` function is idempotent.
- **Joti unreachable:** Stop succeeds. Joti push failure is silent at the API level. Logged as `DEBUG joti.client: push_simulation_result failed: ...`.
- **Session manager scheduler exception during start:** Session marked running in DB; no events generated. Can be diagnosed via `GET /sessions/{id}/stats` showing `total_events: 0` after several seconds.

---

## 3. Event Generation and SSE Streaming

### 3.1 Prerequisites

- A session must be in `status="running"`.
- The SSE endpoint is a long-lived HTTP connection; the caller must support Server-Sent Events (text/event-stream content type).

### 3.2 Trigger

- Streaming: `GET /api/v2/sessions/{session_id}/events/stream`
- Polling (paginated): `GET /api/v2/sessions/{session_id}/events?skip=0&limit=50&severity=high`

### 3.3 SSE Streaming Flow

The SSE endpoint uses a `StreamingResponse` with an `async def event_generator()` coroutine.

1. Client connects to `GET /sessions/{id}/events/stream`. Optional `?since_id={event_uuid}` sets the starting cursor.
2. Every 1.5 seconds (`asyncio.sleep(1.5)`), the generator opens a new async DB session and queries:
   ```sql
   SELECT * FROM generated_events
   WHERE session_id = :session_id
     AND created_at > (SELECT created_at FROM generated_events WHERE id = :last_id)
   ORDER BY created_at ASC
   LIMIT 50
   ```
3. For each event returned, emits a SSE frame:
   ```
   data: {"id": "...", "source_type": "crowdstrike", "technique_id": "T1059.001", "severity": "high", "payload": {...}, "created_at": "2026-07-26T10:00:01.000Z"}

   ```
   Note the double newline terminating each frame.
4. `last_id` is updated to the UUID of the last event in the batch.
5. **Heartbeat:** Every 5 idle polls (no new events), emits:
   ```
   : heartbeat

   ```
   This is a comment-format SSE frame that keeps the connection alive through proxies.
6. **Done signal:** When `idle_count > 3` AND the session's `status != "running"`, emits:
   ```
   data: {"type": "done"}

   ```
   Then the generator returns, closing the SSE stream.

### 3.4 SSE Response Headers

```
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no
Connection: keep-alive
```

`X-Accel-Buffering: no` disables nginx proxy buffering, which would otherwise hold up frames until a buffer fills.

### 3.5 Paginated Event Polling

`GET /sessions/{id}/events` is a REST alternative to SSE for clients that cannot maintain a long-lived connection:

- `skip` and `limit` are offset-based pagination (default: 0 and 50, max 500).
- `severity` filter accepts `critical`, `high`, `medium`, `low`, `info`.
- Returns events in descending `created_at` order (most recent first).
- Response: `{"events": [...], "total": N, "skip": 0, "limit": 50}`.

### 3.6 Session Stats

`GET /sessions/{id}/stats` returns:

```json
{
  "session_id": "...",
  "total_events": 187,
  "by_severity": {"critical": 12, "high": 54, "medium": 88, "low": 33},
  "by_source": {"crowdstrike": 72, "windows_eventlog": 55, "okta": 40, "palo_alto": 20},
  "top_techniques": [
    {"technique_id": "T1059.001", "count": 45},
    {"technique_id": "T1003.001", "count": 38}
  ],
  "events_per_minute": 12.4
}
```

`events_per_minute` is computed as `total_events / elapsed_seconds * 60` where `elapsed_seconds = max(created_at) - min(created_at)` from the `generated_events` table.

### 3.7 Failure Modes

- **Session not found:** 404 on both SSE and polling endpoints.
- **Session stopped before SSE client connects:** Generator immediately queries DB, finds no events, increments `idle_count`, checks session status (`stopped`), emits `{"type": "done"}` after `idle_count > 3` cycles (approximately 6 seconds).
- **DB connection loss mid-stream:** The `async with async_session()` context manager raises an exception inside the generator. The `StreamingResponse` wrapper terminates the SSE connection. The client receives a truncated stream with no `done` signal.

---

## 4. Vendor API Simulation: Splunk

### 4.1 Prerequisites

- A simulation session must exist and have generated events (status can be running or stopped).
- The Joti CrowdStrike connector must be configured with the PurpleLab base URL as the Splunk API endpoint.

### 4.2 API Prefix

`/api/vendor/splunk` — all routes below are relative to this prefix.

### 4.3 Create a Search Job

**Trigger:** Joti (or any Splunk-compatible SOAR) calls `POST /services/search/jobs` with form-encoded body.

**Step-by-step:**
1. Parse `search` field from the form body. This is a SPL query string, e.g. `search sourcetype=crowdstrike ComputerName=WIN-VICTIM | stats count by technique_id`.
2. Parse optional `earliest_time`, `latest_time`, `max_count` from the form body.
3. Generate a `sid` (search ID) as a UUID-based string: `1722000000.{uuid_hex[:8]}`.
4. Store job metadata in the in-memory `_jobs` dict: `{sid: {status: "QUEUED", search, session_id, created_at}}`.
5. Immediately begin SPL execution asynchronously: filter `generated_events` by keywords extracted from the SPL string. If `sourcetype=X` is present, filter `product_type = X`. If `host=X` is present, filter payload JSON for matching hostname.
6. Store results in `_jobs[sid]["results"]` and set `_jobs[sid]["status"] = "DONE"`.
7. Return:
   ```json
   {"sid": "1722000000.abc12345"}
   ```

**Get Job Status:**
`GET /services/search/jobs/{sid}` returns:
```json
{
  "sid": "1722000000.abc12345",
  "entry": [{
    "content": {
      "dispatchState": "DONE",
      "resultCount": 45,
      "eventCount": 45,
      "runDuration": 0.12
    }
  }]
}
```

**Get Job Results:**
`GET /services/search/jobs/{sid}/results?count=100&output_mode=json` returns:
```json
{
  "results": [
    {"_time": "2026-07-26T10:00:01Z", "sourcetype": "crowdstrike", "technique_id": "T1059.001", ...},
    ...
  ],
  "preview": false,
  "fields": [{"name": "_time"}, {"name": "sourcetype"}, {"name": "technique_id"}]
}
```

### 4.4 Create Saved Search (Deploy Detection)

`POST /services/saved/searches` with form body `name=DetectionName&search=search sourcetype=edr...`:

1. Parses `name` and `search` from form body.
2. Extracts any MITRE technique IDs (`T\d{4}`) found in the search string.
3. Stores in `_saved_searches` dict keyed by name.
4. Optionally calls `execute_action("deploy_detection", {...})` to also persist a `DeployedDetection` row in the DB.
5. Returns: `{"name": "DetectionName", "search": "...", "created": true}`.

`GET /services/saved/searches` returns all saved searches for the current session.

### 4.5 Create Notable (Alert)

`POST /services/alerts/fired_alerts` injects an alert into the session:
- Body: `{"search_name": "DetectionName", "severity": "high", "notable_fields": {...}}`
- Calls `execute_action("inject_alert", {...})` which creates a `GeneratedEvent` row.

### 4.6 Server Info

`GET /services/server/info` always returns:
```json
{
  "entry": [{
    "content": {
      "version": "9.2.0",
      "build": "purplelab-sim",
      "serverName": "purplelab-splunk",
      "licenseState": "OK"
    }
  }]
}
```

### 4.7 Failure Modes

- **Unknown `sid` for job status or results:** 404 with `{"messages": [{"type": "FATAL", "text": "Unknown sid"}]}`.
- **Empty search string:** 400.
- **`_jobs` dict cleared on restart (RISK-002):** 404 on subsequent job polls. Joti must handle this gracefully.

---

## 5. Vendor API Simulation: CrowdStrike Falcon

### 5.1 Prerequisites

None beyond a running PurpleLab backend. CrowdStrike OAuth2 token endpoint never requires DB access.

### 5.2 API Prefix

`/api/vendor/crowdstrike` — all routes below are relative to this prefix.

### 5.3 OAuth2 Token

**Trigger:** Any Joti connector initialization.

`POST /oauth2/token` with form body `{client_id, client_secret, grant_type=client_credentials}`:

1. No credential validation. The endpoint always succeeds.
2. Returns:
   ```json
   {
     "access_token": "SIMULATED_TOKEN_550e8400",
     "token_type": "bearer",
     "expires_in": 1799
   }
   ```
3. No DB interaction. The token is a deterministic fake string.

### 5.4 List Devices

`GET /devices/v1?session_id={session_id}` — returns all endpoints known to the session's EDR state machine.

1. Calls `get_machine(session_id).snapshot()` to get `{hostname: state}` dict.
2. Maps each hostname to a CrowdStrike device resource object.
3. Returns:
   ```json
   {
     "resources": [
       {
         "device_id": "a1b2c3d4e5f6",
         "hostname": "WIN-VICTIM",
         "status": "normal",
         "containment_status": "normal",
         "local_ip": "10.0.0.101",
         "platform_name": "Windows",
         "os_version": "Windows 10 x64",
         "agent_version": "7.05.17503"
       }
     ],
     "meta": {"query_time": 0.001, "pagination": {"total": 1}}
   }
   ```
   Containment status maps: `ISOLATED → "contained"`, `COMPROMISED → "normal"`, all others → `"normal"`.

### 5.5 Isolate / Release Device

`POST /devices/actions/v2?action_name=contain` with body `{"ids": ["device_id"]}`:

1. Resolves the `device_id` to a hostname via the snapshot reverse map.
2. Calls `execute_action("isolate_host", {hostname, actor: "crowdstrike_soar", session_id})`.
3. Returns:
   ```json
   {"resources": ["device_id"], "meta": {"query_time": 0.023}}
   ```

`POST /devices/actions/v2?action_name=lift_containment` calls `execute_action("release_host", ...)`.

### 5.6 Detection Queries and Summaries

`GET /detects/queries/detects/v1` returns detection IDs derived from `generated_events` with `product_type IN ('crowdstrike', 'crowdstrike_edr')`.

`POST /detects/entities/summaries/GET` with body `{"ids": ["detect_id"]}` returns full detection details:
```json
{
  "resources": [
    {
      "detection_id": "ldt:a1b2c3:123456",
      "status": "new",
      "severity": 80,
      "technique": "T1059.001",
      "tactic": "Execution",
      "device": {"hostname": "WIN-VICTIM"},
      "timestamp": "2026-07-26T10:00:01Z"
    }
  ]
}
```

### 5.7 IOC Management

`POST /iocs/entities/iocs/v1` — add IOC to session blocklist. Internally calls `execute_action("block_ioc", {ioc_type, ioc_value})`.

`DELETE /iocs/entities/iocs/v1` — remove IOC. Calls `execute_action("unblock_ioc", {ioc_value})`.

### 5.8 Incidents

`GET /incidents/queries/incidents/v1` returns incident IDs for endpoints in `COMPROMISED` or `ISOLATED` state.

### 5.9 Failure Modes

- **`session_id` not provided or invalid UUID on `GET /devices/v1`:** Returns empty `resources` list. No error.
- **`device_id` not found in snapshot:** Isolation returns empty `resources` but HTTP 200.

---

## 6. Vendor API Simulation: XSIAM (Palo Alto)

### 6.1 Prerequisites

None beyond a running PurpleLab backend.

### 6.2 API Prefix

`/api/vendor/xsiam` — all routes below are relative to this prefix.

### 6.3 Authentication

`POST /public_api/v1/auth/get_token` — returns a fake token regardless of credentials:
```json
{"reply": {"token": "SIMULATED_XSIAM_TOKEN_abc123", "token_expiration": 3600}}
```

### 6.4 XQL Query — Async Job Pattern

**Start query:**
`POST /public_api/v1/xql/start_xql_query` with body `{"request_data": {"query": "dataset=xdr_data | filter technique_id = \"T1059.001\"", "timeframe": {"from": 0, "to": 1753910400}}}`:

1. Generates a `job_id` as a UUID string.
2. Stores the query and an empty results list in the in-memory `_xql_jobs` dict with key `{session_id}:{job_id}` to prevent cross-session collision (see RISK-009).
3. Executes the XQL query asynchronously by filtering `generated_events`.
4. Returns:
   ```json
   {"reply": {"job_id": "xql_job_abc123def456", "status": "PENDING"}}
   ```

**Get results:**
`POST /public_api/v1/xql/get_query_results` with body `{"request_data": {"job_id": "xql_job_abc123def456"}}`:
```json
{
  "reply": {
    "status": "SUCCESS",
    "number_of_results": 12,
    "results": {
      "data": [
        {"event_id": "...", "technique_id": "T1059.001", "severity": "high", ...}
      ]
    }
  }
}
```

**Quota:**
`POST /public_api/v1/xql/quota` returns simulated quota info:
```json
{"reply": {"quota": {"limit": 1000, "used": 0, "remaining": 1000}}}
```

### 6.5 Incidents and Alerts

`POST /public_api/v1/incidents/get_incidents` returns incidents from endpoints in `COMPROMISED` or `AT_RISK` state, formatted as XSIAM incident objects.

`POST /public_api/v1/alerts/get_alerts_multi_events` returns alert events from `generated_events` filtered to EDR/CrowdStrike source types.

### 6.6 Endpoint Actions

`POST /public_api/v1/endpoints/isolate` — calls `execute_action("isolate_host", ...)`.
`POST /public_api/v1/endpoints/unisolate` — calls `execute_action("release_host", ...)`.
`POST /public_api/v1/endpoints/scan` — returns a simulated scan task ID.
`POST /public_api/v1/scripts/run_script` — returns a simulated script execution ID.
`POST /public_api/v1/endpoints/quarantine_files` — calls `execute_action("quarantine_file", ...)`.
`POST /public_api/v1/endpoints/get_endpoint` — returns single endpoint detail from EDR state machine.

### 6.7 Indicator Management

`POST /public_api/v1/indicators/insert_jsons` — calls `execute_action("block_ioc", ...)` for each indicator.
`POST /public_api/v1/indicators/delete` — calls `execute_action("unblock_ioc", ...)`.

### 6.8 Incident Update

`POST /public_api/v1/incidents/update_incident` — updates incident fields in the in-memory incident registry.

### 6.9 Failure Modes

- **Unknown `job_id` in get_query_results:** Returns `{"reply": {"status": "FAILED", "error": "Unknown job_id"}}`.
- **Job ID collision (RISK-009):** Mitigated by `{session_id}:` prefix on job_id dict key.

---

## 7. Vendor API Simulation: Microsoft Defender

### 7.1 Prerequisites

None beyond a running PurpleLab backend.

### 7.2 API Prefix

`/api/vendor/defender` — all routes below are relative to this prefix.

### 7.3 Authentication

`POST /oauth2/v2.0/token` with form body `{client_id, client_secret, grant_type, scope}`:
```json
{
  "token_type": "Bearer",
  "expires_in": 3599,
  "access_token": "SIMULATED_DEFENDER_TOKEN_xyz789"
}
```

### 7.4 Machine List

`GET /api/machines?session_id={session_id}` returns all machines from the EDR state machine:

```json
{
  "value": [
    {
      "id": "f4c1234567890abcdef",
      "computerDnsName": "WIN-VICTIM",
      "lastIpAddress": "10.0.0.101",
      "healthStatus": "Active",
      "riskScore": "High",
      "isolationStatus": "None",
      "osPlatform": "Windows10",
      "version": "2009",
      "agentVersion": "10.7740.19041.1151"
    }
  ]
}
```

Machine `riskScore` is derived from EDR state: `COMPROMISED/ISOLATED → "High"`, `AT_RISK → "Medium"`, `ONLINE/REMEDIATED → "None"`.

### 7.5 Isolate / Unisolate Machine

`POST /api/machines/{machine_id}/isolate` with body `{"Comment": "Joti SOAR isolation", "IsolationType": "Full"}`:

1. Looks up `machine_id` in the EDR snapshot.
2. Calls `execute_action("isolate_host", {hostname, actor: "defender_soar", session_id})`.
3. Returns HTTP 202 with:
   ```json
   {
     "id": "action-uuid-xyz",
     "type": "Isolate",
     "status": "Pending",
     "machineId": "f4c1234567890abcdef"
   }
   ```

`POST /api/machines/{machine_id}/unisolate` calls `execute_action("release_host", ...)`.

### 7.6 Stop and Quarantine File

`POST /api/machines/{machine_id}/stopAndQuarantineFile` with body `{"Comment": "...", "Sha1": "..."}`:

1. Calls `execute_action("quarantine_file", {sha256: sha1, hostname})`.
2. Returns 202 with action status.

### 7.7 Indicator Management

`POST /api/indicators` with body `{"indicatorValue": "192.168.1.1", "indicatorType": "IpAddress", "action": "Block", ...}`:

1. Maps Defender `action=Block` → `execute_action("block_ioc", {ioc_value, ioc_type})`.
2. Returns the indicator object with a generated `id`.

`GET /api/indicators` returns all IOCs currently blocked in the session firewall state machine.

### 7.8 Alerts

`GET /api/alerts` returns alerts from `generated_events` where `product_type` is `crowdstrike` or `edr`, formatted as Defender alert objects with `severity`, `status: "New"`, `category`, and `detectionSource: "CustomDetection"`.

### 7.9 Failure Modes

- **Unknown `machine_id`:** Isolation returns 400 with `{"error": {"code": "NotFound", "message": "Machine not found"}}`.
- **EDR state machine not initialized for session:** Returns empty machine list rather than 500.

---

## 8. SOAR Action Execution

### 8.1 Prerequisites

- A simulation session must be running or have been run (so an EDR state machine snapshot exists for it in memory).
- For identity actions: the session must have generated identity-related events so that simulated user objects exist.
- `session_id` must be passed to the action executor — it is the primary key for all state machine lookups.

### 8.2 Trigger

Actions are dispatched by:
- Vendor API endpoints (CrowdStrike `/devices/actions/v2`, Defender `/machines/{id}/isolate`, XSIAM `/endpoints/isolate`)
- The use case identity simulation endpoint (`POST /use-cases/{id}/simulate-identity`)
- Direct calls from the pipeline or AI engine

All routes ultimately call `await execute_action(session_id, action_type, params)` from `backend/engine/action_executor.py`.

### 8.3 Supported Actions and Their Mechanics

**`isolate_host`**
- Required params: `hostname`
- Gets `get_machine(session_id)`, reads `state_before`, sets state to `ISOLATED`.
- Generates a CrowdStrike-format confirmation event in `generated_events`.
- Returns `ActionResult{success=True, state_before, state_after="isolated"}`.

**`release_host`**
- Required params: `hostname`
- Sets state to `REMEDIATED`.
- Generates CrowdStrike confirmation event.
- Returns `ActionResult{success=True, state_before, state_after="remediated"}`.

**`disable_account`**
- Required params: `username`
- Gets `get_bundle(session_id).identity`, sets `IdentityState.DISABLED` on the username.
- Generates Okta-format `user.lifecycle.deactivate` event.

**`enable_account`**
- Required params: `username`
- Sets `IdentityState.REMEDIATED`.
- Generates Okta `user.lifecycle.activate` event.

**`reset_password`**
- Required params: `username`
- Generates a random `reset_token` (UUID hex, 32 chars). Returns truncated first 8 chars in `details.reset_token`.
- Generates Okta `user.account.reset_password` event.

**`block_ioc`**
- Required params: `ioc_type` (ip/ipv4/ipv6/domain/hash), `ioc_value`
- For IP types: calls `get_bundle(session_id).firewall.set_state(ioc_value, FirewallState.BLOCKED)`.
- Generates firewall or EDR block event.

**`unblock_ioc`**
- Required params: `ioc_value`, `ioc_type`
- For IP types: sets `FirewallState.ALLOWED`.
- Generates firewall unblock event.

**`kill_process`**
- Required params: `process_name`, `hostname`
- Optional: `pid`
- Generates EDR process termination event.
- Marks matching nodes in the session's `ThreatGraph` as `terminated=True`.

**`quarantine_file`**
- Required params: `sha256` (or `hash`), `hostname`
- Generates EDR quarantine event with truncated hash in title.
- Returns `details.sha256` with full hash.

**`deploy_detection`**
- Required params: `name`
- Optional: `sigma_yaml`, `query_spl`, `technique_ids`
- Inserts a `DeployedDetection` row in the DB with `status="deployed"`, `deployed_by=actor`.
- Does not generate a `GeneratedEvent` — this is a persistent configuration action.

**`inject_alert`**
- Required params: `title`
- Optional: `severity` (default: `medium`), `technique_id`, `source_type`
- Generates a synthetic `GeneratedEvent` row. Useful for testing detection rules against a specific alert shape.

### 8.4 ActionResult Model

Every action returns an `ActionResult`:

```json
{
  "success": true,
  "action_type": "isolate_host",
  "target": "WIN-VICTIM",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "WIN-VICTIM isolated successfully",
  "state_before": "compromised",
  "state_after": "isolated",
  "event_ids": ["a1b2c3d4-..."],
  "timestamp": "2026-07-26T10:05:00.000Z",
  "details": {}
}
```

### 8.5 Audit Record Persistence

Every action dispatched through `execute_action()` persists a row to `response_actions` via raw SQL INSERT:

```sql
INSERT INTO response_actions
  (id, session_id, action_type, actor, target, params, result, persona_key, created_at)
VALUES
  (gen_random_uuid(), :session_id, :action_type, :actor, :target,
   CAST(:params AS JSONB), CAST(:result AS JSONB), :persona_key, now())
```

The `params` column contains the action parameters with the `actor` field stripped. The `result` column contains the full serialized `ActionResult`.

### 8.6 Failure Modes

- **Unknown `action_type`:** Returns `ActionResult{success=False, message="Unknown action type: X"}`. No DB write.
- **Exception in handler:** Caught by the outer try/except in `execute_action`. Returns `ActionResult{success=False, message="Action failed: {exc}"}`. DB persist is also skipped for the result (the persist itself is in a separate try/except).
- **`_persist_action` DB failure:** Silently caught. The action result is still returned to the caller. Audit trail is lost for this action.

---

## 9. Use Case Validation

### 9.1 Prerequisites

- Use case must exist in the DB (`use_cases` table).
- For `simulate-identity`: use case must have `"identity"` in its `tags` list.
- Celery worker must be running for async runs.

### 9.2 Trigger

- Manual single run: `POST /use-cases/{id}/run`
- Bulk run: `POST /use-cases/run-all`
- Webhook-triggered: Joti POSTs to `/joti/webhook/alerts`
- Pipeline/scheduled: Internal Celery task

### 9.3 Run Lifecycle

1. **`POST /use-cases/{id}/run`** verifies the use case exists in DB.
2. Creates a `UseCaseRun` row: `status="pending"`, `triggered_by=body.triggered_by` (default: `"manual"`).
3. Returns immediately with `{run_id, use_case_id, status: "queued", task_id}`.
4. The Celery task `run_use_case_task` picks up the job asynchronously.
5. The task:
   - Creates a simulation session from the use case's `technique_ids`.
   - Generates events.
   - Tests Sigma rules and SIEM queries against the generated events.
   - Updates the `UseCaseRun` to a terminal status: `passed`, `failed`, `partial`, or `error`.
   - Sets `completed_at`, `events_generated`, `rules_tested`, `rules_fired`, `pass_rate`.
6. `UseCase.last_validated_at` is updated to the current timestamp.

### 9.4 Run History

`GET /use-cases/{id}/runs?limit=20` returns:

```json
{
  "runs": [
    {
      "id": "run-uuid",
      "use_case_id": "uc-uuid",
      "status": "passed",
      "triggered_by": "manual",
      "events_generated": 45,
      "rules_tested": 3,
      "rules_fired": 3,
      "pass_rate": 1.0,
      "started_at": "2026-07-26T10:00:00Z",
      "completed_at": "2026-07-26T10:00:42Z",
      "error_message": null
    }
  ],
  "total": 1
}
```

### 9.5 Coverage Summary

`GET /use-cases/coverage` returns per-tactic aggregate stats:

```json
{
  "by_tactic": {
    "execution": {"total": 5, "passing": 4, "failing": 1, "coverage_pct": 80.0},
    "credential_access": {"total": 3, "passing": 1, "failing": 2, "coverage_pct": 33.3},
    "lateral_movement": {"total": 2, "passing": 2, "failing": 0, "coverage_pct": 100.0}
  },
  "overall": {"total": 10, "passing": 7, "failing": 3, "coverage_pct": 70.0}
}
```

A use case is "passing" if its most recent `UseCaseRun` has `status="passed"`.

### 9.6 Failing Use Cases

`GET /use-cases/failing` returns use cases with no passing run or that have never been run:

```json
{
  "failing": [
    {"id": "uc-uuid", "name": "DCSync Detection", "technique_ids": ["T1003.006"], "last_run_status": "failed"},
    {"id": "uc-uuid2", "name": "Golden Ticket", "technique_ids": ["T1558.001"], "last_run_status": null}
  ],
  "total": 2
}
```

### 9.7 Failure Modes

- **Use case not found:** 404.
- **Celery worker unavailable:** `UseCaseRun` stays at `status="pending"`. Watchdog job (if implemented) flips to `error` after timeout.
- **Celery task exception:** Task marks the run as `status="error"` with `error_message` set to the exception string.
- **`POST /use-cases/run-all` with no active use cases:** Returns `{status: "queued", task_id, message: "Validation for all active use cases has been queued"}` but the Celery task completes immediately with 0 runs created.

---

## 10. Identity Simulation

### 10.1 Prerequisites

- Use case must exist and have `"identity"` in its `tags` JSONB field.
- The identity action must be in the valid set.

### 10.2 Trigger

`POST /use-cases/{use_case_id}/simulate-identity` with body:

```json
{
  "action": "lock_user",
  "target_username": "jdoe@example.local",
  "reason": "purple_team_identity_simulation",
  "dry_run": false
}
```

### 10.3 Valid Actions

| Action | Effect |
|--------|--------|
| `lock_user` | Locks user account (equivalent to AD account lockout) |
| `unlock_user` | Unlocks a locked account |
| `disable_user` | Disables user account (equivalent to AD disabled flag) |
| `enable_user` | Re-enables a disabled account |
| `revoke_sessions` | Terminates all active sessions for the user |
| `force_mfa` | Triggers MFA re-enrollment for the user |
| `force_pw_reset` | Forces a password reset on next login |

### 10.4 Step-by-Step Flow

1. API verifies the use case exists via DB lookup.
2. Checks `"identity" in uc.tags`; if not, returns 400: `"Use case is not tagged as an identity scenario"`.
3. Validates `body.action` against `valid_actions`. If invalid, returns 400 with the sorted list of valid actions.
4. If `target_username` is None, a random `SimulatedUser` from the session's identity pool is selected automatically (auto-seed).
5. Dispatches the action to the identity simulation module.
6. Writes a `ContainmentAction` row: `{action_type=body.action, target_type="user", target_value=username, status="success"|"failed"}`.
7. Returns:
   ```json
   {
     "use_case_id": "uc-uuid",
     "action": "lock_user",
     "target_username": "jdoe@example.local",
     "status": "success",
     "dry_run": false,
     "containment_action_id": "ca-uuid",
     "message": "User jdoe@example.local locked"
   }
   ```

### 10.5 Failure Modes

- **Use case not tagged `identity`:** 400 with explicit message.
- **Invalid action string:** 400 with sorted list of valid actions.
- **`target_username` not found and auto-seed fails:** Returns `status: "failed"` with message; still creates a `ContainmentAction` with `status="failed"`.
- **`dry_run=True`:** Returns the expected result shape but writes no DB rows.

---

## 11. ITDR Scenario Workflow

### 11.1 Prerequisites

- No DB state required for listing, detail, sigma, or hunt-query routes (all data is from the static `ITDR_SCENARIOS` catalogue in `backend/api/v2/itdr.py`).
- For `simulate` with `dry_run=False`: the Scenarios API (`POST /v2/scenarios`) must be able to create a session (DB must be available).

### 11.2 Trigger

Any client (analyst, Joti, or automated test) calls the ITDR endpoints.

### 11.3 List Scenarios

`GET /itdr/scenarios` returns summary cards for all 10 scenarios:

```json
[
  {"id": "kerberoasting", "name": "Kerberoasting", "technique_id": "T1558.003", "mitre_tactic": "Credential Access", "severity": "high", "platforms": ["windows", "active_directory"]},
  {"id": "pass_the_hash", "name": "Pass the Hash", "technique_id": "T1550.002", ...},
  ...
]
```

The full 10 scenario IDs are: `kerberoasting`, `pass_the_hash`, `golden_ticket`, `dcsync`, `mfa_fatigue`, `impossible_travel`, `password_spray`, `credential_stuffing`, `token_theft`, `privileged_account_creation`.

### 11.4 Get Scenario Detail

`GET /itdr/scenarios/{id}` returns the full scenario including:
- `id`, `name`, `technique_id`, `mitre_tactic`, `severity`, `description`, `platforms`, `prerequisites`
- `simulation_steps` — ordered list of `{step, action, command, tool, description, purplelab_atomic?}`
- `expected_logs` — `{source, event_id, description, key_fields}`
- `detection_sigma` — full Sigma YAML string
- `hunt_queries` — `{splunk_spl, sentinel_kql}`

### 11.5 Sigma Download

`GET /itdr/scenarios/{id}/sigma` returns the raw Sigma YAML string for the scenario's detection rule with `Content-Type: text/plain`. This is intended for direct import into a Sigma compilation toolchain.

### 11.6 Hunt Queries

`GET /itdr/scenarios/{id}/hunt-queries` returns:
```json
{
  "splunk_spl": "index=windows EventCode=4769 ServiceName!=krbtgt TicketEncryptionType=0x17 | stats count by AccountName, ServiceName | where count > 5",
  "sentinel_kql": "SecurityEvent | where EventID == 4769 and TicketEncryptionType == '0x17' and ServiceName != 'krbtgt' | summarize count() by AccountName, ServiceName | where count_ > 5"
}
```

### 11.7 Simulate (Dry Run, default)

`POST /itdr/scenarios/{id}/simulate` with body `{"dry_run": true}` (default):

1. Looks up scenario by `id` in `ITDR_SCENARIOS`. Returns 404 if not found.
2. Returns preview information: scenario steps, technique_id, expected log sources, sigma preview.
3. **No session is created. No DB writes.**
4. Response:
   ```json
   {
     "scenario_id": "kerberoasting",
     "dry_run": true,
     "technique_id": "T1558.003",
     "steps": [...],
     "expected_events": 15,
     "sigma_preview": "title: Kerberoasting..."
   }
   ```

### 11.8 Simulate (Live Dispatch, dry_run=False)

`POST /itdr/scenarios/{id}/simulate` with body `{"dry_run": false, "session_name": "Kerberoasting Test 1"}`:

1. Looks up scenario by `id`.
2. Calls `POST /v2/scenarios` internally to create a simulation session with `technique_ids: [scenario.technique_id]` and `simulation_mode: "ttps"`.
3. The created session is immediately started.
4. Creates a `UseCaseRun` row: `triggered_by="itdr_dispatch"`, `status="pending"`.
5. Returns:
   ```json
   {
     "scenario_id": "kerberoasting",
     "dry_run": false,
     "session_id": "550e8400-...",
     "run_id": "run-uuid-...",
     "status": "dispatched",
     "technique_id": "T1558.003"
   }
   ```

### 11.9 Failure Modes

- **Unknown scenario id:** 404 with `"Unknown ITDR scenario: {id}"`.
- **`dry_run=False` + DB unavailable:** 500. No session or run created.
- **`dry_run=False` + Scenarios API fails:** Returns 503 with the upstream error detail. The caller can retry.

---

## 12. Joti Audit Event Ingest

### 12.1 Prerequisites

- Joti platform must be configured with a SIEM Audit Forwarder with `target_type="purplelab"` pointing to `http://purplelab-backend:8002/joti/audit-events`.
- `JOTI_WEBHOOK_TOKEN` must be set identically in both Joti and PurpleLab environment configs.

### 12.2 Trigger

Joti's SIEM audit forwarder (which runs every 60 seconds and forwards all audit log rows with `id > last_forwarded_id`) sends `POST /joti/audit-events` with a batch of audit events.

### 12.3 Step-by-Step Flow

1. Request arrives at `POST /joti/audit-events` (router prefix: `/joti`).
2. `_verify_token(request)` reads `request.headers.get("X-Joti-Token")` and compares it to `settings.JOTI_WEBHOOK_TOKEN`. If missing or mismatched, returns 401.
3. Body is parsed as JSON. Accepted shapes:
   - A JSON array: each element is an audit event dict.
   - A JSON object with `"logs"` key: `body.get("logs", [])`.
   - A JSON object with `"event_type"` key: treated as a single event `[body]`.
4. For each audit event in the batch, a `JotiAuditEvent` row is inserted with:
   - `joti_event_id` = `event.get("joti_event_id")`
   - `event_type` = `event.get("event_type")`
   - `action` = `event.get("action")`
   - `user_email` = `event.get("user_email")`
   - `ip_address` = `event.get("ip_address")`
   - `resource_type` = `event.get("resource_type")`
   - `resource_id` = `event.get("resource_id")`
   - `correlation_id` = `event.get("correlation_id")`
   - `details` = `event.get("details", {})` (stored as JSONB)
   - `created_at_joti` = `event.get("created_at_joti")`
   - `received_at` = `datetime.utcnow()`
5. For events where `event_type IN ("HUNT_TRIGGER", "EXTRACTION")`, an additional `UseCaseRun` is created:
   - `triggered_by = "joti_audit_event"`
   - `status` derived from severity if available, otherwise `"partial"`
   - `run_details.joti_event_id` = the event's `joti_event_id`
6. Returns `{"accepted": N}` where N is the number of events successfully stored.

### 12.4 HUNT_TRIGGER and EXTRACTION Event Types

These two event types are treated specially because they represent Joti performing a hunt or IOC extraction that correlates with a PurpleLab simulation. By creating a `UseCaseRun` on receipt, PurpleLab can track whether Joti's detection rules fired in response to the simulation.

All other event types (e.g., `LOGIN`, `ARTICLE_READ`, `CASE_CREATED`, `PERMISSION_DENIED`) are stored in `joti_audit_events` for audit purposes but do not trigger any downstream action.

### 12.5 Joti Webhook: Alert Ingestion

`POST /joti/webhook/alerts` follows the same auth pattern (`X-Joti-Token`) and similarly auto-creates `UseCaseRun` records. The alert body is a list of alert dicts with `technique_id` and `severity` fields. Severity mapping: `critical/high → failed`, `medium → partial`, `low/info → passed`.

### 12.6 Expected Audit Event Payload

```json
[
  {
    "joti_event_id": "evt-00000123",
    "event_type": "HUNT_TRIGGER",
    "action": "create",
    "user_email": "analyst@example.local",
    "ip_address": "10.0.0.1",
    "resource_type": "hunt",
    "resource_id": "42",
    "correlation_id": "corr-abc123def456",
    "details": {"technique_id": "T1059.001", "hunt_id": 42, "session_id": "purplelab-session-uuid"},
    "created_at_joti": "2026-07-26T10:05:00Z"
  }
]
```

### 12.7 Failure Modes

- **Missing or wrong `X-Joti-Token`:** 401 Unauthorized. No DB writes.
- **Malformed JSON body:** 422 Unprocessable Entity. No DB writes.
- **Empty `logs` or `alerts` array:** Returns `{"accepted": 0}`. No error.
- **DB insert failure for a specific event:** That event's DB write is skipped; the batch continues. `accepted` count reflects only successful inserts.
- **`settings.JOTI_WEBHOOK_TOKEN` not set (empty string):** The `_verify_token` function skips validation when `expected` is empty. **This is a security misconfiguration.** Both tokens must be set in production.

---

## 13. Coverage Report

### 13.1 Prerequisites

- At least one `UseCase` row must exist in the DB.
- `UseCaseRun` rows must exist to compute pass/fail stats.

### 13.2 Trigger

`GET /api/v2/use-cases/coverage`

### 13.3 Coverage Summary Flow

1. The `UseCaseService.get_coverage_summary()` method queries all `UseCase` rows.
2. For each use case, fetches the most recent `UseCaseRun` (by `completed_at DESC`).
3. Groups use cases by `tactic`.
4. For each tactic group, computes:
   - `total` = number of use cases with this tactic
   - `passing` = number where most recent run has `status="passed"`
   - `failing` = `total - passing`
   - `coverage_pct` = `(passing / total) * 100` rounded to 1 decimal
5. Computes overall totals across all tactics.
6. Returns the dict described in section 9.5.

### 13.4 Failing Use Cases

`GET /api/v2/use-cases/failing` returns use cases in either of these conditions:
- Has never been run (no `UseCaseRun` rows with non-null `completed_at`).
- Most recent completed run has `status IN ("failed", "error")`.

This endpoint is the primary gap analysis tool: operators use it to identify detection blind spots and prioritize which use cases to run next.

### 13.5 Failure Modes

- **No use cases in DB:** Returns `{"by_tactic": {}, "overall": {"total": 0, "passing": 0, "failing": 0, "coverage_pct": 0.0}}`.
- **All use cases have never been run:** All appear in `GET /use-cases/failing`. Coverage returns 0% for all tactics.
- **DB unavailable:** 500 from the service layer.

---

## Appendix A: API Quick Reference

### Session Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /sessions | List sessions (paginated, filterable by status) |
| POST | /sessions | Create session |
| GET | /sessions/{id} | Get session with last 10 events |
| PUT | /sessions/{id} | Update name/config |
| PATCH | /sessions/{id}/rename | Quick rename |
| DELETE | /sessions/{id} | Delete session and all events |
| POST | /sessions/{id}/start | Start event generation |
| POST | /sessions/{id}/stop | Stop and trigger Joti push |
| POST | /sessions/{id}/resolve-mcp | Resolve MCP ingest source |
| GET | /sessions/{id}/events | Paginated events |
| GET | /sessions/{id}/events/stream | SSE event stream |
| GET | /sessions/{id}/stats | Severity/source/technique aggregates |

### Use Case Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /use-cases | List with filters (active_only, tactic, severity, tag, search) |
| POST | /use-cases | Create use case |
| GET | /use-cases/coverage | Per-tactic pass/fail stats |
| GET | /use-cases/failing | Use cases with no passing run |
| POST | /use-cases/run-all | Queue Celery bulk validation |
| GET | /use-cases/{id} | Single use case detail |
| PUT | /use-cases/{id} | Update use case |
| DELETE | /use-cases/{id} | Delete use case and all runs |
| POST | /use-cases/{id}/run | Queue single validation run |
| GET | /use-cases/{id}/runs | Run history |
| POST | /use-cases/{id}/simulate-identity | Identity containment action |

### ITDR Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /itdr/scenarios | List all 10 scenarios |
| GET | /itdr/scenarios/{id} | Full detail |
| GET | /itdr/scenarios/{id}/sigma | Sigma YAML download |
| GET | /itdr/scenarios/{id}/hunt-queries | SPL + KQL |
| POST | /itdr/scenarios/{id}/simulate | Dry run or live dispatch |

### Joti Integration Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /joti/webhook/alerts | Receive alert batches from Joti |
| POST | /joti/audit-events | Receive audit event stream |

---

## Appendix B: Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JOTI_BASE_URL` | For outbound push | Base URL of Joti platform API (e.g., `https://joti.example.com`) |
| `JOTI_API_KEY` | For outbound push | Bearer token for `push_simulation_result()` calls |
| `JOTI_WEBHOOK_TOKEN` | For inbound events | Shared secret validated in `X-Joti-Token` header |
| `DATABASE_URL` | Yes | `postgresql+asyncpg://user:pass@localhost:5434/purplelab` |
| `REDIS_URL` | Yes | `redis://localhost:6379/0` (Celery broker) |
