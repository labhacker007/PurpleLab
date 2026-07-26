# PurpleLab Architecture Diagrams

**Version:** 1.0 | **Date:** 2026-07-26

This document contains all architectural Mermaid diagrams for the PurpleLab platform. Every diagram is grounded in the actual source code and reflects the production codebase as of the date above.

---

## Diagram 1 — System Architecture Overview

Shows the full deployed topology: services, ports, and communication directions.

```mermaid
graph LR
    subgraph Client["Client Layer"]
        Browser["Browser / Analyst\nport 3000"]
        JotiPlatform["Joti TIP\nexternal"]
    end

    subgraph PurpleLab["PurpleLab Platform"]
        Frontend["Frontend\nNext.js / React\nport 3000"]
        Backend["Backend\nFastAPI\nport 8002 internal"]
        Redis["Redis\nTask broker\nport 6379"]
        Celery["Celery Worker\nuse_case_tasks"]
        DB["PostgreSQL 15\nport 5434\nschema: purplelab"]
    end

    subgraph ExternalMCP["External (optional)"]
        MCPServer["MCP Server\nJSON-RPC endpoint\ncustomer-supplied"]
    end

    Browser -->|"HTTP/SSE"| Frontend
    Frontend -->|"REST /api/v2/*"| Backend
    JotiPlatform -->|"POST /joti/audit-events\nPOST /joti/webhook/alerts\nX-Joti-Token auth"| Backend
    Backend -->|"Bearer token\nX-Source: purplelab\nPOST /api/v2/simulations"| JotiPlatform
    Backend -->|"async SQLAlchemy\nasyncpg"| DB
    Backend -->|"task.delay()"| Redis
    Redis -->|"task queue"| Celery
    Celery -->|"async SQLAlchemy"| DB
    Backend -->|"JSON-RPC tools/call\nmcp_ingest sessions only"| MCPServer
```

**Notes:**
- The backend runs on port 8002 inside Docker but is exposed via the frontend Next.js proxy.
- Redis serves both as Celery broker and as a potential cache layer for vendor API state.
- The Joti connection is bidirectional: Joti pushes audit events inbound; PurpleLab pushes simulation results outbound.
- MCP server communication is triggered only when `simulation_mode="mcp_ingest"` and `POST /sessions/{id}/resolve-mcp` is called.

---

## Diagram 2 — EDR State Machine

Exact states and trigger labels from `backend/engine/edr_state_machine.py`. Technique triggers are listed in the notes below the diagram.

```mermaid
stateDiagram-v2
    [*] --> ONLINE : default (no state set)

    ONLINE --> AT_RISK : anomaly_detected
    ONLINE --> OFFLINE : offline_event

    AT_RISK --> COMPROMISED : confirmed_detection
    AT_RISK --> ONLINE : false_positive

    COMPROMISED --> ISOLATED : isolation_requested

    ISOLATED --> REMEDIATED : remediation_complete

    REMEDIATED --> ONLINE : reimaged
    REMEDIATED --> ONLINE : reimaged_ok

    OFFLINE --> ONLINE : checkin_received
```

**Technique-to-Trigger Mapping (from `_TECHNIQUE_TRIGGERS`):**

| Technique | Trigger | Effect from ONLINE |
|-----------|---------|-------------------|
| T1059, T1059.001, T1059.003 | anomaly_detected | ONLINE → AT_RISK |
| T1078 | anomaly_detected | ONLINE → AT_RISK |
| T1021, T1021.001, T1021.002 | anomaly_detected | ONLINE → AT_RISK |
| T1105 | anomaly_detected | ONLINE → AT_RISK |
| T1547, T1547.001 | anomaly_detected | ONLINE → AT_RISK |
| T1053.005 | anomaly_detected | ONLINE → AT_RISK |
| T1003, T1003.001 | confirmed_detection | ONLINE → AT_RISK skipped; only fires from AT_RISK |
| T1055, T1055.001 | confirmed_detection | fires from AT_RISK → COMPROMISED |
| T1041 | confirmed_detection | fires from AT_RISK → COMPROMISED |
| T1486 (Ransomware) | confirmed_detection | fires from AT_RISK → COMPROMISED |

**High-fidelity source override:** Sources in `{"edr", "crowdstrike_edr", "crowdstrike"}` always emit `confirmed_detection` regardless of technique_id.

**Secondary events per transition:**

| New State | EDR Alert | Windows Event ID |
|-----------|-----------|-----------------|
| AT_RISK | Yes (medium) | 4719 |
| COMPROMISED | Yes (high) | 4688 |
| ISOLATED | Yes (high) + auto-isolation event | 7045 |
| REMEDIATED | Yes (info) | 1102 |

---

## Diagram 3 — Session Lifecycle Sequence

From session creation through start, event generation, stop, and Joti push. Based on `backend/api/v2/sessions.py` and `backend/engine/session_manager.py`.

```mermaid
sequenceDiagram
    participant Client
    participant SessionsAPI as Sessions API<br/>/api/v2/sessions
    participant SessionManager as SessionManager<br/>engine/session_manager.py
    participant DB as PostgreSQL<br/>simulation_sessions<br/>generated_events
    participant JotiClient as JotiClient<br/>joti/client.py

    Client->>SessionsAPI: POST /sessions<br/>{simulation_mode, technique_ids, event_count}
    SessionsAPI->>SessionsAPI: Build merged_config<br/>mode + chains + technique_ids
    SessionsAPI->>DB: INSERT simulation_sessions<br/>status="stopped"
    DB-->>SessionsAPI: session row with UUID id
    SessionsAPI-->>Client: {id, name, status="stopped", config}

    Note over Client,SessionsAPI: If auto_start=true, start is called inline.<br/>Otherwise client calls POST /start explicitly.

    Client->>SessionsAPI: POST /sessions/{id}/start
    SessionsAPI->>DB: UPDATE status="running"
    SessionsAPI->>SessionManager: start_session(session_id, config)
    SessionManager->>SessionManager: Load into in-memory cache<br/>Initialize EDR state machine via get_machine()
    SessionManager-->>SessionsAPI: (non-fatal if scheduler fails)
    SessionsAPI-->>Client: {status="started", id}

    loop Event Generation (every ~1-5s)
        SessionManager->>SessionManager: Generate events from TTP library<br/>Apply EDR state machine transitions
        SessionManager->>DB: INSERT generated_events<br/>(product_type, severity, title, payload)
        DB-->>SessionManager: saved event row
    end

    Client->>SessionsAPI: GET /sessions/{id}/events/stream (SSE)
    loop SSE Poll every 1.5s
        SessionsAPI->>DB: SELECT generated_events WHERE created_at > last_id
        DB-->>SessionsAPI: new event rows
        SessionsAPI-->>Client: data: {id, source_type, severity, payload}\n\n
        Note over SessionsAPI,Client: Heartbeat: ": heartbeat\n\n" every 5 idle polls<br/>Done: data: {"type":"done"}\n\n when status != running
    end

    Client->>SessionsAPI: POST /sessions/{id}/stop
    SessionsAPI->>DB: UPDATE status="stopped"<br/>SET stopped_at=now()
    SessionsAPI->>DB: SELECT technique_ids, events_sent from session
    SessionsAPI->>JotiClient: push_simulation_result({session_name, technique_ids, events_generated, summary})
    JotiClient->>JotiClient: POST /api/v2/simulations to Joti
    Note over JotiClient: Failure is non-fatal — caught and logged at debug level
    SessionsAPI-->>Client: {status="stopped", id}
```

---

## Diagram 4 — Vendor Simulation Flow: CrowdStrike Isolate

How a CrowdStrike isolation request flows from the Joti SOAR connector through the vendor API facade into the action executor and EDR state machine.

```mermaid
sequenceDiagram
    participant Joti as Joti SOAR Playbook<br/>(CrowdStrike connector)
    participant CrowdStrikeAPI as CrowdStrike Vendor API<br/>/api/vendor/crowdstrike
    participant ActionExecutor as Action Executor<br/>engine/action_executor.py
    participant EDR as EDR State Machine<br/>engine/edr_state_machine.py
    participant DB as PostgreSQL<br/>generated_events<br/>response_actions

    Joti->>CrowdStrikeAPI: POST /oauth2/token<br/>{client_id, client_secret}
    CrowdStrikeAPI-->>Joti: {access_token: "fake_token", token_type: "bearer", expires_in: 1799}
    Note over CrowdStrikeAPI: Always succeeds. No DB lookup. Fake token only.

    Joti->>CrowdStrikeAPI: GET /devices/v1<br/>Authorization: Bearer fake_token
    CrowdStrikeAPI->>EDR: get_machine(session_id).snapshot()
    EDR-->>CrowdStrikeAPI: {hostname: state, ...}
    CrowdStrikeAPI-->>Joti: {resources: [{device_id, hostname, status, ...}]}

    Joti->>CrowdStrikeAPI: POST /devices/actions/v2?action_name=contain<br/>{ids: [device_id]}
    CrowdStrikeAPI->>ActionExecutor: execute_action("isolate_host", {hostname, actor})
    ActionExecutor->>EDR: get_machine(session_id)
    EDR-->>ActionExecutor: machine for session
    ActionExecutor->>EDR: machine.set_state(hostname, ISOLATED)
    EDR-->>ActionExecutor: state updated
    ActionExecutor->>DB: INSERT generated_events (edr source, "Host isolation initiated", ISOLATED payload)
    DB-->>ActionExecutor: event_id
    ActionExecutor->>DB: INSERT response_actions (session_id, "isolate_host", actor, target, params, result)
    DB-->>ActionExecutor: row inserted
    ActionExecutor-->>CrowdStrikeAPI: ActionResult{success=true, state_before="compromised", state_after="isolated"}
    CrowdStrikeAPI-->>Joti: {resources: [device_id], meta: {query_time: ...}}
```

---

## Diagram 5 — Joti Integration: Bidirectional Data Flow

Inbound audit event stream from Joti's SIEM forwarder and outbound simulation result push.

```mermaid
sequenceDiagram
    participant JotiSIEM as Joti SIEM Audit Forwarder<br/>(target_type=purplelab)
    participant WebhookReceiver as Webhook Receiver<br/>joti/webhook.py
    participant DB as PostgreSQL<br/>joti_audit_events<br/>use_case_runs
    participant SessionsStop as Sessions API<br/>POST /sessions/{id}/stop
    participant JotiClient as JotiClient<br/>joti/client.py
    participant JotiAPI as Joti API<br/>POST /api/v2/simulations

    Note over JotiSIEM,DB: INBOUND: Audit events from Joti

    JotiSIEM->>WebhookReceiver: POST /joti/audit-events<br/>X-Joti-Token: {token}<br/>[{joti_event_id, event_type, action, user_email, ...}]
    WebhookReceiver->>WebhookReceiver: _verify_token(): compare X-Joti-Token header<br/>against settings.JOTI_WEBHOOK_TOKEN
    alt Token invalid
        WebhookReceiver-->>JotiSIEM: 401 Unauthorized
    end
    WebhookReceiver->>DB: INSERT joti_audit_events<br/>(joti_event_id, event_type, action, user_email,<br/>ip_address, resource_type, resource_id,<br/>correlation_id, details, created_at_joti, received_at)
    Note over WebhookReceiver,DB: HUNT_TRIGGER and EXTRACTION event_types<br/>additionally create UseCaseRun records<br/>triggered_by="joti_audit_event"
    WebhookReceiver-->>JotiSIEM: {accepted: N}

    Note over SessionsStop,JotiAPI: OUTBOUND: Simulation result on session stop

    SessionsStop->>JotiClient: push_simulation_result({<br/>  session_name,<br/>  technique_ids,<br/>  events_generated,<br/>  summary<br/>})
    JotiClient->>JotiAPI: POST /api/v2/simulations<br/>Authorization: Bearer {JOTI_API_KEY}<br/>X-Source: purplelab
    alt Joti reachable
        JotiAPI-->>JotiClient: 200 OK
        JotiClient-->>SessionsStop: True
    else Joti unreachable or error
        JotiClient-->>SessionsStop: False (exception caught, logged at debug)
    end
```

---

## Diagram 6 — ITDR Scenario Execution

From scenario listing through dry-run and live dispatch, based on `backend/api/v2/itdr.py`.

```mermaid
sequenceDiagram
    participant Client as Analyst / Joti
    participant ITDRRouter as ITDR Router<br/>/api/v2/itdr
    participant Catalogue as ITDR_SCENARIOS<br/>(in-memory list, 10 entries)
    participant ScenariosAPI as Scenarios API<br/>/api/v2/scenarios
    participant DB as PostgreSQL<br/>use_case_runs

    Client->>ITDRRouter: GET /itdr/scenarios
    ITDRRouter->>Catalogue: Read ITDR_SCENARIOS list
    Catalogue-->>ITDRRouter: 10 scenario dicts (id, name, technique_id, severity, ...)
    ITDRRouter-->>Client: [{id, name, technique_id, tactic, severity, description, platforms}, ...]

    Client->>ITDRRouter: GET /itdr/scenarios/kerberoasting
    ITDRRouter->>Catalogue: Find by id="kerberoasting"
    Catalogue-->>ITDRRouter: Full detail dict
    ITDRRouter-->>Client: {id, simulation_steps, expected_logs, detection_sigma, hunt_queries, ...}

    Client->>ITDRRouter: GET /itdr/scenarios/kerberoasting/sigma
    ITDRRouter-->>Client: detection_sigma YAML string (Content-Type: text/plain)

    Client->>ITDRRouter: GET /itdr/scenarios/kerberoasting/hunt-queries
    ITDRRouter-->>Client: {splunk_spl: "...", sentinel_kql: "..."}

    Note over Client,DB: Dry run (default): validate + return steps, no simulation created

    Client->>ITDRRouter: POST /itdr/scenarios/kerberoasting/simulate<br/>{dry_run: true}
    ITDRRouter->>Catalogue: Look up scenario by id
    Catalogue-->>ITDRRouter: scenario dict with technique_id=T1558.003
    ITDRRouter-->>Client: {scenario_id, dry_run: true, steps: [...], technique_id, sigma_preview}

    Note over Client,DB: Live dispatch (dry_run=false): creates real simulation session

    Client->>ITDRRouter: POST /itdr/scenarios/kerberoasting/simulate<br/>{dry_run: false, session_name: "Kerberoasting Test"}
    ITDRRouter->>ScenariosAPI: POST /v2/scenarios<br/>{name, technique_ids: ["T1558.003"], simulation_mode: "ttps"}
    ScenariosAPI->>DB: INSERT simulation_sessions
    DB-->>ScenariosAPI: session row
    ScenariosAPI-->>ITDRRouter: {session_id, status}
    ITDRRouter->>DB: INSERT use_case_runs<br/>(status="pending", triggered_by="itdr_dispatch")
    DB-->>ITDRRouter: run row
    ITDRRouter-->>Client: {scenario_id, session_id, run_id, status="dispatched"}
```

---

## Diagram 7 — Database Entity Relationship

Key tables and their relationships. Based on `backend/db/models.py`.

```mermaid
erDiagram
    simulation_sessions {
        UUID id PK
        VARCHAR name
        JSONB config
        VARCHAR status
        INT events_sent
        INT errors
        TIMESTAMP last_event_at
        TIMESTAMP stopped_at
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }

    generated_events {
        UUID id PK
        UUID session_id FK
        VARCHAR product_type
        VARCHAR severity
        VARCHAR title
        JSONB payload
        VARCHAR target_url
        INT status_code
        BOOL success
        TIMESTAMP created_at
    }

    use_cases {
        UUID id PK
        VARCHAR name
        TEXT description
        JSONB technique_ids
        VARCHAR tactic
        VARCHAR threat_actor
        VARCHAR severity
        JSONB tags
        BOOL is_active
        BOOL is_builtin
        TIMESTAMP last_validated_at
        JSONB sim_metadata
    }

    use_case_runs {
        UUID id PK
        UUID use_case_id FK
        VARCHAR status
        VARCHAR triggered_by
        INT events_generated
        INT rules_tested
        INT rules_fired
        FLOAT pass_rate
        JSONB run_details
        TEXT error_message
        TIMESTAMP started_at
        TIMESTAMP completed_at
    }

    joti_audit_events {
        UUID id PK
        VARCHAR joti_event_id
        VARCHAR event_type
        VARCHAR action
        VARCHAR user_email
        VARCHAR ip_address
        VARCHAR resource_type
        VARCHAR resource_id
        VARCHAR correlation_id
        JSONB details
        TIMESTAMP created_at_joti
        TIMESTAMP received_at
    }

    response_actions {
        UUID id PK
        UUID session_id FK
        VARCHAR action_type
        VARCHAR actor
        VARCHAR target
        JSONB params
        JSONB result
        VARCHAR persona_key
        TIMESTAMP created_at
    }

    deployed_detections {
        UUID id PK
        UUID session_id FK
        VARCHAR name
        TEXT sigma_yaml
        TEXT query_spl
        TEXT query_kql
        JSONB technique_ids
        VARCHAR status
        JSONB validation
        VARCHAR deployed_by
    }

    simulated_endpoints {
        INT id PK
        VARCHAR hostname
        VARCHAR ip_address
        VARCHAR os_platform
        VARCHAR edr_vendor
        VARCHAR status
    }

    containment_actions {
        UUID id PK
        VARCHAR action_type
        VARCHAR target_type
        VARCHAR target_value
        VARCHAR status
        TIMESTAMP created_at
    }

    simulation_sessions ||--o{ generated_events : "generates"
    simulation_sessions ||--o{ response_actions : "records"
    simulation_sessions ||--o{ deployed_detections : "deploys"
    use_cases ||--o{ use_case_runs : "has runs"
```

---

## Diagram 8 — API Surface Map

All route groups with their URL prefixes, grouped by domain. Based on `backend/api/v2/__init__.py` router registrations.

```mermaid
graph TD
    subgraph Root["/api/v2"]
        Sessions["Sessions\n/sessions\nGET, POST, PUT, PATCH, DELETE\n/start, /stop, /resolve-mcp\n/events, /events/stream, /stats"]
        UseCases["Use Cases\n/use-cases\nGET, POST, PUT, DELETE\n/coverage, /failing, /run-all\n/{id}/run, /{id}/runs\n/{id}/simulate-identity"]
        ITDR["ITDR\n/itdr\n/scenarios\n/scenarios/{id}\n/scenarios/{id}/sigma\n/scenarios/{id}/hunt-queries\n/scenarios/{id}/simulate"]
        Scenarios["Scenarios\n/scenarios\nGET, POST, PUT, DELETE\n/run, /results"]
        Pipeline["Pipeline\n/pipeline\nPOST /run\nGET /status/{id}"]
        Reports["Reports\n/reports\nGET, POST\n/export"]
        Rules["Rules\n/rules\nGET, POST, PUT, DELETE\n/validate, /test"]
        SigmaLib["Sigma Library\n/sigma-library\nGET, POST\n/search, /sync"]
        Dashboard["Dashboard\n/dashboard\nGET /summary, /kpis"]
        Scoring["Scoring\n/scoring\nGET /coverage\nPOST /evaluate"]
        Edr["EDR Simulation\n/edr\nGET /state, /events\nPOST /inject"]
        Identity["Identity Sim\n/identity-sim\nGET /users\nPOST /actions"]
        Knowledge["Knowledge\n/knowledge\nGET, POST, PUT, DELETE"]
        Admin["Admin\n/admin\nGET /stats, /config\nPOST /reset"]
    end

    subgraph VendorAPIs["Vendor API Facades (separate prefixes)"]
        Splunk["/api/vendor/splunk\nPOST /services/search/jobs\nGET /services/search/jobs/{sid}\nGET /services/search/jobs/{sid}/results\nPOST /services/saved/searches\nGET /services/saved/searches\nPOST /services/alerts/fired_alerts\nGET /services/server/info"]
        CrowdStrike["/api/vendor/crowdstrike\nPOST /oauth2/token\nGET /devices/v1\nPOST /devices/actions/v2\nGET /detects/queries/detects/v1\nPOST /detects/entities/summaries/GET\nPOST /iocs/entities/iocs/v1\nDELETE /iocs/entities/iocs/v1\nGET /incidents/queries/incidents/v1"]
        XSIAM["/api/vendor/xsiam\nPOST /public_api/v1/auth/get_token\nPOST .../xql/start_xql_query\nPOST .../xql/get_query_results\nPOST .../incidents/get_incidents\nPOST .../alerts/get_alerts_multi_events\nPOST .../endpoints/isolate\nPOST .../endpoints/unisolate\nPOST .../indicators/insert_jsons\nPOST .../endpoints/scan\nPOST .../scripts/run_script\nPOST .../endpoints/quarantine_files\nPOST .../incidents/update_incident\nPOST .../endpoints/get_endpoint"]
        Defender["/api/vendor/defender\nPOST /oauth2/v2.0/token\nGET /api/machines\nPOST /api/machines/{id}/isolate\nPOST /api/machines/{id}/unisolate\nPOST /api/machines/{id}/stopAndQuarantineFile\nPOST /api/indicators\nGET /api/indicators\nGET /api/alerts"]
    end

    subgraph JotiRoutes["Joti Integration"]
        JotiWebhook["/joti\nPOST /webhook/alerts\nPOST /audit-events"]
    end
```

---

## Diagram 9 — Use Case Execution Pipeline

Full flow from use case creation through Celery task execution to a terminal UseCaseRun result. Based on `backend/api/v2/use_cases.py` and `backend/tasks/use_case_tasks.py`.

```mermaid
flowchart TD
    A[Analyst creates Use Case\nPOST /use-cases\nname, technique_ids, tactic, severity, tags] --> B[UseCase row saved to DB\nstatus: active\nis_builtin: false]

    B --> C{Trigger run}
    C -->|Manual| D[POST /use-cases/id/run\nbody: triggered_by=manual]
    C -->|Bulk| E[POST /use-cases/run-all\ntriggered_by=manual]
    C -->|Joti webhook| F[POST /joti/webhook/alerts\ntechnique_id matches use case]
    C -->|Pipeline| G[Celery scheduled task\ntriggered_by=pipeline]

    D --> H[INSERT UseCaseRun\nstatus=pending\ntriggered_by=manual]
    E --> H2[INSERT UseCaseRun per active UC\nstatus=pending\ntriggered_by=manual]
    F --> H3[INSERT UseCaseRun\nstatus=pending\ntriggered_by=joti_webhook\nrun_details.joti_alert=alert_payload]
    G --> H4[INSERT UseCaseRun\nstatus=pending\ntriggered_by=pipeline]

    H --> I[run_use_case_task.delay task_id\nReturns immediately: run_id, task_id]
    H2 --> I2[run_all_use_cases_task.delay\nReturns: task_id for bulk operation]
    H3 --> I
    H4 --> I

    I --> J{Celery worker picks up task}
    J -->|Worker available| K[Task: load use case config\nfetch technique_ids from UseCase]
    J -->|Worker down / timeout| L[UseCaseRun stays pending\nWatchdog job flips to error after 10min]

    K --> M[Create simulation session\nSimulationSession with technique_ids]
    M --> N[Generate events matching technique_ids\nSessionManager.start_session]
    N --> O[Apply Sigma / SPL / KQL rules\nagainst generated GeneratedEvent rows]
    O --> P{Rules fired?}

    P -->|All rules fired| Q[pass_rate = rules_fired / rules_tested\nstatus=passed]
    P -->|Some rules fired| R[status=partial\npass_rate < 1.0]
    P -->|No rules fired| S[status=failed\npass_rate=0]
    P -->|Exception thrown| T[status=error\nerror_message=exc string]

    Q --> U[UPDATE UseCaseRun\nset completed_at, events_generated, rules_tested, rules_fired, pass_rate]
    R --> U
    S --> U
    T --> U

    U --> V[UPDATE UseCase.last_validated_at]
    V --> W[GET /use-cases/id/runs returns run history]
    V --> X[GET /use-cases/coverage aggregates per-tactic pass/fail]
    V --> Y[GET /use-cases/failing returns UCs with no passing run]
```

---

## Summary: Diagram Index

| # | Title | Diagram Type | Primary Source Files |
|---|-------|-------------|----------------------|
| 1 | System Architecture | graph LR | docker-compose, config.py |
| 2 | EDR State Machine | stateDiagram-v2 | engine/edr_state_machine.py |
| 3 | Session Lifecycle Sequence | sequenceDiagram | api/v2/sessions.py, engine/session_manager.py |
| 4 | Vendor Flow: CrowdStrike Isolate | sequenceDiagram | api/vendor/crowdstrike, engine/action_executor.py |
| 5 | Joti Integration Bidirectional | sequenceDiagram | joti/client.py, joti/webhook.py |
| 6 | ITDR Scenario Execution | sequenceDiagram | api/v2/itdr.py |
| 7 | Database ERD | erDiagram | db/models.py |
| 8 | API Surface Map | graph TD | api/v2/__init__.py |
| 9 | Use Case Execution Pipeline | flowchart TD | api/v2/use_cases.py, tasks/use_case_tasks.py |
