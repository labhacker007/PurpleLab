# PurpleLab — Universal Security Product Simulator

**Build realistic security lab environments in minutes.** Drag-and-drop security products onto a canvas, connect them to your SOAR/TIP platform, and get production-quality test data flowing instantly.

## What This Is

PurpleLab is a standalone simulation platform that mimics real-world security products — SIEMs, EDRs, identity providers, email gateways, vulnerability scanners, ITSM tools, and cloud security. Each simulator generates realistic alerts, events, and findings that match the actual vendor's API format.

**Not a mock.** Not placeholder data. Each simulator reverse-engineers the real product's webhook/API payload structure and generates events that are indistinguishable from production data.

## Supported Simulators

### SIEM
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **Splunk** | Webhook alert action | search_name, urgency, results |
| **Microsoft Sentinel** | Alert webhook | AlertDisplayName, AlertSeverity |
| **IBM QRadar** | Offense notification | offense_name, magnitude |
| **Elastic SIEM** | Alert webhook | rule.name, kibana.alert.severity |
| **Google Chronicle** | YARA-L 2.0 alerts | detection rules |

### EDR
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **CrowdStrike Falcon** | Detection API | ProcessRollup2, DNS, Network |
| **Carbon Black** | Alert webhook | WATCHLIST, CB_ANALYTICS |
| **SentinelOne** | Threat webhook | malware, exploit, PUP |
| **Microsoft Defender** | Alert API | Informational → High |

### Identity (ITDR)
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **Okta** | System Log | auth, MFA, account lock, impossible travel |
| **Microsoft Entra ID** | Sign-in/audit | risky sign-in, MFA registration |
| **CrowdStrike Identity** | Identity events | lateral movement, privilege escalation |

### Email Security
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **Proofpoint TAP** | Clicks/messages | phishing, malware, BEC |
| **Mimecast** | Threat events | URL protection, impersonation |
| **Defender for Office 365** | Email alerts | file detonation, URL detonation |

### ITSM
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **ServiceNow** | Incident REST API | create, update, resolve |
| **Jira** | Issue webhook | created, updated, transitioned |

### Vulnerability
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **Tenable** | Vulnerability export | CVE findings |
| **Qualys** | Detection format | host vulns |

### Cloud Security
| Product | Payload Format | Event Types |
|---------|---------------|-------------|
| **AWS GuardDuty** | Finding format | recon, trojan, exfil |
| **Azure Security Center** | Alert format | brute force, anomalous |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PURPLELAB — Frontend (React + drag-and-drop canvas)         │
│                                                              │
│  ┌──────┐ ┌──────────┐ ┌──────┐ ┌──────┐                   │
│  │Splunk│→│CrowdStrike│→│ Okta │→│ Joti │                   │
│  └──────┘ └──────────┘ └──────┘ └──────┘                   │
│     Drag products onto canvas, connect with arrows           │
│     Configure: frequency, severity mix, IOC types            │
│     Hit "Run" → data flows in real-time                      │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│  PURPLELAB — Backend (FastAPI + generator engine)            │
│                                                              │
│  SimulationEngine                                            │
│    ├── SessionManager     (create/start/stop sessions)       │
│    ├── GeneratorRegistry  (register vendor generators)       │
│    ├── EventScheduler     (APScheduler per-session)          │
│    └── WebhookDispatcher  (send events to target URLs)       │
│                                                              │
│  Per-Vendor Generators                                       │
│    ├── SplunkGenerator    (realistic SPL alert payloads)     │
│    ├── CrowdStrikeGenerator (Falcon detection payloads)      │
│    ├── OktaGenerator      (System Log events)                │
│    ├── ProofpointGenerator (TAP clicks/messages)             │
│    └── ... 20+ generators                                    │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
git clone https://github.com/labhacker007/PurpleLab.git
cd PurpleLab

# One command: builds images, starts all services, runs migrations
bash purplelab.sh release
```

| Service | URL |
|---------|-----|
| Backend API | http://localhost:8002 |
| API Docs | http://localhost:8002/docs |
| Frontend | http://localhost:3002 |

### Common build commands

```bash
bash purplelab.sh build backend    # rebuild backend only (fast, uses pip cache)
bash purplelab.sh build frontend   # rebuild frontend only (fast, uses npm cache)
bash purplelab.sh build            # rebuild both
bash purplelab.sh up               # start all containers
bash purplelab.sh down             # stop all containers
bash purplelab.sh status           # health check
bash purplelab.sh logs             # tail logs
```

> **Full installation guide, build optimization details, and troubleshooting:** [docs/INSTALL.md](docs/INSTALL.md)

## How It Works

1. **Open the UI** at `http://localhost:4000`
2. **Drag products** from the sidebar onto the canvas (e.g., Splunk, CrowdStrike, Okta)
3. **Connect them** to your target platform (e.g., Joti at `http://localhost:8000`)
4. **Configure each product**: alert frequency, severity distribution, IOC types, attack scenarios
5. **Start the session** — realistic events start flowing to your target
6. **Monitor** the live event log showing what's being sent

## Connecting to Joti

```
PurpleLab (port 4000)  ──webhook──→  Joti Platform (port 8000)
                                     /api/alerts/ingest/{token}
```

Each simulator sends data to Joti's webhook endpoint using the AlertSource token. Create an AlertSource in Joti with the matching `source_type` (splunk, crowdstrike, okta, etc.) and use that webhook token in the simulator config.

---

## MCP Server — AI Agent Integration

PurpleLab exposes all security simulation capabilities as an **MCP (Model Context Protocol) server**, so any AI agent — Claude Desktop, VS Code Copilot, Cursor, Joti's SOC Agent, or your own custom agent — can call EDR, SIEM, Identity, and Network tools directly.

### Available Tool Categories

| Category | Tools | Example Operations |
|----------|-------|--------------------|
| **EDR** | 8 tools | List endpoints, isolate host, block hash/process, hunt IOC, run RTR command |
| **SIEM** | 3 tools | Get alerts, search events, deploy detection rule |
| **Identity** | 5 tools | List users, lock/unlock account, revoke sessions, force MFA reset |
| **Network** | 6 tools | Block/unblock IP, domain, URL, hash; list active blocks |
| **Platform** | 2 tools | Get containment audit log, environment status |

### Quick Start — Claude Code CLI

```bash
# Get your API key (auto-generated by purplelab.sh)
grep PURPLELAB_MCP_API_KEY .env

# Register PurpleLab as an MCP server in Claude Code
claude mcp add purplelab \
  --transport http \
  --url http://localhost:8002/api/v2/mcp \
  --header "X-API-Key:YOUR_KEY"

# Verify
claude mcp list
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "purplelab": {
      "transport": "http",
      "url": "http://localhost:8002/api/v2/mcp",
      "headers": { "X-API-Key": "YOUR_KEY" }
    }
  }
}
```

### VS Code / Cursor

Add to `.vscode/mcp.json` (VS Code) or `~/.cursor/mcp.json` (Cursor):

```json
{
  "servers": {
    "purplelab": {
      "type": "http",
      "url": "http://localhost:8002/api/v2/mcp",
      "headers": { "X-API-Key": "YOUR_KEY" }
    }
  }
}
```

### Discovery Endpoint (no auth required)

```bash
curl http://localhost:8002/api/v2/mcp
```

Returns the full tool catalogue, quick-connect commands, and client config snippets. Also shows the correct API key for the running instance.

### Connecting to Joti

PurpleLab can register itself automatically as an MCP server in Joti's MCP Hub so Joti's SOC Agent can call simulation tools during incident response:

```bash
# Option A — automatic on startup (.env)
PURPLELAB_MCP_AUTO_REGISTER_JOTI=true
JOTI_BASE_URL=http://localhost:8000

# Option B — manual one-shot registration
python scripts/register_with_joti.py
```

After registration, Joti creates enrichment policies so the SOC Agent can run IOC hunts, check endpoint isolation status, and pull active network blocks directly from PurpleLab during case investigation.

### Transport Options

| Transport | Endpoint | Best For |
|-----------|----------|----------|
| HTTP JSON-RPC | `POST /api/v2/mcp` | Server-to-server (Joti, scripts, CI) |
| SSE | `GET /api/v2/mcp/sse` + `POST /api/v2/mcp/messages` | Claude Desktop, VS Code, Cursor |
| Discovery | `GET /api/v2/mcp` | No-auth tool catalogue, client config |

Full client configs for all tools: [`mcp-clients.json`](mcp-clients.json)

---

## Containment Actions

All containment actions taken through the MCP server or REST API are logged to an immutable audit trail at `GET /api/v2/edr/actions`.

| Action | Endpoint | MCP Tool |
|--------|----------|----------|
| Isolate host | `POST /api/v2/edr/devices/{id}/isolate` | `edr_isolate_host` |
| Release host | `DELETE /api/v2/edr/devices/{id}/isolate` | `edr_release_host` |
| Block hash | `POST /api/v2/edr/block/hash` | `edr_block_hash` |
| Lock user | `POST /api/v2/identity/users/{id}/lock` | `identity_lock_user` |
| Revoke sessions | `POST /api/v2/identity/users/{id}/revoke-sessions` | `identity_revoke_sessions` |
| Block IP | `POST /api/v2/network/block/ip` | `network_block_ip` |
| Block domain | `POST /api/v2/network/block/domain` | `network_block_domain` |

---

## License

MIT — see [LICENSE](LICENSE)
