# Joti Sim — Universal Security Product Simulator

**Build realistic security lab environments in minutes.** Drag-and-drop security products onto a canvas, connect them to your SOAR/TIP platform, and get production-quality test data flowing instantly.

## What This Is

Joti Sim is a standalone simulation platform that mimics real-world security products — SIEMs, EDRs, identity providers, email gateways, vulnerability scanners, ITSM tools, and cloud security. Each simulator generates realistic alerts, events, and findings that match the actual vendor's API format.

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
│  JOTI SIM — Frontend (React + drag-and-drop canvas)         │
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
│  JOTI SIM — Backend (FastAPI + generator engine)            │
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
# Clone
git clone https://github.com/labhacker007/joti-sim.git
cd joti-sim

# Run with Docker
docker compose up -d

# Open UI
open http://localhost:4000

# Or run directly
pip install -r requirements.txt
python -m uvicorn backend.main:app --port 4000
```

## How It Works

1. **Open the UI** at `http://localhost:4000`
2. **Drag products** from the sidebar onto the canvas (e.g., Splunk, CrowdStrike, Okta)
3. **Connect them** to your target platform (e.g., Joti at `http://localhost:8000`)
4. **Configure each product**: alert frequency, severity distribution, IOC types, attack scenarios
5. **Start the session** — realistic events start flowing to your target
6. **Monitor** the live event log showing what's being sent

## Connecting to Joti

```
Joti Sim (port 4000)  ──webhook──→  Joti Platform (port 8000)
                                     /api/alerts/ingest/{token}
```

Each simulator sends data to Joti's webhook endpoint using the AlertSource token. Create an AlertSource in Joti with the matching `source_type` (splunk, crowdstrike, okta, etc.) and use that webhook token in the simulator config.

## License

Internal tool — not for distribution.
