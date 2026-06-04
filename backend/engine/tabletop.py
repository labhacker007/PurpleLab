"""Tabletop Exercise Engine.

Provides pre-built attack scenario scripts and a HITL exercise runner.
Each exercise has phases with inject events and decision gates.
The engine scores team responses and generates an after-action report.

Built-in scenarios:
  ransomware_response       — Conti-style ransomware, 6 phases
  apt_infiltration          — APT28 spear-phish → exfil, 7 phases
  insider_threat            — Malicious insider data theft, 5 phases
  supply_chain_compromise   — SolarWinds-style, 6 phases
  bec_wire_fraud            — Business Email Compromise, 5 phases
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional


# ── Scenario library ──────────────────────────────────────────────────────────

SCENARIOS: dict[str, dict[str, Any]] = {

    "ransomware_response": {
        "name": "Ransomware Response Exercise",
        "description": "Simulate a Conti-style ransomware incident from initial access through containment.",
        "total_phases": 6,
        "expected_duration_minutes": 90,
        "phases": [
            {
                "phase": 1,
                "title": "Initial Access — Phishing Email",
                "inject": (
                    "T+0: A user (hr.manager@corp.com) reports receiving a suspicious email "
                    "with an Office macro attachment titled 'Q4_Payroll_Update.xlsm'. "
                    "Email gateway blocked 4 copies, but 2 reached inboxes. "
                    "EDR detects macro execution on WKSTN-HR-496."
                ),
                "observables": ["T1566.001", "T1059.001", "WKSTN-HR-496"],
                "decisions": [
                    "Isolate WKSTN-HR-496 immediately",
                    "Monitor and investigate before isolating",
                    "Scan all endpoints for similar macro patterns",
                    "Block sender domain at email gateway",
                ],
                "recommended": 0,
                "scoring": {"0": 10, "1": 5, "2": 7, "3": 6},
                "timer_minutes": 15,
            },
            {
                "phase": 2,
                "title": "Lateral Movement Detection",
                "inject": (
                    "T+22 min: Network traffic analysis shows SMB traffic from WKSTN-HR-496 "
                    "to 12 file servers. WKSTN-HR-496 is now contacting SERVER-DC01 via WMI. "
                    "Identity logs show valid domain admin credentials (svc-backup) used from WKSTN-HR-496."
                ),
                "observables": ["T1021.002", "T1047", "T1078", "SERVER-DC01"],
                "decisions": [
                    "Isolate WKSTN-HR-496 and reset svc-backup credentials",
                    "Isolate WKSTN-HR-496 only",
                    "Reset svc-backup only",
                    "Wait for more data",
                ],
                "recommended": 0,
                "scoring": {"0": 10, "1": 5, "2": 4, "3": 1},
                "timer_minutes": 10,
            },
            {
                "phase": 3,
                "title": "Ransomware Detonation",
                "inject": (
                    "T+45 min: Multiple endpoints begin showing mass file encryption. "
                    "File server FS-01 is generating thousands of .conti extension writes. "
                    "Ransom note 'CONTI_README.txt' appears on 8 file shares. "
                    "Backup server (BACKUP-01) is being accessed via SMB."
                ),
                "observables": ["T1486", "T1490", "BACKUP-01", "FS-01"],
                "decisions": [
                    "Isolate ALL file servers and backup server immediately",
                    "Isolate FS-01 only",
                    "Take network segment offline",
                    "Contact ransomware negotiation firm",
                ],
                "recommended": 0,
                "scoring": {"0": 10, "1": 4, "2": 8, "3": 0},
                "timer_minutes": 8,
            },
            {
                "phase": 4,
                "title": "C2 and Exfiltration Evidence",
                "inject": (
                    "T+60 min: Firewall logs show 2.3GB outbound to 185.220.101.45 (known Tor exit node) "
                    "over port 443. DNS queries for *.onion domains from multiple endpoints. "
                    "The threat actor appears to have had 18 days of persistent access before detonation."
                ),
                "observables": ["T1041", "T1048", "T1090", "185.220.101.45"],
                "decisions": [
                    "Block all Tor exit nodes at perimeter firewall",
                    "Notify legal and data protection officer",
                    "Preserve evidence before remediation",
                    "Begin forensic imaging of all compromised systems",
                ],
                "recommended": [1, 2],  # multiple correct
                "scoring": {"0": 5, "1": 9, "2": 10, "3": 8},
                "timer_minutes": 12,
            },
            {
                "phase": 5,
                "title": "Scope and Notification Decision",
                "inject": (
                    "T+75 min: Forensics confirms 15 endpoints encrypted, 3 file servers with data exfiltration. "
                    "Customer PII data (42,000 records) appears to have been exfiltrated based on directory listings. "
                    "Legal counsel has been notified. Regulatory reporting window: 72 hours under GDPR."
                ),
                "observables": ["GDPR", "notification", "PII"],
                "decisions": [
                    "File incident report with DPA within 72 hours",
                    "Wait for full forensic confirmation before notifying",
                    "Notify affected customers immediately",
                    "Engage ransomware negotiation",
                ],
                "recommended": 0,
                "scoring": {"0": 10, "1": 3, "2": 6, "3": 0},
                "timer_minutes": 15,
            },
            {
                "phase": 6,
                "title": "Recovery and Lessons Learned",
                "inject": (
                    "T+90 min: Affected systems are isolated, backups verified (last clean backup: 2 days ago). "
                    "Threat actor has not been re-detected. Leadership requests ETA for recovery and root cause."
                ),
                "observables": ["recovery", "RTO", "RCA"],
                "decisions": [
                    "Restore from backups, estimated 4-6 hours per server",
                    "Pay ransom to recover faster (2TB encrypted)",
                    "Rebuild from gold image, 2-3 day ETA",
                    "Restore most critical systems first, triage order",
                ],
                "recommended": 3,
                "scoring": {"0": 7, "1": 0, "2": 6, "3": 10},
                "timer_minutes": 10,
            },
        ],
    },

    "apt_infiltration": {
        "name": "APT Infiltration Exercise",
        "description": "APT28-style spear-phishing to credential theft and data exfiltration.",
        "total_phases": 5,
        "expected_duration_minutes": 75,
        "phases": [
            {
                "phase": 1,
                "title": "Spear-Phishing Attack",
                "inject": "T+0: HR director receives spear-phish from ceo@corp-mail.net (lookalike domain). Link leads to credential harvester. Director entered credentials before suspecting phishing.",
                "observables": ["T1566.002", "T1078", "credential_harvest"],
                "decisions": ["Reset director's credentials immediately", "Monitor account activity first", "Block lookalike domain", "Both reset and block"],
                "recommended": 3,
                "scoring": {"0": 5, "1": 3, "2": 4, "3": 10},
                "timer_minutes": 10,
            },
            {
                "phase": 2,
                "title": "Persistence Established",
                "inject": "T+3 days: SIEM alert — scheduled task created on director's workstation. Registry run key added. PowerShell beacon to known APT28 C2 infrastructure.",
                "observables": ["T1547.001", "T1053.005", "T1071.001"],
                "decisions": ["Isolate workstation", "Run memory forensics before isolating", "Block C2 IP at firewall", "All of the above"],
                "recommended": 3,
                "scoring": {"0": 4, "1": 8, "2": 5, "3": 10},
                "timer_minutes": 12,
            },
            {
                "phase": 3,
                "title": "Credential Dumping",
                "inject": "T+5 days: EDR detects procdump.exe accessing lsass.exe on director's workstation. 4 other credentials extracted from memory (including a domain admin).",
                "observables": ["T1003.001", "lsass", "T1078.002"],
                "decisions": ["Isolate and reset all 5 compromised accounts", "Reset domain admin only", "Full AD password reset", "Monitor without action"],
                "recommended": 0,
                "scoring": {"0": 10, "1": 6, "2": 8, "3": 0},
                "timer_minutes": 10,
            },
            {
                "phase": 4,
                "title": "Lateral Movement to Crown Jewels",
                "inject": "T+7 days: Domain admin credentials used to access finance server (FS-FINANCE). M365 mailbox export of CFO's email detected. 8GB SharePoint download.",
                "observables": ["T1005", "T1048", "FS-FINANCE", "exfiltration"],
                "decisions": ["Disable domain admin, isolate FS-FINANCE", "Let it run to collect evidence", "Block SharePoint externally", "Notify legal immediately"],
                "recommended": [0, 3],
                "scoring": {"0": 9, "1": 0, "2": 5, "3": 10},
                "timer_minutes": 15,
            },
            {
                "phase": 5,
                "title": "Attribution and Notification",
                "inject": "T+10 days: Forensics confirms APT28 TTPs. 120 days of access. CFO emails and financial projections compromised. Nation-state attribution.",
                "observables": ["APT28", "nation_state", "CISA_report"],
                "decisions": ["Report to CISA as critical infrastructure incident", "Handle quietly to avoid reputational damage", "Notify board and legal", "Both report to CISA and notify board"],
                "recommended": 3,
                "scoring": {"0": 8, "1": 0, "2": 7, "3": 10},
                "timer_minutes": 10,
            },
        ],
    },

    "insider_threat": {
        "name": "Insider Threat — Data Exfiltration",
        "description": "A malicious insider systematically exfiltrating sensitive IP before resigning.",
        "total_phases": 5,
        "expected_duration_minutes": 60,
        "phases": [
            {
                "phase": 1,
                "title": "DLP Alert",
                "inject": "T+0: DLP triggers on engineer john.doe@corp.com uploading 2.3GB to personal Google Drive. Content includes source code and customer data.",
                "observables": ["T1052", "T1041", "john.doe", "DLP"],
                "decisions": ["Block Google Drive org-wide", "Investigate john.doe account", "Alert HR and legal", "Revoke john.doe's access"],
                "recommended": 2,
                "scoring": {"0": 3, "1": 7, "2": 10, "3": 6},
                "timer_minutes": 10,
            },
            {
                "phase": 2,
                "title": "Investigation Reveals Pattern",
                "inject": "T+2 hours: HR confirms john.doe gave 2 weeks notice 3 days ago. CASB logs show 45 uploads over the past 30 days. USB device connected twice last week.",
                "observables": ["T1005", "T1052.001", "resignation"],
                "decisions": ["Disable account immediately", "Continue monitoring to capture full scope", "Preserve evidence before acting", "Interview john.doe"],
                "recommended": 2,
                "scoring": {"0": 5, "1": 3, "2": 10, "3": 2},
                "timer_minutes": 12,
            },
            {
                "phase": 3,
                "title": "Scope Determination",
                "inject": "T+1 day: Forensics shows 150GB exfiltrated. Source code, customer contracts, salary data. USB copies of 3 project designs. Evidence preserved.",
                "observables": ["scope", "forensics", "customer_data"],
                "decisions": ["Notify affected customers", "File police report", "Consult legal on civil action", "All of the above"],
                "recommended": 3,
                "scoring": {"0": 8, "1": 7, "2": 6, "3": 10},
                "timer_minutes": 15,
            },
            {
                "phase": 4,
                "title": "Access Revocation",
                "inject": "T+1 day: John.doe still has access to 3 SaaS systems (Salesforce, Jira, GitHub). Last login to GitHub was 2 hours ago.",
                "observables": ["saas_access", "github", "T1078"],
                "decisions": ["Revoke all SaaS access immediately", "Alert GitHub security team", "Revoke GitHub only given recent activity", "All SaaS + change git secrets"],
                "recommended": 3,
                "scoring": {"0": 7, "1": 5, "2": 6, "3": 10},
                "timer_minutes": 8,
            },
            {
                "phase": 5,
                "title": "Prevention and Closure",
                "inject": "T+1 week: All actions complete. Leadership wants lessons learned and prevention measures.",
                "observables": ["lessons_learned", "DLP", "offboarding"],
                "decisions": ["Implement automated offboarding checklist", "Add DLP rules for departing employees", "Quarterly access reviews", "All of the above"],
                "recommended": 3,
                "scoring": {"0": 7, "1": 8, "2": 6, "3": 10},
                "timer_minutes": 10,
            },
        ],
    },
}


# ── Exercise runner helpers ────────────────────────────────────────────────────

def get_scenario(key: str) -> Optional[dict]:
    return SCENARIOS.get(key)


def list_scenarios() -> list[dict]:
    return [
        {
            "key": k,
            "name": v["name"],
            "description": v["description"],
            "total_phases": v["total_phases"],
            "expected_duration_minutes": v["expected_duration_minutes"],
        }
        for k, v in SCENARIOS.items()
    ]


def score_response(scenario_key: str, phase_num: int, decision_index: str) -> int:
    scenario = SCENARIOS.get(scenario_key, {})
    phases = scenario.get("phases", [])
    for phase in phases:
        if phase["phase"] == phase_num:
            scoring = phase.get("scoring", {})
            return scoring.get(str(decision_index), 0)
    return 0


def compute_final_score(scenario_key: str, responses: list[dict]) -> float:
    """Compute normalized score (0-100) from response list."""
    scenario = SCENARIOS.get(scenario_key, {})
    phases = scenario.get("phases", [])
    if not phases:
        return 0.0

    # Max possible score = 10 per phase
    max_score = len(phases) * 10
    total = 0
    for resp in responses:
        phase_num = resp.get("phase")
        decision = str(resp.get("decision_index", "0"))
        for phase in phases:
            if phase["phase"] == phase_num:
                total += phase.get("scoring", {}).get(decision, 0)
                # Bonus for fast response
                time_taken = resp.get("time_seconds", 999)
                timer = phase.get("timer_minutes", 10) * 60
                if time_taken < timer * 0.5:
                    total += 2  # speed bonus

    return round((total / max_score) * 100, 1)


def generate_aar(exercise_data: dict) -> dict:
    """Generate an after-action report from a completed exercise."""
    scenario_key = exercise_data.get("scenario_key", "")
    scenario = SCENARIOS.get(scenario_key, {})
    responses = exercise_data.get("responses", []) or []
    score = exercise_data.get("score", 0)

    phase_results = []
    for resp in responses:
        phase_num = resp.get("phase")
        decision = str(resp.get("decision_index", "0"))
        for phase in (scenario.get("phases") or []):
            if phase["phase"] == phase_num:
                recommended = phase.get("recommended", 0)
                rec_indices = recommended if isinstance(recommended, list) else [recommended]
                correct = int(decision) in rec_indices
                phase_score = phase.get("scoring", {}).get(decision, 0)
                phase_results.append({
                    "phase": phase_num,
                    "title": phase["title"],
                    "decision_taken": phase["decisions"][int(decision)] if int(decision) < len(phase["decisions"]) else "Unknown",
                    "recommended_decision": phase["decisions"][rec_indices[0]] if rec_indices[0] < len(phase["decisions"]) else "",
                    "correct": correct,
                    "score": phase_score,
                    "time_seconds": resp.get("time_seconds"),
                    "rationale": resp.get("rationale", ""),
                })

    strengths = [r["title"] for r in phase_results if r["correct"]]
    gaps = [r["title"] for r in phase_results if not r["correct"]]

    performance = "Excellent" if score >= 85 else ("Good" if score >= 70 else ("Fair" if score >= 50 else "Needs Improvement"))

    return {
        "exercise_name": scenario.get("name", ""),
        "scenario": scenario_key,
        "score": score,
        "performance_rating": performance,
        "total_phases": len(scenario.get("phases", [])),
        "phases_completed": len(responses),
        "phase_results": phase_results,
        "strengths": strengths,
        "improvement_areas": gaps,
        "key_findings": [
            f"Score: {score}/100 ({performance})",
            f"Completed {len(responses)}/{len(scenario.get('phases', []))} phases",
            f"Strengths in: {', '.join(strengths[:3]) or 'None identified'}",
            f"Gaps in: {', '.join(gaps[:3]) or 'None identified'}",
        ],
        "recommendations": _generate_recommendations(gaps, scenario_key),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _generate_recommendations(gaps: list[str], scenario_key: str) -> list[str]:
    recs = []
    gap_text = " ".join(gaps).lower()
    if "phishing" in gap_text or "initial access" in gap_text:
        recs.append("Review phishing response playbook and ensure analysts can identify spear-phishing indicators within 15 minutes.")
    if "lateral" in gap_text or "credential" in gap_text:
        recs.append("Improve credential monitoring — implement alerts for admin account usage outside business hours.")
    if "isolation" in gap_text or "contain" in gap_text:
        recs.append("Test and rehearse endpoint isolation workflow — target <5 minute time-to-contain for critical systems.")
    if "notification" in gap_text or "legal" in gap_text:
        recs.append("Establish clear escalation paths to Legal/DPO — ensure team knows notification thresholds (GDPR 72h, etc.).")
    if not recs:
        recs.append("Continue regular tabletop exercises to maintain response muscle memory.")
    return recs
