"""Jira Cloud REST API v3 emulation.

Grounded in the official Jira Cloud REST API Reference:
  https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/

Implements:
  Issues (CRUD, JQL search, transitions, comments, worklogs)
  Projects (list, get)
  Boards and Sprints (Agile API)
  Users (search, get)
  Attachments
  Priorities, Statuses, Issue Types metadata
  Service Management (JSM) Service Desk + Requests + SLAs

Authentication:
  Basic: Authorization: Basic base64(email:api_token)
  Bearer: Authorization: Bearer <oauth2_token>
  Cookie: JSESSIONID (server-to-server)

Jira Agile API base: /rest/agile/1.0
Jira Core API base: /rest/api/3
Jira Service Management API base: /rest/servicedeskapi
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Path, Query, Request

router = APIRouter(prefix="/api/vendor/jira", tags=["vendor:jira"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _sid() -> str:
    return uuid.uuid4().hex[:24]


def _key(project: str, num: int) -> str:
    return f"{project}-{num}"


# ─────────────────────────────────────────────────────────────────────────────
# Seed data
# ─────────────────────────────────────────────────────────────────────────────

_USERS: dict[str, dict] = {
    "611a2b3c4d5e6f7890abcdef": {
        "accountId": "611a2b3c4d5e6f7890abcdef",
        "accountType": "atlassian",
        "active": True,
        "displayName": "John Smith",
        "emailAddress": "jsmith@corp.local",
        "avatarUrls": {"48x48": "https://secure.gravatar.com/avatar/0"},
        "locale": "en_US",
        "timeZone": "America/New_York",
    },
    "611a2b3c4d5e6f7890abcde0": {
        "accountId": "611a2b3c4d5e6f7890abcde0",
        "accountType": "atlassian",
        "active": True,
        "displayName": "Ana Garcia",
        "emailAddress": "agarcia@corp.local",
        "avatarUrls": {"48x48": "https://secure.gravatar.com/avatar/1"},
        "locale": "en_US",
        "timeZone": "America/Los_Angeles",
    },
    "611a2b3c4d5e6f7890abcde1": {
        "accountId": "611a2b3c4d5e6f7890abcde1",
        "accountType": "atlassian",
        "active": True,
        "displayName": "SOC Automation",
        "emailAddress": "soc-auto@corp.local",
        "avatarUrls": {"48x48": "https://secure.gravatar.com/avatar/2"},
        "locale": "en_US",
        "timeZone": "UTC",
    },
}

_PROJECTS: list[dict] = [
    {
        "id": "10001", "key": "SEC",
        "name": "Security Operations",
        "projectTypeKey": "software",
        "simplified": False,
        "style": "classic",
        "isPrivate": False,
        "description": "Security incidents, vulnerabilities, and threat response tracking",
        "lead": _USERS["611a2b3c4d5e6f7890abcde0"],
        "avatarUrls": {"48x48": "/images/project/avatar/security.png"},
        "projectCategory": {"id": "10000", "name": "Operations"},
        "issueTypes": ["Bug", "Task", "Story", "Epic", "Sub-task"],
    },
    {
        "id": "10002", "key": "IT",
        "name": "IT Operations",
        "projectTypeKey": "service_desk",
        "simplified": True,
        "style": "next-gen",
        "isPrivate": False,
        "description": "IT support, change management, and infrastructure tasks",
        "lead": _USERS["611a2b3c4d5e6f7890abcdef"],
        "avatarUrls": {"48x48": "/images/project/avatar/it.png"},
        "projectCategory": {"id": "10001", "name": "IT"},
        "issueTypes": ["Service Request", "Incident", "Change", "Problem"],
    },
]

_ISSUE_TYPES: list[dict] = [
    {"id": "1", "name": "Bug", "description": "A problem which impairs or prevents the functions of the product.", "iconUrl": "/images/icons/issuetypes/bug.png", "subtask": False},
    {"id": "2", "name": "Task", "description": "A task that needs to be done.", "iconUrl": "/images/icons/issuetypes/task.png", "subtask": False},
    {"id": "3", "name": "Story", "description": "A user story.", "iconUrl": "/images/icons/issuetypes/story.png", "subtask": False},
    {"id": "4", "name": "Epic", "description": "A big user story that needs to be broken down.", "iconUrl": "/images/icons/issuetypes/epic.png", "subtask": False},
    {"id": "5", "name": "Sub-task", "description": "The sub-task of the issue.", "iconUrl": "/images/icons/issuetypes/subtask_alternate.png", "subtask": True},
    {"id": "6", "name": "Incident", "description": "Security or IT incident requiring response.", "iconUrl": "/images/icons/issuetypes/bug.png", "subtask": False},
    {"id": "7", "name": "Vulnerability", "description": "Tracked vulnerability from scanning tools.", "iconUrl": "/images/icons/issuetypes/bug.png", "subtask": False},
]

_PRIORITIES: list[dict] = [
    {"id": "1", "name": "Critical", "description": "Critical business impact.", "iconUrl": "/images/icons/priorities/critical.png"},
    {"id": "2", "name": "High", "description": "High impact.", "iconUrl": "/images/icons/priorities/major.png"},
    {"id": "3", "name": "Medium", "description": "Medium impact.", "iconUrl": "/images/icons/priorities/medium.png"},
    {"id": "4", "name": "Low", "description": "Low impact.", "iconUrl": "/images/icons/priorities/minor.png"},
    {"id": "5", "name": "Lowest", "description": "Lowest priority.", "iconUrl": "/images/icons/priorities/trivial.png"},
]

_STATUSES: list[dict] = [
    {"id": "1", "name": "To Do", "statusCategory": {"id": 2, "key": "new", "colorName": "blue-gray", "name": "To Do"}},
    {"id": "2", "name": "In Progress", "statusCategory": {"id": 4, "key": "indeterminate", "colorName": "yellow", "name": "In Progress"}},
    {"id": "3", "name": "In Review", "statusCategory": {"id": 4, "key": "indeterminate", "colorName": "yellow", "name": "In Progress"}},
    {"id": "4", "name": "Done", "statusCategory": {"id": 3, "key": "done", "colorName": "green", "name": "Done"}},
    {"id": "5", "name": "Blocked", "statusCategory": {"id": 4, "key": "indeterminate", "colorName": "yellow", "name": "In Progress"}},
    {"id": "6", "name": "Closed", "statusCategory": {"id": 3, "key": "done", "colorName": "green", "name": "Done"}},
    {"id": "7", "name": "Won't Do", "statusCategory": {"id": 3, "key": "done", "colorName": "green", "name": "Done"}},
]


def _make_transitions(status_id: str) -> list[dict]:
    """Return available transitions from a given status."""
    all_transitions = {
        "1": [  # To Do → In Progress, Blocked, Won't Do
            {"id": "11", "name": "Start Progress", "to": _STATUSES[1], "hasScreen": False},
            {"id": "15", "name": "Won't Do", "to": _STATUSES[6], "hasScreen": True},
        ],
        "2": [  # In Progress → In Review, Blocked, Done
            {"id": "21", "name": "Send for Review", "to": _STATUSES[2], "hasScreen": False},
            {"id": "22", "name": "Mark as Blocked", "to": _STATUSES[4], "hasScreen": True},
            {"id": "23", "name": "Done", "to": _STATUSES[3], "hasScreen": True},
            {"id": "29", "name": "Back to To Do", "to": _STATUSES[0], "hasScreen": False},
        ],
        "3": [  # In Review → Done, Back to In Progress
            {"id": "31", "name": "Approve", "to": _STATUSES[3], "hasScreen": True},
            {"id": "32", "name": "Request Changes", "to": _STATUSES[1], "hasScreen": True},
        ],
        "4": [  # Done → Reopen
            {"id": "41", "name": "Reopen", "to": _STATUSES[0], "hasScreen": False},
        ],
        "5": [  # Blocked → In Progress
            {"id": "51", "name": "Unblock", "to": _STATUSES[1], "hasScreen": False},
        ],
    }
    return all_transitions.get(status_id, [])


def _build_issue(raw: dict) -> dict:
    """Build a full Jira issue response object from internal storage."""
    status = next((s for s in _STATUSES if s["id"] == raw.get("status_id", "1")), _STATUSES[0])
    priority = next((p for p in _PRIORITIES if p["id"] == raw.get("priority_id", "3")), _PRIORITIES[2])
    issue_type = next((t for t in _ISSUE_TYPES if t["id"] == raw.get("issue_type_id", "2")), _ISSUE_TYPES[1])
    assignee = _USERS.get(raw.get("assignee_id", "")) if raw.get("assignee_id") else None
    reporter = _USERS.get(raw.get("reporter_id", "611a2b3c4d5e6f7890abcde1"), _USERS["611a2b3c4d5e6f7890abcde1"])

    return {
        "id": raw["id"],
        "key": raw["key"],
        "self": f"/rest/api/3/issue/{raw['id']}",
        "fields": {
            "summary": raw.get("summary", ""),
            "description": raw.get("description", ""),
            "status": status,
            "priority": priority,
            "issuetype": issue_type,
            "project": next((p for p in _PROJECTS if p["key"] == raw.get("project_key")), _PROJECTS[0]),
            "assignee": assignee,
            "reporter": reporter,
            "created": raw.get("created", _now_iso()),
            "updated": raw.get("updated", _now_iso()),
            "resolutiondate": raw.get("resolutiondate"),
            "duedate": raw.get("duedate"),
            "labels": raw.get("labels", []),
            "components": [{"id": "10000", "name": c} for c in raw.get("components", [])],
            "fixVersions": [],
            "versions": [],
            "comment": {
                "comments": raw.get("comments", []),
                "maxResults": len(raw.get("comments", [])),
                "total": len(raw.get("comments", [])),
                "startAt": 0,
            },
            "attachment": raw.get("attachments", []),
            "subtasks": [],
            "parent": None,
            "timetracking": {
                "originalEstimate": raw.get("original_estimate"),
                "remainingEstimate": raw.get("remaining_estimate"),
                "timeSpent": raw.get("time_spent"),
            },
            "customfield_10000": raw.get("epic_link"),    # Epic Link
            "customfield_10001": raw.get("story_points"), # Story Points
            "customfield_10002": raw.get("sprint"),        # Sprint
            "customfield_10014": raw.get("epic_name"),     # Epic Name
            "customfield_10016": raw.get("story_points"),  # Story point estimate (next-gen)
            # Security custom fields
            "customfield_10100": raw.get("cve_id"),
            "customfield_10101": raw.get("cvss_score"),
            "customfield_10102": raw.get("affected_asset"),
            "customfield_10103": raw.get("severity"),
            "customfield_10104": raw.get("attack_vector"),
            "customfield_10105": raw.get("mitre_tactic"),
            "customfield_10106": raw.get("mitre_technique"),
            "customfield_10107": raw.get("soc_ticket_id"),  # Linked SOC/SOAR ticket
            "environment": raw.get("environment"),
            "resolution": {"id": "10000", "name": raw.get("resolution")} if raw.get("resolution") else None,
            "votes": {"votes": 0, "hasVoted": False},
            "watches": {"watchCount": 1, "isWatching": True},
        },
        "changelog": {"startAt": 0, "maxResults": 0, "total": 0, "histories": []},
        "renderedFields": {},
        "names": {},
        "schema": {},
        "transitions": _make_transitions(raw.get("status_id", "1")),
    }


# Seed issues
_now = _now_iso
_SEED_ISSUES: list[dict] = [
    {
        "id": "10001", "key": "SEC-1", "project_key": "SEC",
        "issue_type_id": "6",   # Incident
        "summary": "Suspicious PowerShell execution on CORP-WS-001",
        "description": {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Encoded PowerShell execution detected by CrowdStrike EDR on CORP-WS-001. Parent process: WINWORD.EXE. Possible phishing attack. Investigate and remediate."}]}]
        },
        "status_id": "2",    # In Progress
        "priority_id": "1",  # Critical
        "assignee_id": "611a2b3c4d5e6f7890abcde0",
        "reporter_id": "611a2b3c4d5e6f7890abcde1",
        "labels": ["security", "edr", "powershell", "phishing"],
        "components": ["Endpoint Security"],
        "created": (datetime.now(timezone.utc) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "updated": (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "severity": "Critical",
        "mitre_tactic": "TA0002",  # Execution
        "mitre_technique": "T1059.001",  # PowerShell
        "affected_asset": "CORP-WS-001",
        "soc_ticket_id": "INC0001002",
        "comments": [
            {
                "id": "10001",
                "author": _USERS["611a2b3c4d5e6f7890abcde0"],
                "body": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Isolating endpoint CORP-WS-001 in CrowdStrike. Starting memory acquisition."}]}]},
                "created": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "updated": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            }
        ],
    },
    {
        "id": "10002", "key": "SEC-2", "project_key": "SEC",
        "issue_type_id": "7",   # Vulnerability
        "summary": "CVE-2024-21413 — Microsoft Outlook RCE (CVSS 9.8) — 47 affected hosts",
        "description": {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": "Critical Outlook RCE vulnerability detected by Tenable scan. Affects 47 Windows workstations. Patch via SCCM: KB5034671. Emergency change CHG0010001 submitted."}]}]
        },
        "status_id": "2",    # In Progress
        "priority_id": "1",  # Critical
        "assignee_id": "611a2b3c4d5e6f7890abcdef",
        "reporter_id": "611a2b3c4d5e6f7890abcde1",
        "labels": ["vulnerability", "patch", "emergency", "cve"],
        "components": ["Patch Management", "Endpoint Security"],
        "created": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "updated": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "cve_id": "CVE-2024-21413",
        "cvss_score": "9.8",
        "severity": "Critical",
        "attack_vector": "Network",
        "duedate": (datetime.now(timezone.utc) + timedelta(hours=24)).strftime("%Y-%m-%d"),
        "soc_ticket_id": "CHG0010001",
        "comments": [],
    },
    {
        "id": "10003", "key": "IT-1", "project_key": "IT",
        "issue_type_id": "1",   # Incident (IT)
        "summary": "VPN access broken for user jsmith after password reset",
        "description": {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": "User John Smith unable to authenticate to Cisco AnyConnect VPN after scheduled password reset. Error: Authentication failed."}]}]
        },
        "status_id": "2",    # In Progress
        "priority_id": "2",  # High
        "assignee_id": "611a2b3c4d5e6f7890abcdef",
        "reporter_id": "611a2b3c4d5e6f7890abcdef",
        "labels": ["vpn", "authentication", "network"],
        "components": ["Network", "Identity"],
        "created": (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "updated": (datetime.now(timezone.utc) - timedelta(minutes=45)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "soc_ticket_id": "INC0001001",
        "comments": [],
    },
]

# Mutable state
_issues: dict[str, dict] = {i["id"]: i for i in _SEED_ISSUES}
_issues_by_key: dict[str, str] = {i["key"]: i["id"] for i in _SEED_ISSUES}
_comments: dict[str, list] = {}  # issue_id → [comment, ...]


def _jql_filter(jql: str, issues: list[dict]) -> list[dict]:
    """
    Parse a subset of JQL and filter issues.
    Supported clauses: project=, issuetype=, status=, priority=, assignee=,
    labels=, text~, created>=, updated>=, AND/OR
    ORDER BY (ignored — returns as-is)
    """
    if not jql:
        return issues

    jql_clean = re.sub(r'\s+ORDER\s+BY.*', '', jql, flags=re.IGNORECASE).strip()
    result = issues

    # Split on AND / OR (simplified — treat all as AND)
    clauses = re.split(r'\s+(?:AND|OR)\s+', jql_clean, flags=re.IGNORECASE)
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue

        # text ~ "..."
        m = re.match(r'text\s*~\s*["\']?([^"\']+)["\']?', clause, re.IGNORECASE)
        if m:
            term = m.group(1).lower()
            result = [i for i in result if term in i.get("summary", "").lower()
                      or term in str(i.get("description", "")).lower()]
            continue

        # summary ~ "..."
        m = re.match(r'summary\s*~\s*["\']?([^"\']+)["\']?', clause, re.IGNORECASE)
        if m:
            term = m.group(1).lower()
            result = [i for i in result if term in i.get("summary", "").lower()]
            continue

        # labels in ("a","b") or labels = "a"
        m = re.match(r'labels?\s*(?:in\s*\(([^)]+)\)|=\s*["\']?([^"\']+)["\']?)', clause, re.IGNORECASE)
        if m:
            vals = [v.strip().strip('"\'') for v in (m.group(1) or m.group(2) or "").split(",")]
            result = [i for i in result if any(l in i.get("labels", []) for l in vals)]
            continue

        # customfield_xxxxx = "value"
        m = re.match(r'(customfield_\d+)\s*=\s*["\']?([^"\']+)["\']?', clause, re.IGNORECASE)
        if m:
            field, val = m.group(1), m.group(2).lower()
            # Map to internal fields
            cf_map = {"customfield_10100": "cve_id", "customfield_10101": "cvss_score",
                      "customfield_10102": "affected_asset", "customfield_10103": "severity",
                      "customfield_10107": "soc_ticket_id"}
            ifield = cf_map.get(field, field)
            result = [i for i in result if str(i.get(ifield, "")).lower() == val]
            continue

        # Generic: field = "value" or field in ("v1","v2")
        m_in = re.match(r'(\w+)\s+in\s*\(([^)]+)\)', clause, re.IGNORECASE)
        if m_in:
            field, vals_raw = m_in.group(1).lower(), m_in.group(2)
            vals = [v.strip().strip('"\'').lower() for v in vals_raw.split(",")]
            result = [i for i in result if _jql_field_match(i, field, vals)]
            continue

        m_eq = re.match(r'(\w+)\s*(=|!=|>=|<=|>|<)\s*["\']?([^"\']+)["\']?', clause, re.IGNORECASE)
        if m_eq:
            field, op, val = m_eq.group(1).lower(), m_eq.group(2), m_eq.group(3).strip('"\'').lower()
            if op == "=":
                result = [i for i in result if _jql_field_match(i, field, [val])]
            elif op == "!=":
                result = [i for i in result if not _jql_field_match(i, field, [val])]
            # Date comparisons for created/updated (simplified)
            elif field in ("created", "updated") and op in (">=", "<=", ">", "<"):
                result = [i for i in result if _jql_date_compare(i.get(field, ""), op, val)]
            continue

    return result


def _jql_field_match(issue: dict, field: str, vals: list[str]) -> bool:
    field_map = {
        "project": "project_key",
        "issuetype": "issue_type_id",
        "issueType": "issue_type_id",
        "status": "status_id",
        "priority": "priority_id",
        "assignee": "assignee_id",
        "reporter": "reporter_id",
        "labels": "labels",
        "key": "key",
        "id": "id",
    }
    ifield = field_map.get(field, field)
    raw_val = issue.get(ifield)

    # Resolve display name for ID fields
    if field == "issuetype" or field == "issuetype":
        it = next((t for t in _ISSUE_TYPES if t["id"] == raw_val), {})
        return it.get("name", "").lower() in vals or str(raw_val).lower() in vals
    if field == "status":
        st = next((s for s in _STATUSES if s["id"] == raw_val), {})
        return st.get("name", "").lower() in vals or str(raw_val).lower() in vals
    if field == "priority":
        pr = next((p for p in _PRIORITIES if p["id"] == raw_val), {})
        return pr.get("name", "").lower() in vals or str(raw_val).lower() in vals
    if field == "labels":
        return any(v in [l.lower() for l in (raw_val or [])] for v in vals)
    if field == "assignee":
        user = _USERS.get(raw_val or "", {})
        return user.get("displayName", "").lower() in vals or (raw_val or "").lower() in vals or user.get("emailAddress", "").lower() in vals

    return str(raw_val or "").lower() in vals


def _jql_date_compare(date_str: str, op: str, val: str) -> bool:
    try:
        d = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if val == "now()":
            t = datetime.now(timezone.utc)
        elif val.endswith("d"):
            t = datetime.now(timezone.utc) - timedelta(days=int(val[1:-1]))
        elif val.endswith("h"):
            t = datetime.now(timezone.utc) - timedelta(hours=int(val[1:-1]))
        else:
            t = datetime.strptime(val, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return {">=": d >= t, "<=": d <= t, ">": d > t, "<": d < t}.get(op, True)
    except Exception:
        return True


def _next_issue_id() -> tuple[str, str]:
    existing = [int(i["id"]) for i in _issues.values()]
    new_id = str(max(existing, default=10000) + 1)
    return new_id, new_id


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/rest/api/3/oauth2/token")
async def get_token(body: dict = Body(default={})):
    """OAuth2 token endpoint."""
    return {
        "access_token": f"jira-sim-{uuid.uuid4().hex[:32]}",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "read:jira-work write:jira-work manage:jira-project",
    }


@router.get("/rest/api/3/myself")
async def get_myself():
    """Get the currently authenticated user."""
    return _USERS["611a2b3c4d5e6f7890abcde1"]


# ─────────────────────────────────────────────────────────────────────────────
# Issues — Search (JQL)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/search")
async def search_issues(
    jql: Optional[str] = Query("", description="JQL query string"),
    startAt: int = Query(0, ge=0),
    maxResults: int = Query(50, ge=1, le=100),
    fields: Optional[str] = Query("*all", description="Comma-separated fields or *all"),
    expand: Optional[str] = Query(None, description="changelog,renderedFields,names,schema,transitions"),
    validateQuery: str = Query("strict", description="strict|warn|none"),
):
    """
    Search issues using JQL.
    GET /rest/api/3/search?jql=project=SEC+AND+status=%22In+Progress%22
    """
    all_issues = list(_issues.values())
    filtered = _jql_filter(jql or "", all_issues)
    total = len(filtered)
    page = filtered[startAt: startAt + maxResults]
    return {
        "startAt": startAt,
        "maxResults": maxResults,
        "total": total,
        "issues": [_build_issue(i) for i in page],
    }


@router.post("/rest/api/3/search")
async def search_issues_post(body: dict = Body(default={})):
    """POST variant of JQL search (for complex queries)."""
    jql = body.get("jql", "")
    start_at = body.get("startAt", 0)
    max_results = body.get("maxResults", 50)
    fields = body.get("fields", ["*all"])

    all_issues = list(_issues.values())
    filtered = _jql_filter(jql, all_issues)
    total = len(filtered)
    page = filtered[start_at: start_at + max_results]
    return {
        "startAt": start_at,
        "maxResults": max_results,
        "total": total,
        "issues": [_build_issue(i) for i in page],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Issues — CRUD
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/issue/{issue_id_or_key}")
async def get_issue(
    issue_id_or_key: str,
    fields: Optional[str] = Query(None),
    expand: Optional[str] = Query(None),
    properties: Optional[str] = Query(None),
    fieldsByKeys: bool = Query(False),
    updateHistory: bool = Query(False),
):
    """Get a single issue by ID or key."""
    # Look up by key
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue does not exist or you do not have permission to see it: {issue_id_or_key}"], "errors": {}})
    return _build_issue(raw)


@router.post("/rest/api/3/issue")
async def create_issue(body: dict = Body(default={})):
    """Create a new issue."""
    fields = body.get("fields", {})
    project_key = fields.get("project", {}).get("key", "SEC")
    proj = next((p for p in _PROJECTS if p["key"] == project_key), _PROJECTS[0])

    # Determine next key number in project
    project_issues = [i for i in _issues.values() if i.get("project_key") == project_key]
    next_num = max((int(i["key"].split("-")[1]) for i in project_issues), default=0) + 1
    key = f"{project_key}-{next_num}"

    new_id, _ = _next_issue_id()
    issue_type_name = fields.get("issuetype", {}).get("name", "Task")
    issue_type = next((t for t in _ISSUE_TYPES if t["name"].lower() == issue_type_name.lower()), _ISSUE_TYPES[1])
    priority_name = fields.get("priority", {}).get("name", "Medium")
    priority = next((p for p in _PRIORITIES if p["name"].lower() == priority_name.lower()), _PRIORITIES[2])

    raw: dict[str, Any] = {
        "id": new_id,
        "key": key,
        "project_key": project_key,
        "issue_type_id": issue_type["id"],
        "summary": fields.get("summary", ""),
        "description": fields.get("description", ""),
        "status_id": "1",   # To Do
        "priority_id": priority["id"],
        "assignee_id": (fields.get("assignee") or {}).get("accountId"),
        "reporter_id": (fields.get("reporter") or {}).get("accountId", "611a2b3c4d5e6f7890abcde1"),
        "labels": fields.get("labels", []),
        "components": [c.get("name") for c in fields.get("components", [])],
        "duedate": fields.get("duedate"),
        "created": _now_iso(),
        "updated": _now_iso(),
        # Security custom fields
        "cve_id": (fields.get("customfield_10100") or {}).get("value") if isinstance(fields.get("customfield_10100"), dict) else fields.get("customfield_10100"),
        "cvss_score": fields.get("customfield_10101"),
        "affected_asset": fields.get("customfield_10102"),
        "severity": fields.get("customfield_10103"),
        "mitre_tactic": fields.get("customfield_10105"),
        "mitre_technique": fields.get("customfield_10106"),
        "soc_ticket_id": fields.get("customfield_10107"),
        "story_points": fields.get("customfield_10001") or fields.get("customfield_10016"),
        "environment": fields.get("environment"),
        "comments": [],
    }
    _issues[new_id] = raw
    _issues_by_key[key] = new_id

    return {
        "id": new_id,
        "key": key,
        "self": f"/rest/api/3/issue/{new_id}",
    }


@router.put("/rest/api/3/issue/{issue_id_or_key}")
async def update_issue(
    issue_id_or_key: str,
    body: dict = Body(default={}),
    notifyUsers: bool = Query(True),
    overrideScreenSecurity: bool = Query(False),
    overrideEditableFlag: bool = Query(False),
):
    """Update an issue (fields or update operations)."""
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue not found: {issue_id_or_key}"], "errors": {}})

    fields = body.get("fields", {})
    update_ops = body.get("update", {})

    # Apply field updates
    if "summary" in fields:
        raw["summary"] = fields["summary"]
    if "description" in fields:
        raw["description"] = fields["description"]
    if "priority" in fields:
        pname = (fields["priority"] or {}).get("name", "Medium")
        p = next((p for p in _PRIORITIES if p["name"].lower() == pname.lower()), None)
        if p:
            raw["priority_id"] = p["id"]
    if "assignee" in fields:
        raw["assignee_id"] = (fields["assignee"] or {}).get("accountId")
    if "labels" in fields:
        raw["labels"] = fields["labels"]
    if "duedate" in fields:
        raw["duedate"] = fields["duedate"]
    if "customfield_10100" in fields:
        raw["cve_id"] = fields["customfield_10100"]
    if "customfield_10101" in fields:
        raw["cvss_score"] = str(fields["customfield_10101"])
    if "customfield_10102" in fields:
        raw["affected_asset"] = fields["customfield_10102"]
    if "customfield_10103" in fields:
        raw["severity"] = fields["customfield_10103"]
    if "customfield_10107" in fields:
        raw["soc_ticket_id"] = fields["customfield_10107"]

    # Apply update operations (e.g., {"labels": [{"add": "new-label"}]})
    for field, ops in update_ops.items():
        if field == "labels":
            for op in ops:
                if "add" in op:
                    raw.setdefault("labels", []).append(op["add"])
                elif "remove" in op and op["remove"] in raw.get("labels", []):
                    raw["labels"].remove(op["remove"])
        if field == "comment":
            for op in ops:
                if "add" in op:
                    raw.setdefault("comments", []).append(_make_comment(raw["id"], op["add"]))

    raw["updated"] = _now_iso()
    return None  # 204


@router.delete("/rest/api/3/issue/{issue_id_or_key}")
async def delete_issue(issue_id_or_key: str, deleteSubtasks: bool = Query(False)):
    """Delete an issue."""
    issue_id = _issues_by_key.pop(issue_id_or_key, issue_id_or_key)
    _issues.pop(issue_id, None)
    return None  # 204


# ─────────────────────────────────────────────────────────────────────────────
# Issue Transitions
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/issue/{issue_id_or_key}/transitions")
async def get_transitions(issue_id_or_key: str, expand: Optional[str] = Query(None)):
    """Get available transitions for an issue."""
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue not found: {issue_id_or_key}"], "errors": {}})
    return {"transitions": _make_transitions(raw.get("status_id", "1"))}


@router.post("/rest/api/3/issue/{issue_id_or_key}/transitions")
async def do_transition(issue_id_or_key: str, body: dict = Body(default={})):
    """Perform a transition on an issue."""
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue not found: {issue_id_or_key}"], "errors": {}})

    transition_id = (body.get("transition") or {}).get("id", "")
    update_fields = body.get("fields", {})
    comment_body = (body.get("update") or {}).get("comment", [{}])[0].get("add") if (body.get("update") or {}).get("comment") else None

    # Apply transition — map transition_id to new status
    transition_status_map = {
        "11": "2",  # Start Progress → In Progress
        "21": "3",  # Send for Review → In Review
        "22": "5",  # Mark as Blocked → Blocked
        "23": "4",  # Done → Done
        "29": "1",  # Back to To Do → To Do
        "31": "4",  # Approve → Done
        "32": "2",  # Request Changes → In Progress
        "41": "1",  # Reopen → To Do
        "51": "2",  # Unblock → In Progress
        "15": "7",  # Won't Do → Won't Do
    }
    new_status = transition_status_map.get(str(transition_id))
    if new_status:
        raw["status_id"] = new_status
        if new_status in ("4", "6", "7"):  # Done states
            raw["resolutiondate"] = _now_iso()
            if "resolution" not in raw:
                raw["resolution"] = update_fields.get("resolution", {}).get("name", "Done")
        raw["updated"] = _now_iso()

    if comment_body:
        raw.setdefault("comments", []).append(_make_comment(raw["id"], comment_body))

    return None  # 204


# ─────────────────────────────────────────────────────────────────────────────
# Comments
# ─────────────────────────────────────────────────────────────────────────────

def _make_comment(issue_id: str, body: Any, author_id: str = "611a2b3c4d5e6f7890abcde1") -> dict:
    cid = _sid()
    return {
        "id": cid,
        "self": f"/rest/api/3/issue/{issue_id}/comment/{cid}",
        "author": _USERS.get(author_id, _USERS["611a2b3c4d5e6f7890abcde1"]),
        "updateAuthor": _USERS.get(author_id, _USERS["611a2b3c4d5e6f7890abcde1"]),
        "body": body if isinstance(body, dict) else {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(body)}]}]},
        "created": _now_iso(),
        "updated": _now_iso(),
        "visibility": None,
        "renderedBody": str(body) if isinstance(body, str) else "",
    }


@router.get("/rest/api/3/issue/{issue_id_or_key}/comment")
async def list_comments(
    issue_id_or_key: str,
    startAt: int = Query(0),
    maxResults: int = Query(5000),
    orderBy: Optional[str] = Query(None),
    expand: Optional[str] = Query(None),
):
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue not found: {issue_id_or_key}"], "errors": {}})
    comments = raw.get("comments", [])
    return {
        "startAt": startAt,
        "maxResults": maxResults,
        "total": len(comments),
        "comments": comments[startAt: startAt + maxResults],
    }


@router.post("/rest/api/3/issue/{issue_id_or_key}/comment")
async def add_comment(
    issue_id_or_key: str,
    body: dict = Body(default={}),
    expand: Optional[str] = Query(None),
):
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": [f"Issue not found: {issue_id_or_key}"], "errors": {}})

    comment = _make_comment(issue_id, body.get("body", ""))
    if body.get("visibility"):
        comment["visibility"] = body["visibility"]
    raw.setdefault("comments", []).append(comment)
    raw["updated"] = _now_iso()
    return comment


@router.put("/rest/api/3/issue/{issue_id_or_key}/comment/{comment_id}")
async def update_comment(issue_id_or_key: str, comment_id: str, body: dict = Body(default={})):
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": ["Issue not found"], "errors": {}})
    for c in raw.get("comments", []):
        if c["id"] == comment_id:
            c["body"] = body.get("body", c["body"])
            c["updated"] = _now_iso()
            return c
    raise HTTPException(404, {"errorMessages": ["Comment not found"], "errors": {}})


@router.delete("/rest/api/3/issue/{issue_id_or_key}/comment/{comment_id}")
async def delete_comment(issue_id_or_key: str, comment_id: str):
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id, {})
    raw["comments"] = [c for c in raw.get("comments", []) if c["id"] != comment_id]
    return None  # 204


# ─────────────────────────────────────────────────────────────────────────────
# Worklogs
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/rest/api/3/issue/{issue_id_or_key}/worklog")
async def add_worklog(
    issue_id_or_key: str,
    body: dict = Body(default={}),
    notifyUsers: bool = Query(True),
    adjustEstimate: str = Query("auto", description="auto|new|manual|leave"),
):
    issue_id = _issues_by_key.get(issue_id_or_key) or issue_id_or_key
    raw = _issues.get(issue_id)
    if not raw:
        raise HTTPException(404, {"errorMessages": ["Issue not found"], "errors": {}})

    wid = _sid()
    worklog = {
        "id": wid,
        "self": f"/rest/api/3/issue/{issue_id}/worklog/{wid}",
        "author": _USERS["611a2b3c4d5e6f7890abcde1"],
        "updateAuthor": _USERS["611a2b3c4d5e6f7890abcde1"],
        "comment": body.get("comment", ""),
        "created": _now_iso(),
        "updated": _now_iso(),
        "started": body.get("started", _now_iso()),
        "timeSpent": body.get("timeSpent", "1h"),
        "timeSpentSeconds": body.get("timeSpentSeconds", 3600),
    }
    raw.setdefault("worklogs", []).append(worklog)
    raw["updated"] = _now_iso()
    return worklog


# ─────────────────────────────────────────────────────────────────────────────
# Issue Links
# ─────────────────────────────────────────────────────────────────────────────

_LINK_TYPES = [
    {"id": "10000", "name": "Blocks", "inward": "is blocked by", "outward": "blocks", "self": "/rest/api/3/issueLinkType/10000"},
    {"id": "10001", "name": "Clones", "inward": "is cloned by", "outward": "clones", "self": "/rest/api/3/issueLinkType/10001"},
    {"id": "10002", "name": "Relates", "inward": "relates to", "outward": "relates to", "self": "/rest/api/3/issueLinkType/10002"},
    {"id": "10003", "name": "Duplicate", "inward": "is duplicated by", "outward": "duplicates", "self": "/rest/api/3/issueLinkType/10003"},
    {"id": "10004", "name": "Caused by", "inward": "is caused by", "outward": "caused", "self": "/rest/api/3/issueLinkType/10004"},
]


@router.post("/rest/api/3/issueLink")
async def create_issue_link(body: dict = Body(default={})):
    """Create a link between two issues."""
    return None  # 201 with empty body


@router.get("/rest/api/3/issueLinkType")
async def get_link_types():
    return {"issueLinkTypes": _LINK_TYPES}


# ─────────────────────────────────────────────────────────────────────────────
# Projects
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/project")
async def list_projects(
    startAt: int = Query(0),
    maxResults: int = Query(50),
    orderBy: str = Query("name"),
    query: Optional[str] = Query(None),
    typeKey: Optional[str] = Query(None),
    expand: Optional[str] = Query(None),
):
    projects = _PROJECTS
    if query:
        projects = [p for p in projects if query.lower() in p["name"].lower() or query.lower() in p["key"].lower()]
    if typeKey:
        projects = [p for p in projects if p["projectTypeKey"] == typeKey]
    return projects[startAt: startAt + maxResults]


@router.get("/rest/api/3/project/{project_key_or_id}")
async def get_project(project_key_or_id: str, expand: Optional[str] = Query(None)):
    p = next((p for p in _PROJECTS if p["key"] == project_key_or_id or p["id"] == project_key_or_id), None)
    if not p:
        raise HTTPException(404, {"errorMessages": [f"No project could be found with key '{project_key_or_id}'."], "errors": {}})
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Metadata endpoints (priorities, statuses, issue types, fields)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/priority")
async def list_priorities():
    return _PRIORITIES


@router.get("/rest/api/3/status")
async def list_statuses():
    return _STATUSES


@router.get("/rest/api/3/issuetype")
async def list_issue_types():
    return _ISSUE_TYPES


@router.get("/rest/api/3/field")
async def list_fields():
    """Return field metadata including security custom fields."""
    base = [
        {"id": "summary", "name": "Summary", "schema": {"type": "string"}},
        {"id": "description", "name": "Description", "schema": {"type": "doc"}},
        {"id": "status", "name": "Status", "schema": {"type": "status"}},
        {"id": "priority", "name": "Priority", "schema": {"type": "priority"}},
        {"id": "issuetype", "name": "Issue Type", "schema": {"type": "issuetype"}},
        {"id": "assignee", "name": "Assignee", "schema": {"type": "user"}},
        {"id": "reporter", "name": "Reporter", "schema": {"type": "user"}},
        {"id": "labels", "name": "Labels", "schema": {"type": "array", "items": "string"}},
        {"id": "components", "name": "Components", "schema": {"type": "array", "items": "component"}},
        {"id": "duedate", "name": "Due Date", "schema": {"type": "date"}},
        {"id": "customfield_10001", "name": "Story Points", "custom": True, "schema": {"type": "number"}},
        {"id": "customfield_10100", "name": "CVE ID", "custom": True, "schema": {"type": "string"}},
        {"id": "customfield_10101", "name": "CVSS Score", "custom": True, "schema": {"type": "number"}},
        {"id": "customfield_10102", "name": "Affected Asset", "custom": True, "schema": {"type": "string"}},
        {"id": "customfield_10103", "name": "Severity", "custom": True, "schema": {"type": "option"}},
        {"id": "customfield_10104", "name": "Attack Vector", "custom": True, "schema": {"type": "string"}},
        {"id": "customfield_10105", "name": "MITRE Tactic", "custom": True, "schema": {"type": "string"}},
        {"id": "customfield_10106", "name": "MITRE Technique", "custom": True, "schema": {"type": "string"}},
        {"id": "customfield_10107", "name": "SOC Ticket ID", "custom": True, "schema": {"type": "string"}},
    ]
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Users
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/user")
async def get_user(accountId: Optional[str] = Query(None), username: Optional[str] = Query(None)):
    if accountId:
        u = _USERS.get(accountId)
        if not u:
            raise HTTPException(404, {"errorMessages": ["User not found"], "errors": {}})
        return u
    return list(_USERS.values())[0]


@router.get("/rest/api/3/user/search")
async def search_users(
    query: Optional[str] = Query(None),
    accountId: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    startAt: int = Query(0),
    maxResults: int = Query(50),
):
    users = list(_USERS.values())
    if query:
        users = [u for u in users if query.lower() in u["displayName"].lower() or query.lower() in u["emailAddress"].lower()]
    return users[startAt: startAt + maxResults]


@router.get("/rest/api/3/groupuserpicker")
async def group_user_picker(query: str = Query(""), maxResults: int = Query(8)):
    users = [u for u in _USERS.values() if query.lower() in u["displayName"].lower() or not query]
    return {"users": {"users": users[:maxResults], "total": len(users), "header": f"Showing {min(len(users), maxResults)} of {len(users)} matching users"}, "groups": {"header": "Showing 0 of 0 matching groups", "total": 0, "groups": []}}


# ─────────────────────────────────────────────────────────────────────────────
# Agile API — Boards and Sprints
# ─────────────────────────────────────────────────────────────────────────────

_BOARDS: list[dict] = [
    {"id": 1, "name": "Security Operations Board", "type": "scrum", "self": "/rest/agile/1.0/board/1", "location": {"projectKey": "SEC", "projectName": "Security Operations"}},
    {"id": 2, "name": "IT Operations Board", "type": "kanban", "self": "/rest/agile/1.0/board/2", "location": {"projectKey": "IT", "projectName": "IT Operations"}},
]

_SPRINTS: list[dict] = [
    {"id": 1, "state": "active", "name": "Sprint 24 — Q3 Security", "startDate": "2026-07-14T00:00:00.000Z", "endDate": "2026-07-28T00:00:00.000Z", "boardId": 1, "goal": "Close all critical CVEs and incident tickets"},
    {"id": 2, "state": "future", "name": "Sprint 25 — Q3 Security", "startDate": "2026-07-28T00:00:00.000Z", "endDate": "2026-08-11T00:00:00.000Z", "boardId": 1, "goal": ""},
]


@router.get("/rest/agile/1.0/board")
async def list_boards(
    startAt: int = Query(0),
    maxResults: int = Query(50),
    type: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    projectKeyOrId: Optional[str] = Query(None),
):
    boards = _BOARDS
    if type:
        boards = [b for b in boards if b["type"] == type]
    if name:
        boards = [b for b in boards if name.lower() in b["name"].lower()]
    if projectKeyOrId:
        boards = [b for b in boards if b["location"].get("projectKey") == projectKeyOrId]
    page = boards[startAt: startAt + maxResults]
    return {"startAt": startAt, "maxResults": maxResults, "total": len(boards), "values": page}


@router.get("/rest/agile/1.0/board/{board_id}")
async def get_board(board_id: int):
    b = next((b for b in _BOARDS if b["id"] == board_id), None)
    if not b:
        raise HTTPException(404, {"errorMessages": [f"Board {board_id} not found"]})
    return b


@router.get("/rest/agile/1.0/board/{board_id}/sprint")
async def list_sprints(
    board_id: int,
    state: Optional[str] = Query(None, description="active,closed,future"),
    startAt: int = Query(0),
    maxResults: int = Query(50),
):
    sprints = [s for s in _SPRINTS if s["boardId"] == board_id]
    if state:
        valid_states = [s.strip() for s in state.split(",")]
        sprints = [s for s in sprints if s["state"] in valid_states]
    return {"startAt": startAt, "maxResults": maxResults, "total": len(sprints), "values": sprints[startAt: startAt + maxResults]}


@router.get("/rest/agile/1.0/board/{board_id}/issue")
async def get_board_issues(
    board_id: int,
    jql: Optional[str] = Query(None),
    startAt: int = Query(0),
    maxResults: int = Query(50),
    fields: Optional[str] = Query(None),
):
    board = next((b for b in _BOARDS if b["id"] == board_id), None)
    if not board:
        raise HTTPException(404, {"errorMessages": [f"Board {board_id} not found"]})
    project_key = board["location"].get("projectKey")
    all_issues = [i for i in _issues.values() if i.get("project_key") == project_key]
    if jql:
        all_issues = _jql_filter(jql, all_issues)
    return {"startAt": startAt, "maxResults": maxResults, "total": len(all_issues), "issues": [_build_issue(i) for i in all_issues[startAt: startAt + maxResults]]}


@router.get("/rest/agile/1.0/sprint/{sprint_id}/issue")
async def get_sprint_issues(sprint_id: int, startAt: int = Query(0), maxResults: int = Query(50)):
    sprint = next((s for s in _SPRINTS if s["id"] == sprint_id), None)
    if not sprint:
        raise HTTPException(404, {"errorMessages": [f"Sprint {sprint_id} not found"]})
    # Return all issues in the sprint's board's project
    board = next((b for b in _BOARDS if b["id"] == sprint["boardId"]), None)
    project_key = board["location"].get("projectKey") if board else "SEC"
    all_issues = [i for i in _issues.values() if i.get("project_key") == project_key]
    return {"startAt": startAt, "maxResults": maxResults, "total": len(all_issues), "issues": [_build_issue(i) for i in all_issues[startAt: startAt + maxResults]]}


# ─────────────────────────────────────────────────────────────────────────────
# Service Management API (JSM)
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_DESKS: list[dict] = [
    {"id": "1", "projectId": "10002", "projectKey": "IT", "projectName": "IT Operations", "description": "IT Support Portal"},
]

_REQUEST_TYPES: list[dict] = [
    {"id": "1", "name": "Get IT help", "description": "General IT support request", "serviceDeskId": "1", "issueTypeId": "1"},
    {"id": "2", "name": "Report a security incident", "description": "Report a suspected security incident", "serviceDeskId": "1", "issueTypeId": "6"},
    {"id": "3", "name": "Request access", "description": "Request access to a system or application", "serviceDeskId": "1", "issueTypeId": "2"},
    {"id": "4", "name": "Password reset", "description": "Request a password reset", "serviceDeskId": "1", "issueTypeId": "2"},
]


@router.get("/rest/servicedeskapi/servicedesk")
async def list_service_desks(start: int = Query(0), limit: int = Query(50)):
    return {"start": start, "limit": limit, "isLastPage": True, "size": len(_SERVICE_DESKS), "values": _SERVICE_DESKS}


@router.get("/rest/servicedeskapi/servicedesk/{service_desk_id}")
async def get_service_desk(service_desk_id: str):
    sd = next((s for s in _SERVICE_DESKS if s["id"] == service_desk_id), None)
    if not sd:
        raise HTTPException(404, {"errorMessage": f"Service desk {service_desk_id} not found"})
    return sd


@router.get("/rest/servicedeskapi/servicedesk/{service_desk_id}/requesttype")
async def list_request_types(service_desk_id: str, start: int = Query(0), limit: int = Query(50)):
    rts = [r for r in _REQUEST_TYPES if r["serviceDeskId"] == service_desk_id]
    return {"start": start, "limit": limit, "isLastPage": True, "size": len(rts), "values": rts[start: start + limit]}


@router.post("/rest/servicedeskapi/request")
async def create_service_request(body: dict = Body(default={})):
    """Create a JSM service request."""
    service_desk_id = body.get("serviceDeskId", "1")
    request_type_id = body.get("requestTypeId", "1")
    fields = body.get("requestFieldValues", {})

    rt = next((r for r in _REQUEST_TYPES if r["id"] == str(request_type_id)), _REQUEST_TYPES[0])
    summary = fields.get("summary", "New service request")

    # Create underlying issue
    create_body = {
        "fields": {
            "project": {"key": "IT"},
            "issuetype": {"name": "Service Request"},
            "summary": summary,
            "description": fields.get("description", ""),
        }
    }
    issue_resp = await create_issue(create_body)

    return {
        "_links": {
            "jiraRest": f"/rest/api/3/issue/{issue_resp['id']}",
            "web": f"/servicedesk/customer/portal/1/{issue_resp['key']}",
            "self": f"/rest/servicedeskapi/request/{issue_resp['id']}",
        },
        "issueId": issue_resp["id"],
        "issueKey": issue_resp["key"],
        "requestTypeId": request_type_id,
        "serviceDeskId": service_desk_id,
        "createdDate": {"epochMillis": 1700000000000, "friendly": "Just now", "iso8601": _now_iso()},
        "reporter": _USERS["611a2b3c4d5e6f7890abcde1"],
        "currentStatus": {"status": "Waiting for support", "statusCategory": "NEW", "statusDate": {"epochMillis": 1700000000000, "iso8601": _now_iso()}},
        "requestFieldValues": [{"fieldId": k, "label": k, "value": v} for k, v in fields.items()],
        "reporter": _USERS["611a2b3c4d5e6f7890abcde1"],
    }


@router.get("/rest/servicedeskapi/request")
async def list_service_requests(start: int = Query(0), limit: int = Query(50), requestOwnership: Optional[str] = Query(None)):
    all_it_issues = [i for i in _issues.values() if i.get("project_key") == "IT"]
    return {"start": start, "limit": limit, "isLastPage": True, "size": len(all_it_issues), "values": [_build_issue(i) for i in all_it_issues[start: start + limit]]}


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rest/api/3/serverInfo")
async def server_info():
    return {
        "baseUrl": "http://purplelab-jira.corp.local",
        "version": "9.12.0",
        "versionNumbers": [9, 12, 0],
        "deploymentType": "Cloud",
        "buildNumber": 901200,
        "buildDate": "2026-01-15T00:00:00.000+0000",
        "serverTitle": "PurpleLab Jira Simulation",
        "scmInfo": "JIRA-SIM",
        "serverTime": _now_iso(),
    }
