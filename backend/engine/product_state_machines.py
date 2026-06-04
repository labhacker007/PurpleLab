"""Product State Machines — Identity, Firewall, and SIEM.

Tracks per-entity lifecycle states across all three product tiers, firing
secondary log events at each transition so detection rules and correlation
engines have realistic state-change telemetry to work with.

Each machine is per-session and can be queried via the REST API to show the
current state of every entity the simulation has touched.

Identity state graph (per user)
--------------------------------
    active ──(suspicious_auth)──▶ suspicious
    suspicious ──(lockout_triggered)──▶ locked_out
    locked_out ──(admin_disabled)──▶ disabled
    disabled ──(account_remediated)──▶ remediated
    remediated ──(account_restored)──▶ active

Firewall state graph (per remote IP)
--------------------------------------
    allowed ──(policy_violation)──▶ monitored
    monitored ──(confirmed_c2)──▶ blocked
    blocked ──(quarantine_scope)──▶ quarantined

SIEM correlation state graph (per session)
-------------------------------------------
    ingesting ──(rule_match_count >= threshold)──▶ correlating
    correlating ──(correlation_score >= 0.7)──▶ alert_raised
    alert_raised ──(analyst_assigned)──▶ case_created
    case_created ──(case_closed)──▶ closed
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Identity state machine
# ────────────────────────────────────────────────────────────────────────────

class IdentityState(str, Enum):
    ACTIVE      = "active"
    SUSPICIOUS  = "suspicious"
    LOCKED_OUT  = "locked_out"
    DISABLED    = "disabled"
    REMEDIATED  = "remediated"


_IDENTITY_TRANSITIONS: dict[IdentityState, dict[str, IdentityState]] = {
    IdentityState.ACTIVE: {
        "suspicious_auth":  IdentityState.SUSPICIOUS,
        "mfa_anomaly":      IdentityState.SUSPICIOUS,
        "password_spray":   IdentityState.SUSPICIOUS,
    },
    IdentityState.SUSPICIOUS: {
        "lockout_triggered": IdentityState.LOCKED_OUT,
        "false_positive":    IdentityState.ACTIVE,
    },
    IdentityState.LOCKED_OUT: {
        "admin_disabled": IdentityState.DISABLED,
        "admin_unlocked": IdentityState.ACTIVE,
    },
    IdentityState.DISABLED: {
        "account_remediated": IdentityState.REMEDIATED,
    },
    IdentityState.REMEDIATED: {
        "account_restored": IdentityState.ACTIVE,
    },
}

# Technique-to-trigger map for identity
_IDENTITY_TECHNIQUE_TRIGGERS: dict[str, str] = {
    "T1078":     "suspicious_auth",
    "T1078.001": "suspicious_auth",
    "T1078.002": "suspicious_auth",
    "T1110":     "password_spray",
    "T1110.003": "password_spray",
    "T1110.001": "password_spray",
    "T1621":     "mfa_anomaly",
    "T1556":     "suspicious_auth",
}

_IDENTITY_HIGH_FIDELITY_SOURCES = {"auth", "okta", "okta_identity", "entra_id"}


def _make_identity_alert(username: str, email: str, technique_id: str, state: IdentityState) -> dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat()
    title_map = {
        IdentityState.SUSPICIOUS:  f"Suspicious authentication for {username}",
        IdentityState.LOCKED_OUT:  f"Account locked out: {username}",
        IdentityState.DISABLED:    f"Account disabled by policy: {username}",
        IdentityState.REMEDIATED:  f"Account remediated: {username}",
    }
    sev_map = {
        IdentityState.SUSPICIOUS:  "medium",
        IdentityState.LOCKED_OUT:  "high",
        IdentityState.DISABLED:    "high",
        IdentityState.REMEDIATED:  "info",
    }
    return {
        "source_type": "okta",
        "technique_id": technique_id,
        "severity": sev_map.get(state, "medium"),
        "title": title_map.get(state, f"Identity state change: {username} → {state.value}"),
        "timestamp": ts,
        "_state_transition": True,
        "_new_state": state.value,
        "payload": {
            "eventType": "user.account.lock" if state == IdentityState.LOCKED_OUT else "user.session.start",
            "actor.alternateId": email or username,
            "actor.displayName": username,
            "outcome.result": "FAILURE" if state in (IdentityState.SUSPICIOUS, IdentityState.LOCKED_OUT) else "SUCCESS",
            "displayMessage": title_map.get(state, ""),
            "published": ts,
            "_technique": technique_id,
        },
    }


class IdentityStateMachine:
    """Per-session identity state tracker keyed by username."""

    def __init__(self) -> None:
        self._states: dict[str, IdentityState] = {}

    def get_state(self, username: str) -> IdentityState:
        return self._states.get(username, IdentityState.ACTIVE)

    def set_state(self, username: str, state: IdentityState) -> None:
        self._states[username] = state

    def snapshot(self) -> dict[str, str]:
        return {u: s.value for u, s in self._states.items()}

    def process_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("_benign") or event.get("_state_transition"):
            return []

        technique_id = event.get("technique_id") or event.get("_technique") or ""
        source_type = event.get("source_type", "")
        payload = event.get("payload") or {}

        username = (
            payload.get("actor.alternateId")
            or payload.get("SubjectUserName")
            or payload.get("UserName")
            or payload.get("user")
            or ""
        )
        if not username:
            return []

        email = payload.get("actor.alternateId") or username

        if source_type in _IDENTITY_HIGH_FIDELITY_SOURCES:
            trigger = "suspicious_auth"
        else:
            trigger = _IDENTITY_TECHNIQUE_TRIGGERS.get(technique_id, "")
            if not trigger and "." in technique_id:
                trigger = _IDENTITY_TECHNIQUE_TRIGGERS.get(technique_id.split(".")[0], "")

        if not trigger:
            return []

        current = self.get_state(username)
        next_state = _IDENTITY_TRANSITIONS.get(current, {}).get(trigger)
        if next_state is None:
            return []

        self._states[username] = next_state
        log.debug("Identity state: %s %s → %s (trigger=%s)", username, current.value, next_state.value, trigger)

        secondary = [_make_identity_alert(username, email, technique_id, next_state)]

        # Escalate to lockout if already suspicious and high-severity
        if next_state == IdentityState.SUSPICIOUS and event.get("severity") in ("high", "critical"):
            lock_state = _IDENTITY_TRANSITIONS.get(IdentityState.SUSPICIOUS, {}).get("lockout_triggered")
            if lock_state:
                self._states[username] = lock_state
                secondary.append(_make_identity_alert(username, email, technique_id, lock_state))

        return secondary


# ────────────────────────────────────────────────────────────────────────────
# Firewall state machine
# ────────────────────────────────────────────────────────────────────────────

class FirewallState(str, Enum):
    ALLOWED     = "allowed"
    MONITORED   = "monitored"
    BLOCKED     = "blocked"
    QUARANTINED = "quarantined"


_FIREWALL_TRANSITIONS: dict[FirewallState, dict[str, FirewallState]] = {
    FirewallState.ALLOWED: {
        "policy_violation": FirewallState.MONITORED,
        "port_scan":        FirewallState.MONITORED,
    },
    FirewallState.MONITORED: {
        "confirmed_c2":     FirewallState.BLOCKED,
        "threshold_hit":    FirewallState.BLOCKED,
    },
    FirewallState.BLOCKED: {
        "quarantine_scope": FirewallState.QUARANTINED,
    },
}

_FIREWALL_TECHNIQUE_TRIGGERS: dict[str, str] = {
    "T1046":     "port_scan",
    "T1071":     "policy_violation",
    "T1071.001": "policy_violation",
    "T1071.004": "policy_violation",
    "T1041":     "confirmed_c2",
    "T1048":     "confirmed_c2",
    "T1572":     "confirmed_c2",
    "T1095":     "policy_violation",
}

_FIREWALL_HIGH_FIDELITY_SOURCES = {"firewall", "palo_alto", "network"}


def _make_firewall_alert(remote_ip: str, technique_id: str, state: FirewallState) -> dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat()
    title_map = {
        FirewallState.MONITORED:   f"Traffic from {remote_ip} flagged for monitoring",
        FirewallState.BLOCKED:     f"IP {remote_ip} blocked at perimeter (C2 traffic)",
        FirewallState.QUARANTINED: f"IP {remote_ip} quarantined — all traffic denied",
    }
    return {
        "source_type": "palo_alto",
        "technique_id": technique_id,
        "severity": "high" if state in (FirewallState.BLOCKED, FirewallState.QUARANTINED) else "medium",
        "title": title_map.get(state, f"Firewall state: {remote_ip} → {state.value}"),
        "timestamp": ts,
        "_state_transition": True,
        "_new_state": state.value,
        "payload": {
            "src": remote_ip,
            "action": "deny" if state in (FirewallState.BLOCKED, FirewallState.QUARANTINED) else "monitor",
            "type": "THREAT",
            "subtype": "c2" if state == FirewallState.BLOCKED else "scan",
            "severity": "high" if state in (FirewallState.BLOCKED, FirewallState.QUARANTINED) else "medium",
            "receive_time": ts,
            "_technique": technique_id,
        },
    }


class FirewallStateMachine:
    """Per-session firewall state tracker keyed by remote IP."""

    def __init__(self) -> None:
        self._states: dict[str, FirewallState] = {}

    def get_state(self, remote_ip: str) -> FirewallState:
        return self._states.get(remote_ip, FirewallState.ALLOWED)

    def set_state(self, remote_ip: str, state: FirewallState) -> None:
        self._states[remote_ip] = state

    def snapshot(self) -> dict[str, str]:
        return {ip: s.value for ip, s in self._states.items()}

    def process_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("_benign") or event.get("_state_transition"):
            return []

        technique_id = event.get("technique_id") or event.get("_technique") or ""
        source_type = event.get("source_type", "")
        payload = event.get("payload") or {}

        remote_ip = (
            payload.get("RemoteAddressIP4")
            or payload.get("dst_ip")
            or payload.get("ExternalIP")
            or payload.get("dst")
            or ""
        )
        if not remote_ip or remote_ip.startswith("10.") or remote_ip.startswith("192.168."):
            return []  # Only track external IPs

        if source_type in _FIREWALL_HIGH_FIDELITY_SOURCES:
            trigger = "policy_violation"
        else:
            trigger = _FIREWALL_TECHNIQUE_TRIGGERS.get(technique_id, "")
            if not trigger and "." in technique_id:
                trigger = _FIREWALL_TECHNIQUE_TRIGGERS.get(technique_id.split(".")[0], "")

        if not trigger:
            return []

        current = self.get_state(remote_ip)
        next_state = _FIREWALL_TRANSITIONS.get(current, {}).get(trigger)
        if next_state is None:
            return []

        self._states[remote_ip] = next_state
        log.debug("Firewall state: %s %s → %s (trigger=%s)", remote_ip, current.value, next_state.value, trigger)
        return [_make_firewall_alert(remote_ip, technique_id, next_state)]


# ────────────────────────────────────────────────────────────────────────────
# SIEM correlation state machine
# ────────────────────────────────────────────────────────────────────────────

class SIEMState(str, Enum):
    INGESTING   = "ingesting"
    CORRELATING = "correlating"
    ALERT_RAISED = "alert_raised"
    CASE_CREATED = "case_created"
    CLOSED      = "closed"


_SIEM_RULE_MATCH_THRESHOLD = 3   # N rule hits before SIEM correlation escalates


def _make_siem_alert(session_id: str, technique_id: str, state: SIEMState, match_count: int) -> dict[str, Any]:
    ts = datetime.now(timezone.utc).isoformat()
    title_map = {
        SIEMState.CORRELATING:  f"SIEM: Correlated {match_count} rule matches for {technique_id}",
        SIEMState.ALERT_RAISED: f"SIEM alert raised: {technique_id} campaign detected",
        SIEMState.CASE_CREATED: f"SOAR case created from SIEM alert: {technique_id}",
        SIEMState.CLOSED:       f"SIEM case closed: {technique_id}",
    }
    return {
        "source_type": "siem",
        "technique_id": technique_id,
        "severity": "high" if state in (SIEMState.ALERT_RAISED, SIEMState.CASE_CREATED) else "medium",
        "title": title_map.get(state, f"SIEM state: {state.value}"),
        "timestamp": ts,
        "_state_transition": True,
        "_new_state": state.value,
        "payload": {
            "rule_match_count": match_count,
            "technique_id": technique_id,
            "session_id": session_id,
            "correlation_status": state.value,
            "_technique": technique_id,
        },
    }


class SIEMStateMachine:
    """Per-session SIEM correlation tracker.

    Counts rule matches per technique and escalates the SIEM state when
    the correlation threshold is hit.  The 'session' here is the simulation
    session_id, not a user session.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._state: SIEMState = SIEMState.INGESTING
        self._match_counts: dict[str, int] = {}   # technique_id → hit count

    def get_state(self) -> SIEMState:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": self._state.value,
            "technique_match_counts": dict(self._match_counts),
        }

    def process_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        if event.get("_benign") or event.get("_state_transition"):
            return []

        technique_id = event.get("technique_id") or event.get("_technique") or ""
        if not technique_id:
            return []

        self._match_counts[technique_id] = self._match_counts.get(technique_id, 0) + 1
        count = self._match_counts[technique_id]
        secondary: list[dict[str, Any]] = []

        # Transition logic
        if self._state == SIEMState.INGESTING and count >= _SIEM_RULE_MATCH_THRESHOLD:
            self._state = SIEMState.CORRELATING
            secondary.append(_make_siem_alert(self.session_id, technique_id, SIEMState.CORRELATING, count))

        elif self._state == SIEMState.CORRELATING and count >= _SIEM_RULE_MATCH_THRESHOLD * 2:
            self._state = SIEMState.ALERT_RAISED
            secondary.append(_make_siem_alert(self.session_id, technique_id, SIEMState.ALERT_RAISED, count))

        elif self._state == SIEMState.ALERT_RAISED and event.get("severity") in ("critical", "high"):
            self._state = SIEMState.CASE_CREATED
            secondary.append(_make_siem_alert(self.session_id, technique_id, SIEMState.CASE_CREATED, count))

        return secondary


# ────────────────────────────────────────────────────────────────────────────
# Per-session container
# ────────────────────────────────────────────────────────────────────────────

class ProductStateMachineBundle:
    """Holds all three product state machines for a single session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.identity  = IdentityStateMachine()
        self.firewall  = FirewallStateMachine()
        self.siem      = SIEMStateMachine(session_id)

    def process_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Route event through all three machines and aggregate secondary events."""
        secondary: list[dict[str, Any]] = []
        secondary.extend(self.identity.process_event(event))
        secondary.extend(self.firewall.process_event(event))
        secondary.extend(self.siem.process_event(event))
        return secondary

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "identity": self.identity.snapshot(),
            "firewall": self.firewall.snapshot(),
            "siem": self.siem.snapshot(),
        }


# ── Singleton registry ─────────────────────────────────────────────────────

_bundles: dict[str, ProductStateMachineBundle] = {}


def get_bundle(session_id: str) -> ProductStateMachineBundle:
    if session_id not in _bundles:
        _bundles[session_id] = ProductStateMachineBundle(session_id)
    return _bundles[session_id]


def drop_bundle(session_id: str) -> None:
    _bundles.pop(session_id, None)
