"""EDR Endpoint State Machine.

Models realistic per-endpoint lifecycle transitions driven by simulated events.
Each transition emits one or more secondary log events so Joti's detection rules
can fire on the state change as well as on the original attack event.

State graph
-----------
    online ──(anomaly_detected)──▶ at_risk
    at_risk ──(confirmed_detection)──▶ compromised
    compromised ──(isolation_requested)──▶ isolated
    isolated ──(remediation_complete)──▶ remediated
    remediated ──(reimaged)──▶ online
    online ──(offline_event)──▶ offline
    offline ──(checkin_received)──▶ online

Transition triggers are matched against simulated event technique IDs or
source_types. Transitions are idempotent — calling them when already in the
target state is a no-op.

Secondary events follow vendor-specific formats so they normalise correctly
through the OCSF layer.
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger(__name__)


# ── State definitions ─────────────────────────────────────────────────────────

class EndpointState(str, Enum):
    ONLINE      = "online"
    AT_RISK     = "at_risk"
    COMPROMISED = "compromised"
    ISOLATED    = "isolated"
    REMEDIATED  = "remediated"
    OFFLINE     = "offline"


# Allowed transitions: current_state → {trigger → next_state}
_TRANSITIONS: dict[EndpointState, dict[str, EndpointState]] = {
    EndpointState.ONLINE: {
        "anomaly_detected":  EndpointState.AT_RISK,
        "offline_event":     EndpointState.OFFLINE,
    },
    EndpointState.AT_RISK: {
        "confirmed_detection": EndpointState.COMPROMISED,
        "false_positive":      EndpointState.ONLINE,
    },
    EndpointState.COMPROMISED: {
        "isolation_requested": EndpointState.ISOLATED,
    },
    EndpointState.ISOLATED: {
        "remediation_complete": EndpointState.REMEDIATED,
    },
    EndpointState.REMEDIATED: {
        "reimaged":    EndpointState.ONLINE,
        "reimaged_ok": EndpointState.ONLINE,
    },
    EndpointState.OFFLINE: {
        "checkin_received": EndpointState.ONLINE,
    },
}


# Map technique IDs to triggers (first match wins)
_TECHNIQUE_TRIGGERS: dict[str, str] = {
    "T1059":     "anomaly_detected",
    "T1059.001": "anomaly_detected",
    "T1059.003": "anomaly_detected",
    "T1003":     "confirmed_detection",
    "T1003.001": "confirmed_detection",
    "T1055":     "confirmed_detection",
    "T1055.001": "confirmed_detection",
    "T1078":     "anomaly_detected",
    "T1021":     "anomaly_detected",
    "T1021.001": "anomaly_detected",
    "T1021.002": "anomaly_detected",
    "T1105":     "anomaly_detected",
    "T1547":     "anomaly_detected",
    "T1547.001": "anomaly_detected",
    "T1053.005": "anomaly_detected",
    "T1041":     "confirmed_detection",
    "T1486":     "confirmed_detection",  # Ransomware
}

# Source types that escalate directly to confirmed_detection
_HIGH_FIDELITY_SOURCES = {"edr", "crowdstrike_edr", "crowdstrike"}


# ── Secondary event templates ─────────────────────────────────────────────────

def _make_edr_alert(
    hostname: str,
    ip: str,
    technique_id: str,
    state: EndpointState,
    vendor: str = "crowdstrike",
) -> dict[str, Any]:
    """Build a secondary EDR alert event for a state transition."""
    ts = datetime.now(timezone.utc).isoformat()
    severity_map = {
        EndpointState.AT_RISK:     "medium",
        EndpointState.COMPROMISED: "high",
        EndpointState.ISOLATED:    "high",
        EndpointState.REMEDIATED:  "info",
    }
    sev = severity_map.get(state, "medium")
    title_map = {
        EndpointState.AT_RISK:     f"Anomalous activity detected on {hostname}",
        EndpointState.COMPROMISED: f"Endpoint {hostname} confirmed compromised ({technique_id})",
        EndpointState.ISOLATED:    f"Endpoint {hostname} network-isolated by EDR policy",
        EndpointState.REMEDIATED:  f"Endpoint {hostname} remediated and cleared",
    }
    title = title_map.get(state, f"EDR state change: {hostname} → {state.value}")
    return {
        "source_type": vendor,
        "technique_id": technique_id,
        "severity": sev,
        "title": title,
        "timestamp": ts,
        "_state_transition": True,
        "_new_state": state.value,
        "payload": {
            "event_simpleName": "DetectionSummaryEvent",
            "ComputerName": hostname,
            "LocalIP": ip,
            "TechniqueId": technique_id,
            "SeverityName": sev.capitalize(),
            "StatusIndicator": state.value,
            "Timestamp": ts,
            "DetectName": title,
        },
    }


def _make_windows_event(
    hostname: str,
    technique_id: str,
    state: EndpointState,
) -> dict[str, Any]:
    """Windows Security Event Log entry for the state transition."""
    event_id_map = {
        EndpointState.AT_RISK:     4719,   # System audit policy changed
        EndpointState.COMPROMISED: 4688,   # Process creation (suspicious)
        EndpointState.ISOLATED:    7045,   # New service installed (isolation agent action)
        EndpointState.REMEDIATED:  1102,   # Audit log cleared (post-remediation)
    }
    eid = event_id_map.get(state, 4625)
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "source_type": "windows_eventlog",
        "technique_id": technique_id,
        "severity": "medium" if state in (EndpointState.AT_RISK, EndpointState.REMEDIATED) else "high",
        "title": f"Windows event {eid} on {hostname}",
        "timestamp": ts,
        "_state_transition": True,
        "_new_state": state.value,
        "payload": {
            "EventID": eid,
            "Computer": hostname,
            "SubjectUserName": "SYSTEM",
            "TimeCreated": ts,
            "_technique": technique_id,
        },
    }


# ── State machine class ───────────────────────────────────────────────────────

class EndpointStateMachine:
    """Per-session endpoint state tracker.

    Maintains a dict of hostname → current EndpointState.
    When `process_event()` is called with a simulated event the machine:
    1. Derives the appropriate trigger from the technique_id / source_type
    2. Looks up the valid transition for the current state
    3. If a transition fires, returns secondary log events that represent the EDR
       responding to the compromise
    """

    def __init__(self) -> None:
        # hostname → EndpointState
        self._states: dict[str, EndpointState] = {}

    def get_state(self, hostname: str) -> EndpointState:
        return self._states.get(hostname, EndpointState.ONLINE)

    def set_state(self, hostname: str, state: EndpointState) -> None:
        self._states[hostname] = state

    def snapshot(self) -> dict[str, str]:
        return {h: s.value for h, s in self._states.items()}

    def process_event(
        self,
        event: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Process one simulated event. Returns secondary events generated by state transitions."""
        if event.get("_benign") or event.get("_state_transition"):
            return []

        technique_id: str = event.get("technique_id") or event.get("_technique") or ""
        source_type: str = event.get("source_type", "")
        payload: dict = event.get("payload") or {}

        hostname: str = (
            payload.get("ComputerName")
            or payload.get("Computer")
            or payload.get("hostname")
            or payload.get("device_hostname")
            or ""
        )
        ip: str = (
            payload.get("LocalIP")
            or payload.get("IpAddress")
            or payload.get("src_ip")
            or "10.0.0.0"
        )
        vendor: str = source_type if source_type in _HIGH_FIDELITY_SOURCES else "crowdstrike"

        if not hostname:
            return []

        current = self.get_state(hostname)

        # Derive trigger: high-fidelity sources jump straight to confirmed_detection
        if source_type in _HIGH_FIDELITY_SOURCES:
            trigger = "confirmed_detection"
        else:
            trigger = _TECHNIQUE_TRIGGERS.get(technique_id, "")
            # Parent technique fallback
            if not trigger and "." in technique_id:
                trigger = _TECHNIQUE_TRIGGERS.get(technique_id.split(".")[0], "")

        if not trigger:
            return []

        valid = _TRANSITIONS.get(current, {})
        next_state = valid.get(trigger)
        if next_state is None:
            return []  # Transition not valid from current state

        self._states[hostname] = next_state
        log.debug("EDR state: %s %s → %s (trigger=%s via %s)", hostname, current.value, next_state.value, trigger, technique_id)

        secondary: list[dict[str, Any]] = []

        # EDR alert for every transition
        secondary.append(_make_edr_alert(hostname, ip, technique_id, next_state, vendor))

        # Windows event log for Windows endpoints in the compromised/isolated states
        if next_state in (EndpointState.COMPROMISED, EndpointState.ISOLATED):
            secondary.append(_make_windows_event(hostname, technique_id, next_state))

        # Synthetic isolation action event when auto-isolation fires
        if next_state == EndpointState.ISOLATED:
            secondary.append({
                "source_type": vendor,
                "technique_id": technique_id,
                "severity": "high",
                "title": f"Auto-isolation triggered for {hostname}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_state_transition": True,
                "_new_state": EndpointState.ISOLATED.value,
                "payload": {
                    "event_simpleName": "NetworkContainmentRequest",
                    "ComputerName": hostname,
                    "LocalIP": ip,
                    "TechniqueId": technique_id,
                    "ActionTaken": "network_contain",
                    "Automated": True,
                },
            })

        return secondary


# ── Singleton per-session registry ────────────────────────────────────────────

_machines: dict[str, EndpointStateMachine] = {}


def get_machine(session_id: str) -> EndpointStateMachine:
    """Return (or create) the state machine for a simulation session."""
    if session_id not in _machines:
        _machines[session_id] = EndpointStateMachine()
    return _machines[session_id]


def drop_machine(session_id: str) -> None:
    """Remove the state machine when a session is stopped."""
    _machines.pop(session_id, None)
