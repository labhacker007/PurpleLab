"""SOAR Action Execution Engine.

Central dispatcher for all simulated response actions.
When Joti fires a SOAR playbook step (via vendor API emulation or MCP),
this module:
  1. Executes the action against the running state machines
  2. Generates realistic confirmation events
  3. Writes an audit record to response_actions table
  4. Returns an ActionResult with full details

Supported actions:
  block_ioc          — add IP/domain/hash to firewall/EDR blocklist
  unblock_ioc        — remove from blocklist
  isolate_host       — contain endpoint (EDR state: COMPROMISED → ISOLATED)
  release_host       — lift isolation (ISOLATED → REMEDIATED)
  disable_account    — suspend user (Identity state → DISABLED)
  enable_account     — re-enable user (DISABLED → REMEDIATED)
  reset_password     — expire password + generate reset token
  kill_process       — terminate process + mark in threat graph
  quarantine_file    — isolate file by hash + mark in threat graph
  deploy_detection   — store Sigma/SPL/KQL rule in session SIEM
  inject_alert       — inject a synthetic alert into the session
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel


class ActionResult(BaseModel):
    success: bool
    action_type: str
    target: str = ""
    session_id: str = ""
    message: str = ""
    state_before: str = ""
    state_after: str = ""
    event_ids: list[str] = []
    timestamp: str = ""
    details: dict = {}

    def dict(self, **kwargs) -> dict:
        return {
            "success": self.success,
            "action_type": self.action_type,
            "target": self.target,
            "session_id": self.session_id,
            "message": self.message,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "event_ids": self.event_ids,
            "timestamp": self.timestamp,
            "details": self.details,
        }


async def execute_action(
    session_id: str,
    action_type: str,
    params: dict[str, Any],
) -> ActionResult:
    """Dispatch a SOAR action and return the result."""
    ts = datetime.now(timezone.utc).isoformat()
    actor = params.get("actor", "system")

    handler = _HANDLERS.get(action_type)
    if not handler:
        return ActionResult(
            success=False,
            action_type=action_type,
            target=params.get("hostname") or params.get("ioc_value") or "",
            session_id=session_id,
            message=f"Unknown action type: {action_type}",
            timestamp=ts,
        )

    try:
        result = await handler(session_id, params)
        result.timestamp = ts
        # Persist audit record
        await _persist_action(session_id, action_type, actor, result, params)
        return result
    except Exception as exc:
        return ActionResult(
            success=False,
            action_type=action_type,
            target=params.get("hostname") or params.get("ioc_value") or "",
            session_id=session_id,
            message=f"Action failed: {exc}",
            timestamp=ts,
        )


# ── Individual action handlers ─────────────────────────────────────────────────

async def _isolate_host(session_id: str, params: dict) -> ActionResult:
    hostname = params.get("hostname", "")
    from backend.engine.edr_state_machine import get_machine, EndpointState
    machine = get_machine(session_id)
    state_before = machine.get_state(hostname).value
    machine.set_state(hostname, EndpointState.ISOLATED)
    state_after = EndpointState.ISOLATED.value

    # Generate CrowdStrike-format isolation confirmation event
    event_id = await _store_event(session_id, "edr", "high", hostname, {
        "event_title": f"Host isolation initiated: {hostname}",
        "ComputerName": hostname,
        "action_taken": "contained",
        "containment_status": "contained",
        "_action": "isolate_host",
        "_actor": params.get("actor", "joti_soar"),
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="isolate_host",
        target=hostname,
        session_id=session_id,
        message=f"{hostname} isolated successfully",
        state_before=state_before,
        state_after=state_after,
        event_ids=[event_id],
    )


async def _release_host(session_id: str, params: dict) -> ActionResult:
    hostname = params.get("hostname", "")
    from backend.engine.edr_state_machine import get_machine, EndpointState
    machine = get_machine(session_id)
    state_before = machine.get_state(hostname).value
    machine.set_state(hostname, EndpointState.REMEDIATED)

    event_id = await _store_event(session_id, "edr", "info", hostname, {
        "event_title": f"Host isolation lifted: {hostname}",
        "ComputerName": hostname,
        "action_taken": "released",
        "containment_status": "normal",
        "_action": "release_host",
        "_actor": params.get("actor", "joti_soar"),
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="release_host",
        target=hostname,
        session_id=session_id,
        message=f"{hostname} released from isolation",
        state_before=state_before,
        state_after="remediated",
        event_ids=[event_id],
    )


async def _disable_account(session_id: str, params: dict) -> ActionResult:
    username = params.get("username") or params.get("user", "")
    from backend.engine.product_state_machines import get_bundle, IdentityState
    bundle = get_bundle(session_id)
    state_before = bundle.identity.get_state(username).value
    bundle.identity.set_state(username, IdentityState.DISABLED)

    event_id = await _store_event(session_id, "okta", "high", username, {
        "event_title": f"User account disabled: {username}",
        "displayMessage": f"Account disabled by security response",
        "eventType": "user.lifecycle.deactivate",
        "actor.alternateId": params.get("actor", "joti_soar"),
        "target[0].alternateId": username,
        "outcome.result": "SUCCESS",
        "_action": "disable_account",
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="disable_account",
        target=username,
        session_id=session_id,
        message=f"Account {username} disabled",
        state_before=state_before,
        state_after="disabled",
        event_ids=[event_id],
    )


async def _enable_account(session_id: str, params: dict) -> ActionResult:
    username = params.get("username") or params.get("user", "")
    from backend.engine.product_state_machines import get_bundle, IdentityState
    bundle = get_bundle(session_id)
    bundle.identity.set_state(username, IdentityState.REMEDIATED)

    event_id = await _store_event(session_id, "okta", "info", username, {
        "event_title": f"User account re-enabled: {username}",
        "eventType": "user.lifecycle.activate",
        "target[0].alternateId": username,
        "outcome.result": "SUCCESS",
        "_action": "enable_account",
        "_type": "response_action",
    })
    return ActionResult(success=True, action_type="enable_account", target=username,
                        session_id=session_id, message=f"Account {username} enabled", event_ids=[event_id])


async def _reset_password(session_id: str, params: dict) -> ActionResult:
    username = params.get("username") or params.get("user", "")
    reset_token = uuid.uuid4().hex[:32]

    event_id = await _store_event(session_id, "okta", "medium", username, {
        "event_title": f"Password reset initiated for: {username}",
        "eventType": "user.account.reset_password",
        "target[0].alternateId": username,
        "outcome.result": "SUCCESS",
        "_action": "reset_password",
        "_reset_token": reset_token,
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="reset_password",
        target=username,
        session_id=session_id,
        message=f"Password reset sent to {username}",
        event_ids=[event_id],
        details={"reset_token": reset_token[:8] + "..."},
    )


async def _block_ioc(session_id: str, params: dict) -> ActionResult:
    ioc_type = params.get("ioc_type", "ip")
    ioc_value = params.get("ioc_value", "")

    # Firewall state machine: if it's an IP, trigger BLOCKED transition
    if ioc_type in ("ip", "ipv4", "ipv6"):
        from backend.engine.product_state_machines import get_bundle, FirewallState
        bundle = get_bundle(session_id)
        bundle.firewall.set_state(ioc_value, FirewallState.BLOCKED)
        source = "firewall"
    else:
        source = "edr"

    event_id = await _store_event(session_id, source, "medium", ioc_value, {
        "event_title": f"IOC blocked: {ioc_type}={ioc_value}",
        "action": "block",
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "rule": f"SOAR_BLOCK_{ioc_type.upper()}",
        "_action": "block_ioc",
        "_actor": params.get("actor", "joti_soar"),
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="block_ioc",
        target=ioc_value,
        session_id=session_id,
        message=f"IOC {ioc_type}={ioc_value} blocked",
        state_after="blocked",
        event_ids=[event_id],
        details={"ioc_type": ioc_type, "ioc_value": ioc_value},
    )


async def _unblock_ioc(session_id: str, params: dict) -> ActionResult:
    ioc_value = params.get("ioc_value", "")
    if params.get("ioc_type", "ip") in ("ip", "ipv4"):
        from backend.engine.product_state_machines import get_bundle, FirewallState
        bundle = get_bundle(session_id)
        bundle.firewall.set_state(ioc_value, FirewallState.ALLOWED)
    event_id = await _store_event(session_id, "firewall", "info", ioc_value, {
        "event_title": f"IOC unblocked: {ioc_value}",
        "_action": "unblock_ioc",
        "_type": "response_action",
    })
    return ActionResult(success=True, action_type="unblock_ioc", target=ioc_value,
                        session_id=session_id, message=f"IOC {ioc_value} unblocked", event_ids=[event_id])


async def _kill_process(session_id: str, params: dict) -> ActionResult:
    process_name = params.get("process_name", "")
    hostname = params.get("hostname", "")
    pid = params.get("pid", "")

    event_id = await _store_event(session_id, "edr", "medium", hostname, {
        "event_title": f"Process terminated: {process_name} on {hostname}",
        "FileName": process_name,
        "ComputerName": hostname,
        "ProcessId": str(pid),
        "action_taken": "killed",
        "_action": "kill_process",
        "_actor": params.get("actor", "joti_soar"),
        "_type": "response_action",
    })

    # Mark in threat graph
    try:
        from backend.engine.threat_graph import get_graph
        graph = get_graph(session_id)
        for node_id, node in list(graph.nodes.items()):
            if node.node_type == "process" and (
                process_name.lower() in (node.label or "").lower()
                or (hostname and hostname.lower() in (node.label or "").lower())
            ):
                node.attrs["terminated"] = True
                node.attrs["terminated_by"] = params.get("actor", "joti_soar")
    except Exception:
        pass

    return ActionResult(
        success=True,
        action_type="kill_process",
        target=f"{process_name}@{hostname}",
        session_id=session_id,
        message=f"Process {process_name} terminated on {hostname}",
        event_ids=[event_id],
    )


async def _quarantine_file(session_id: str, params: dict) -> ActionResult:
    sha256 = params.get("sha256") or params.get("hash", "")
    hostname = params.get("hostname", "")

    event_id = await _store_event(session_id, "edr", "high", hostname, {
        "event_title": f"File quarantined: {sha256[:16]}... on {hostname}",
        "SHA256HashData": sha256,
        "ComputerName": hostname,
        "action_taken": "quarantined",
        "_action": "quarantine_file",
        "_actor": params.get("actor", "joti_soar"),
        "_type": "response_action",
    })
    return ActionResult(
        success=True,
        action_type="quarantine_file",
        target=sha256[:16] + "...",
        session_id=session_id,
        message=f"File {sha256[:16]}... quarantined",
        event_ids=[event_id],
        details={"sha256": sha256},
    )


async def _deploy_detection(session_id: str, params: dict) -> ActionResult:
    """Store a detection rule in the simulated SIEM for this session."""
    name = params.get("name", "Unnamed Detection")
    sigma_yaml = params.get("sigma_yaml", "")
    query_spl = params.get("query_spl", "")
    technique_ids = params.get("technique_ids", [])

    try:
        from backend.db.models import DeployedDetection  # noqa: F401
        from backend.db.session import async_session

        async with async_session() as db:
            import importlib
            models_mod = importlib.import_module("backend.db.models")
            DeployedDetection = getattr(models_mod, "DeployedDetection", None)
            if DeployedDetection:
                det = DeployedDetection(
                    session_id=uuid.UUID(session_id) if session_id else None,
                    name=name,
                    sigma_yaml=sigma_yaml,
                    query_spl=query_spl,
                    technique_ids=technique_ids,
                    status="deployed",
                    deployed_by=params.get("actor", "joti_soar"),
                )
                db.add(det)
                await db.commit()
    except Exception:
        pass

    return ActionResult(
        success=True,
        action_type="deploy_detection",
        target=name,
        session_id=session_id,
        message=f"Detection '{name}' deployed to simulated SIEM",
        details={"name": name, "technique_ids": technique_ids},
    )


async def _inject_alert(session_id: str, params: dict) -> ActionResult:
    title = params.get("title", "Injected Alert")
    severity = params.get("severity", "medium")
    technique = params.get("technique_id", "")

    event_id = await _store_event(session_id, params.get("source_type", "edr"), severity, "", {
        "event_title": title,
        "_technique": technique,
        "_type": "injected_alert",
        "_actor": params.get("actor", "joti_soar"),
    })
    return ActionResult(
        success=True,
        action_type="inject_alert",
        target=title,
        session_id=session_id,
        message=f"Alert '{title}' injected",
        event_ids=[event_id],
    )


# ── Handler registry ──────────────────────────────────────────────────────────

_HANDLERS = {
    "isolate_host":    _isolate_host,
    "release_host":    _release_host,
    "disable_account": _disable_account,
    "enable_account":  _enable_account,
    "reset_password":  _reset_password,
    "block_ioc":       _block_ioc,
    "unblock_ioc":     _unblock_ioc,
    "kill_process":    _kill_process,
    "quarantine_file": _quarantine_file,
    "deploy_detection": _deploy_detection,
    "inject_alert":    _inject_alert,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _store_event(
    session_id: str,
    source_type: str,
    severity: str,
    target: str,
    payload: dict,
) -> str:
    """Store a response action confirmation event in the DB."""
    try:
        from backend.engine.session_manager import get_session_manager
        mgr = get_session_manager()
        result = await mgr.store_event(session_id, {
            "product_type": source_type,
            "severity": severity,
            "title": payload.get("event_title", payload.get("_action", "")),
            "payload": payload,
            "target_url": "",
            "status_code": 200,
            "success": True,
        })
        return str(result.get("id", "")) if result else ""
    except Exception:
        return str(uuid.uuid4())


async def _persist_action(
    session_id: str,
    action_type: str,
    actor: str,
    result: ActionResult,
    params: dict,
) -> None:
    """Write audit record to response_actions table."""
    try:
        from backend.db.session import async_session
        from sqlalchemy import text

        async with async_session() as db:
            import json
            await db.execute(text("""
                INSERT INTO response_actions
                    (id, session_id, action_type, actor, target, params, result, persona_key, created_at)
                VALUES
                    (gen_random_uuid(), :session_id::uuid, :action_type, :actor, :target, :params::jsonb, :result::jsonb, :persona_key, now())
            """), {
                "session_id": session_id,
                "action_type": action_type,
                "actor": actor,
                "target": result.target,
                "params": json.dumps({k: v for k, v in params.items() if k != "actor"}),
                "result": json.dumps(result.dict()),
                "persona_key": params.get("persona_key", ""),
            })
            await db.commit()
    except Exception:
        pass
