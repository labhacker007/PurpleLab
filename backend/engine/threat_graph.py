"""Threat Graph — process tree and lateral movement graph from simulation events.

Builds a directed graph where:
  - Nodes are processes (identified by hostname + PID or filename) or network endpoints
  - Edges are relationships: parent→child process, process→network connection,
    endpoint→endpoint lateral movement

The graph is built incrementally as events are processed and can be serialised
to a dict for the REST API and frontend visualisation.

Usage::

    from backend.engine.threat_graph import get_graph, ThreatGraph

    g = get_graph(session_id)
    g.ingest_event(event)          # call for every simulated event
    data = g.to_dict()             # serialise for the frontend
"""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


# ── Node types ────────────────────────────────────────────────────────────────

NODE_PROCESS  = "process"
NODE_ENDPOINT = "endpoint"
NODE_NETWORK  = "network"   # external IP / C2
NODE_FILE     = "file"
NODE_USER     = "user"

# Edge types
EDGE_SPAWNED   = "spawned"       # parent process → child process
EDGE_CONNECTED = "connected_to"  # process / endpoint → remote IP
EDGE_LATERAL   = "lateral_move"  # endpoint → endpoint
EDGE_WROTE     = "wrote_file"
EDGE_LOGGED_IN = "logged_in_as"


def _nid(*parts: str) -> str:
    """Deterministic short node ID from concatenated parts."""
    key = "|".join(str(p) for p in parts)
    return hashlib.md5(key.encode()).hexdigest()[:16]


class Node:
    __slots__ = ("id", "node_type", "label", "attrs", "first_seen", "last_seen", "technique_ids")

    def __init__(self, node_id: str, node_type: str, label: str, attrs: dict | None = None) -> None:
        self.id = node_id
        self.node_type = node_type
        self.label = label
        self.attrs = attrs or {}
        self.first_seen: str = datetime.now(timezone.utc).isoformat()
        self.last_seen: str = self.first_seen
        self.technique_ids: set[str] = set()

    def touch(self, technique_id: str = "") -> None:
        self.last_seen = datetime.now(timezone.utc).isoformat()
        if technique_id:
            self.technique_ids.add(technique_id)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "attrs": self.attrs,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "technique_ids": list(self.technique_ids),
        }


class Edge:
    __slots__ = ("src", "dst", "edge_type", "technique_id", "timestamp", "weight")

    def __init__(self, src: str, dst: str, edge_type: str, technique_id: str = "", weight: int = 1) -> None:
        self.src = src
        self.dst = dst
        self.edge_type = edge_type
        self.technique_id = technique_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.weight = weight

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "type": self.edge_type,
            "technique_id": self.technique_id,
            "timestamp": self.timestamp,
            "weight": self.weight,
        }


class ThreatGraph:
    """Incrementally builds a threat/process graph from simulated events."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}  # (src, dst, type) → edge
        # Count how many times each edge has been seen (for weight)
        self._edge_counts: defaultdict[tuple[str, str, str], int] = defaultdict(int)

    # ── Node / edge helpers ────────────────────────────────────────────────────

    def _upsert_node(
        self, node_id: str, node_type: str, label: str,
        attrs: dict | None = None, technique_id: str = "",
    ) -> Node:
        if node_id not in self._nodes:
            self._nodes[node_id] = Node(node_id, node_type, label, attrs)
        n = self._nodes[node_id]
        n.touch(technique_id)
        if attrs:
            n.attrs.update(attrs)
        return n

    def _upsert_edge(
        self, src: str, dst: str, edge_type: str, technique_id: str = ""
    ) -> Edge:
        key = (src, dst, edge_type)
        self._edge_counts[key] += 1
        if key not in self._edges:
            self._edges[key] = Edge(src, dst, edge_type, technique_id, weight=1)
        else:
            self._edges[key].weight = self._edge_counts[key]
            if technique_id:
                self._edges[key].technique_id = technique_id
        return self._edges[key]

    # ── Event ingestion ────────────────────────────────────────────────────────

    def ingest_event(self, event: dict[str, Any]) -> None:
        """Parse one simulated event and update the graph."""
        try:
            self._parse_event(event)
        except Exception as exc:
            log.debug("threat_graph ingest error: %s", exc)

    def _parse_event(self, event: dict[str, Any]) -> None:
        source_type: str = event.get("source_type", "")
        technique_id: str = event.get("technique_id") or event.get("_technique") or ""
        payload: dict = event.get("payload") or {}

        # ── Windows Event Log / Sysmon — process creation ─────────────────────
        if source_type in ("windows_eventlog", "sysmon"):
            self._handle_process_event(payload, technique_id)
            return

        # ── EDR / CrowdStrike — rich process + network context ────────────────
        if source_type in ("edr", "crowdstrike", "crowdstrike_edr"):
            self._handle_edr_event(payload, technique_id)
            return

        # ── Firewall / network ────────────────────────────────────────────────
        if source_type in ("firewall", "network", "palo_alto"):
            self._handle_network_event(payload, technique_id)
            return

        # ── Auth / Okta — lateral movement via valid account use ──────────────
        if source_type in ("auth", "okta", "okta_identity"):
            self._handle_auth_event(payload, technique_id)
            return

        # ── Generic fallback ──────────────────────────────────────────────────
        hostname = (
            payload.get("ComputerName") or payload.get("Computer")
            or payload.get("hostname") or ""
        )
        if hostname:
            nid = _nid(NODE_ENDPOINT, hostname)
            self._upsert_node(nid, NODE_ENDPOINT, hostname,
                              {"hostname": hostname}, technique_id)

    # ── Source-specific parsers ───────────────────────────────────────────────

    def _handle_process_event(self, p: dict, tid: str) -> None:
        hostname = p.get("Computer") or p.get("ComputerName") or "unknown"
        host_id = _nid(NODE_ENDPOINT, hostname)
        self._upsert_node(host_id, NODE_ENDPOINT, hostname, {"hostname": hostname})

        child_name = p.get("ProcessName") or p.get("Image") or p.get("NewProcessName") or ""
        child_pid = str(p.get("NewProcessId") or p.get("ProcessId") or "0")
        parent_name = p.get("ParentProcessName") or p.get("ParentImage") or "unknown"
        parent_pid = str(p.get("ParentProcessId") or "0")
        cmdline = p.get("CommandLine") or ""
        user = p.get("SubjectUserName") or p.get("User") or ""

        if child_name:
            child_id = _nid(NODE_PROCESS, hostname, child_name, child_pid)
            self._upsert_node(child_id, NODE_PROCESS, child_name, {
                "hostname": hostname, "pid": child_pid,
                "cmdline": cmdline[:200], "user": user,
            }, tid)
            # Edge: endpoint hosts the process
            self._upsert_edge(host_id, child_id, EDGE_SPAWNED, tid)

            if parent_name and parent_name != "unknown":
                parent_id = _nid(NODE_PROCESS, hostname, parent_name, parent_pid)
                self._upsert_node(parent_id, NODE_PROCESS, parent_name, {
                    "hostname": hostname, "pid": parent_pid,
                }, "")
                self._upsert_edge(parent_id, child_id, EDGE_SPAWNED, tid)

            # User node
            if user:
                uid = _nid(NODE_USER, user)
                self._upsert_node(uid, NODE_USER, user, {"username": user})
                self._upsert_edge(uid, child_id, EDGE_LOGGED_IN, tid)

    def _handle_edr_event(self, p: dict, tid: str) -> None:
        hostname = p.get("ComputerName") or p.get("hostname") or "unknown"
        host_id = _nid(NODE_ENDPOINT, hostname)
        self._upsert_node(host_id, NODE_ENDPOINT, hostname, {"hostname": hostname})

        proc = p.get("FileName") or p.get("process_name") or ""
        cmdline = p.get("CommandLine") or ""
        parent = p.get("ParentImageFileName") or ""
        sha256 = p.get("SHA256String") or p.get("SHA256HashData") or ""
        remote_ip = p.get("ExternalIP") or p.get("RemoteAddressIP4") or ""
        remote_port = str(p.get("RemotePort") or "")

        if proc:
            proc_id = _nid(NODE_PROCESS, hostname, proc)
            self._upsert_node(proc_id, NODE_PROCESS, proc, {
                "hostname": hostname, "cmdline": cmdline[:200], "sha256": sha256,
            }, tid)
            self._upsert_edge(host_id, proc_id, EDGE_SPAWNED, tid)

            if parent:
                parent_id = _nid(NODE_PROCESS, hostname, parent)
                self._upsert_node(parent_id, NODE_PROCESS, parent, {"hostname": hostname})
                self._upsert_edge(parent_id, proc_id, EDGE_SPAWNED, tid)

            if remote_ip:
                net_id = _nid(NODE_NETWORK, remote_ip, remote_port)
                self._upsert_node(net_id, NODE_NETWORK, f"{remote_ip}:{remote_port}" if remote_port else remote_ip,
                                  {"ip": remote_ip, "port": remote_port}, tid)
                self._upsert_edge(proc_id, net_id, EDGE_CONNECTED, tid)

    def _handle_network_event(self, p: dict, tid: str) -> None:
        src_ip = p.get("src_ip") or p.get("LocalAddressIP4") or p.get("src") or ""
        dst_ip = p.get("dst_ip") or p.get("RemoteAddressIP4") or p.get("dst") or ""
        dst_port = str(p.get("dst_port") or p.get("dport") or "")
        hostname = p.get("hostname") or p.get("devname") or src_ip

        if src_ip:
            src_id = _nid(NODE_ENDPOINT, src_ip)
            self._upsert_node(src_id, NODE_ENDPOINT, hostname or src_ip,
                              {"ip": src_ip, "hostname": hostname}, tid)

            if dst_ip:
                dst_id = _nid(NODE_NETWORK, dst_ip, dst_port)
                self._upsert_node(dst_id, NODE_NETWORK,
                                  f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                                  {"ip": dst_ip, "port": dst_port}, tid)
                self._upsert_edge(src_id, dst_id, EDGE_CONNECTED, tid)

    def _handle_auth_event(self, p: dict, tid: str) -> None:
        src_ip = p.get("client", {}).get("ipAddress") if isinstance(p.get("client"), dict) else p.get("client.ipAddress") or p.get("src_ip") or ""
        user = p.get("actor", {}).get("alternateId") if isinstance(p.get("actor"), dict) else p.get("actor.alternateId") or p.get("SubjectUserName") or ""
        target_hostname = p.get("target.hostname") or p.get("TargetServerName") or ""

        if user:
            uid = _nid(NODE_USER, user)
            self._upsert_node(uid, NODE_USER, user, {"email": user}, tid)

            if src_ip:
                src_id = _nid(NODE_ENDPOINT, src_ip)
                self._upsert_node(src_id, NODE_ENDPOINT, src_ip, {"ip": src_ip})
                self._upsert_edge(uid, src_id, EDGE_LOGGED_IN, tid)

            if target_hostname:
                tgt_id = _nid(NODE_ENDPOINT, target_hostname)
                self._upsert_node(tgt_id, NODE_ENDPOINT, target_hostname,
                                  {"hostname": target_hostname})
                self._upsert_edge(uid, tgt_id, EDGE_LATERAL, tid)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        nodes = [n.to_dict() for n in self._nodes.values()]
        edges = [e.to_dict() for e in self._edges.values()]

        # Compute summary stats
        technique_counts: dict[str, int] = defaultdict(int)
        for n in self._nodes.values():
            for tid in n.technique_ids:
                technique_counts[tid] += 1

        return {
            "session_id": self.session_id,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "technique_hit_count": dict(technique_counts),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def stats(self) -> dict[str, Any]:
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "processes": sum(1 for n in self._nodes.values() if n.node_type == NODE_PROCESS),
            "endpoints": sum(1 for n in self._nodes.values() if n.node_type == NODE_ENDPOINT),
            "network_ips": sum(1 for n in self._nodes.values() if n.node_type == NODE_NETWORK),
            "users": sum(1 for n in self._nodes.values() if n.node_type == NODE_USER),
        }


# ── Singleton per-session registry ────────────────────────────────────────────

_graphs: dict[str, ThreatGraph] = {}


def get_graph(session_id: str) -> ThreatGraph:
    """Return (or create) the threat graph for a simulation session."""
    if session_id not in _graphs:
        _graphs[session_id] = ThreatGraph(session_id)
    return _graphs[session_id]


def drop_graph(session_id: str) -> None:
    """Remove the threat graph when a session is stopped."""
    _graphs.pop(session_id, None)
