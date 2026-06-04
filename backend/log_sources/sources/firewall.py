"""Firewall log source generator.

Supports two vendor formats selectable at instantiation:
  - "panos"    : Palo Alto Networks PAN-OS Traffic/Threat logs (default)
  - "fortinet" : Fortinet FortiGate traffic/utm logs

Generates realistic firewall log entries for common traffic patterns and
attack techniques used in detection engineering and purple team exercises.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

_CORP_HOSTNAMES = [
    "FW-CORP-01", "FW-EDGE-02", "FW-DMZ-01", "FW-BRANCH-03",
    "NGFW-HQ-01", "NGFW-DC-02",
]

# Internal IP helpers
def _corp_ip(subnet: int = 0) -> str:
    """Return a random IP from 10.10.{1,2,3}.x."""
    b = subnet if subnet in (1, 2, 3) else random.randint(1, 3)
    return f"10.10.{b}.{random.randint(10, 250)}"

def _external_ip() -> str:
    """Return a random-looking public IP from realistic ranges."""
    prefix = random.choice([
        f"203.0.113.{random.randint(1, 254)}",
        f"198.51.100.{random.randint(1, 254)}",
        f"45.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"91.219.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"194.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"23.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
    ])
    return prefix

_CDN_IPS = [
    "104.18.10.1", "104.18.11.1", "172.64.32.1", "172.64.33.1",
    "151.101.1.140", "151.101.65.140", "13.32.1.100", "54.230.1.50",
    "143.204.1.20", "99.84.1.30",
]

_PANOS_SERIALS = [
    "015351000012345", "015351000067890", "015351000054321", "015351000099999",
]

_PANOS_RULES = [
    "Allow-Outbound-Web", "Block-High-Risk", "Allow-Corp-Apps",
    "Deny-External-Inbound", "Allow-DNS-Outbound", "Allow-RDP-Internal",
    "Block-C2-Known", "Allow-SMTP-Relay", "Inspect-SSL-Outbound",
    "Allow-Monitoring", "Block-Tor-Exit",
]

_PANOS_APPS_BENIGN = [
    "web-browsing", "ssl", "dns", "smtp", "imap", "office365",
    "sharepoint", "salesforce", "zoom", "ms-teams", "slack",
    "dropbox", "google-drive", "windows-update",
]

_PANOS_APPS_MALICIOUS = [
    "unknown", "not-applicable", "generic-tcp", "generic-udp",
    "raw-tcp", "non-syn-tcp",
]

_PANOS_ZONES = ["trust", "untrust", "dmz", "mgmt"]

_PANOS_INTERFACES = [
    "ethernet1/1", "ethernet1/2", "ethernet1/3", "ae1.100", "ae1.200",
]

_PANOS_CATEGORIES = [
    "computer-and-internet-info", "business-and-economy", "news",
    "unknown", "malware", "command-and-control", "phishing", "high-risk",
]

_PANOS_THREAT_IDS = [
    "40000", "40001", "40002", "55555", "33333",
    "14978", "34986", "41060", "14978", "57914",
]

_FORTINET_LOGIDS = [
    "0000000013", "0000000020", "0001000014", "0000000001",
    "0001000234", "0000000022",
]

_FORTINET_INTERFACES = [
    "port1", "port2", "port3", "lan", "wan1", "wan2", "internal", "dmz",
]

_FORTINET_SERVICES = [
    "HTTPS", "HTTP", "DNS", "SMTP", "RDP", "SMB", "FTP",
    "CUSTOM_8443", "ICMP", "SSH",
]

_SESSION_END_REASONS = [
    "aged-out", "tcp-fin", "tcp-rst-from-client", "tcp-rst-from-server",
    "policy-deny", "decrypt-cert-validation", "unknown",
]

# ── Timestamp helper ─────────────────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp, optionally shifted."""
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _ts_parts(offset_seconds: int = 0) -> tuple[str, str]:
    """Return (date, time) strings for Fortinet format."""
    dt = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")


class FirewallLogSource(AbstractLogSource):
    """Firewall log generator supporting PAN-OS and FortiGate formats."""

    source_type = "firewall"
    description = "Firewall traffic and threat logs (PAN-OS or FortiGate)"

    def __init__(self, vendor: str = "panos") -> None:
        if vendor not in ("panos", "fortinet"):
            raise ValueError(f"Unknown vendor '{vendor}'; choose 'panos' or 'fortinet'")
        self.vendor = vendor
        if vendor == "fortinet":
            self.source_type = "fortinet"

    # ── PAN-OS helpers ────────────────────────────────────────────────────────

    def _panos_traffic_base(self, subtype: str = "end") -> dict[str, Any]:
        offset = random.randint(0, 3600)
        return {
            "timestamp": _ts(offset),
            "receive_time": _ts(offset),
            "serial": random.choice(_PANOS_SERIALS),
            "type": "TRAFFIC",
            "subtype": subtype,
            "time_generated": _ts(offset + random.randint(1, 10)),
            "rule": random.choice(_PANOS_RULES),
            "inbound_if": random.choice(_PANOS_INTERFACES),
            "outbound_if": random.choice(_PANOS_INTERFACES),
            "session_end_reason": random.choice(_SESSION_END_REASONS),
            "malicious_indicator": False,
        }

    def _panos_c2_traffic(self) -> dict[str, Any]:
        """C2 callback: high dest port, unknown app, large outbound bytes."""
        ev = self._panos_traffic_base("end")
        ev.update({
            "src": _corp_ip(),
            "dst": _external_ip(),
            "sport": random.randint(49152, 65535),
            "dport": random.choice([4444, 8443, 1337, 6666, 9001, 8080]),
            "proto": "tcp",
            "action": "allow",
            "app": random.choice(_PANOS_APPS_MALICIOUS),
            "from": "trust",
            "to": "untrust",
            "bytes_sent": random.randint(50_000, 200_000),
            "bytes_received": random.randint(1_000, 20_000),
            "bytes": 0,
            "packets": random.randint(50, 500),
            "elapsed": random.randint(300, 3600),
            "category": "command-and-control",
            "malicious_indicator": True,
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    def _panos_exfil_traffic(self) -> dict[str, Any]:
        """Data exfiltration: large bytes_sent to external on 443/80."""
        ev = self._panos_traffic_base("end")
        ev.update({
            "src": _corp_ip(),
            "dst": _external_ip(),
            "sport": random.randint(49152, 65535),
            "dport": random.choice([443, 80, 8443]),
            "proto": "tcp",
            "action": "allow",
            "app": "ssl",
            "from": "trust",
            "to": "untrust",
            "bytes_sent": random.randint(100_000_000, 500_000_000),   # 100MB+
            "bytes_received": random.randint(5_000, 50_000),
            "bytes": 0,
            "packets": random.randint(10_000, 80_000),
            "elapsed": random.randint(600, 7200),
            "category": "unknown",
            "malicious_indicator": True,
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    def _panos_lateral_movement(self) -> dict[str, Any]:
        """Lateral movement: internal-to-internal on SMB/RDP/RPC."""
        ev = self._panos_traffic_base("end")
        ev.update({
            "src": _corp_ip(1),
            "dst": _corp_ip(random.randint(2, 3)),
            "sport": random.randint(49152, 65535),
            "dport": random.choice([445, 135, 3389, 5985, 5986]),
            "proto": "tcp",
            "action": "allow",
            "app": random.choice(["msrpc", "ms-ds-replication", "smb", "msrdp"]),
            "from": "trust",
            "to": "trust",
            "bytes_sent": random.randint(10_000, 100_000),
            "bytes_received": random.randint(5_000, 50_000),
            "bytes": 0,
            "packets": random.randint(20, 200),
            "elapsed": random.randint(1, 120),
            "category": "business-and-economy",
            "malicious_indicator": True,
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    def _panos_port_scan(self) -> dict[str, Any]:
        """Port scan: same src, varied dports, dropped/blocked."""
        ev = self._panos_traffic_base("drop")
        ev.update({
            "src": _corp_ip(),
            "dst": _corp_ip(random.randint(2, 3)),
            "sport": random.randint(1024, 65535),
            "dport": random.randint(1, 65535),
            "proto": "tcp",
            "action": random.choice(["drop", "block", "reset-both"]),
            "app": "not-applicable",
            "from": "trust",
            "to": "trust",
            "bytes_sent": random.randint(60, 200),
            "bytes_received": 0,
            "bytes": random.randint(60, 200),
            "packets": random.randint(1, 3),
            "elapsed": 0,
            "category": "unknown",
            "malicious_indicator": True,
        })
        return ev

    def _panos_threat_event(self) -> dict[str, Any]:
        """PAN-OS Threat log for malicious traffic."""
        ev = self._panos_c2_traffic()
        ev.update({
            "type": "THREAT",
            "threatid": random.choice(_PANOS_THREAT_IDS),
            "category": random.choice(["command-and-control", "malware", "phishing"]),
            "severity": random.choice(["critical", "high", "medium"]),
            "direction": random.choice(["client-to-server", "server-to-client"]),
            "url": f"http://{_external_ip()}/callback/{uuid.uuid4().hex[:8]}",
            "filename": random.choice([
                "update.exe", "patch.dll", "svchost32.exe",
                "payload.ps1", "", "",
            ]),
        })
        return ev

    def _panos_web_browse(self) -> dict[str, Any]:
        """Benign web browsing: dst 80/443, short session."""
        ev = self._panos_traffic_base("end")
        ev.update({
            "src": _corp_ip(),
            "dst": random.choice(_CDN_IPS),
            "sport": random.randint(49152, 65535),
            "dport": random.choice([80, 443]),
            "proto": "tcp",
            "action": "allow",
            "app": random.choice(["web-browsing", "ssl"]),
            "from": "trust",
            "to": "untrust",
            "bytes_sent": random.randint(500, 50_000),
            "bytes_received": random.randint(5_000, 500_000),
            "bytes": 0,
            "packets": random.randint(10, 300),
            "elapsed": random.randint(1, 60),
            "category": random.choice(["computer-and-internet-info", "business-and-economy", "news"]),
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    def _panos_dns(self) -> dict[str, Any]:
        """Benign DNS: dst 53, small bytes, UDP."""
        ev = self._panos_traffic_base("end")
        ev.update({
            "src": _corp_ip(),
            "dst": random.choice(["10.10.1.10", "10.10.1.11", "8.8.8.8", "1.1.1.1"]),
            "sport": random.randint(49152, 65535),
            "dport": 53,
            "proto": "udp",
            "action": "allow",
            "app": "dns",
            "from": "trust",
            "to": "untrust",
            "bytes_sent": random.randint(40, 120),
            "bytes_received": random.randint(60, 300),
            "bytes": 0,
            "packets": 2,
            "elapsed": 0,
            "category": "computer-and-internet-info",
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    def _panos_corp_app(self) -> dict[str, Any]:
        """Benign internal corporate app traffic."""
        ev = self._panos_traffic_base("end")
        dport = random.choice([8080, 3389, 445, 22, 443, 8443])
        ev.update({
            "src": _corp_ip(1),
            "dst": _corp_ip(random.randint(1, 3)),
            "sport": random.randint(49152, 65535),
            "dport": dport,
            "proto": "tcp",
            "action": "allow",
            "app": random.choice(_PANOS_APPS_BENIGN),
            "from": "trust",
            "to": "trust",
            "bytes_sent": random.randint(1_000, 100_000),
            "bytes_received": random.randint(1_000, 100_000),
            "bytes": 0,
            "packets": random.randint(20, 500),
            "elapsed": random.randint(1, 300),
            "category": "business-and-economy",
        })
        ev["bytes"] = ev["bytes_sent"] + ev["bytes_received"]
        return ev

    # ── FortiGate helpers ─────────────────────────────────────────────────────

    def _forti_base(self, log_type: str = "traffic", subtype: str = "forward") -> dict[str, Any]:
        date_str, time_str = _ts_parts(random.randint(0, 3600))
        return {
            "timestamp": f"{date_str}T{time_str}Z",
            "date": date_str,
            "time": time_str,
            "logid": random.choice(_FORTINET_LOGIDS),
            "type": log_type,
            "subtype": subtype,
            "level": "notice",
            "vd": "root",
            "policyid": random.randint(1, 50),
            "malicious_indicator": False,
        }

    def _forti_c2(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "forward")
        ev.update({
            "srcip": _corp_ip(),
            "srcport": random.randint(49152, 65535),
            "srcintf": random.choice(_FORTINET_INTERFACES[:4]),
            "dstip": _external_ip(),
            "dstport": random.choice([4444, 8443, 1337, 6666, 9001]),
            "dstintf": random.choice(["wan1", "wan2"]),
            "action": "accept",
            "sentbyte": random.randint(50_000, 200_000),
            "rcvdbyte": random.randint(1_000, 20_000),
            "duration": random.randint(300, 3600),
            "service": "CUSTOM_" + str(random.choice([4444, 8443, 1337, 6666])),
            "level": "warning",
            "malicious_indicator": True,
        })
        return ev

    def _forti_exfil(self) -> dict[str, Any]:
        ev = self._forti_base("utm", "app-ctrl")
        ev.update({
            "srcip": _corp_ip(),
            "srcport": random.randint(49152, 65535),
            "srcintf": random.choice(_FORTINET_INTERFACES[:4]),
            "dstip": _external_ip(),
            "dstport": 443,
            "dstintf": "wan1",
            "action": "accept",
            "sentbyte": random.randint(100_000_000, 500_000_000),
            "rcvdbyte": random.randint(5_000, 50_000),
            "duration": random.randint(600, 7200),
            "service": "HTTPS",
            "level": "critical",
            "malicious_indicator": True,
        })
        return ev

    def _forti_lateral(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "forward")
        ev.update({
            "srcip": _corp_ip(1),
            "srcport": random.randint(49152, 65535),
            "srcintf": "internal",
            "dstip": _corp_ip(random.randint(2, 3)),
            "dstport": random.choice([445, 135, 3389]),
            "dstintf": "internal",
            "action": "accept",
            "sentbyte": random.randint(5_000, 50_000),
            "rcvdbyte": random.randint(2_000, 20_000),
            "duration": random.randint(1, 60),
            "service": random.choice(["SMB", "RDP", "MSRPC"]),
            "malicious_indicator": True,
        })
        return ev

    def _forti_portscan(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "violation")
        ev.update({
            "srcip": _corp_ip(),
            "srcport": random.randint(1024, 65535),
            "srcintf": "internal",
            "dstip": _corp_ip(random.randint(2, 3)),
            "dstport": random.randint(1, 65535),
            "dstintf": "internal",
            "action": random.choice(["block", "deny"]),
            "sentbyte": random.randint(60, 120),
            "rcvdbyte": 0,
            "duration": 0,
            "service": "CUSTOM_SCAN",
            "level": "alert",
            "malicious_indicator": True,
        })
        return ev

    def _forti_web(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "forward")
        ev.update({
            "srcip": _corp_ip(),
            "srcport": random.randint(49152, 65535),
            "srcintf": "internal",
            "dstip": random.choice(_CDN_IPS),
            "dstport": random.choice([80, 443]),
            "dstintf": "wan1",
            "action": "accept",
            "sentbyte": random.randint(500, 50_000),
            "rcvdbyte": random.randint(5_000, 500_000),
            "duration": random.randint(1, 60),
            "service": random.choice(["HTTP", "HTTPS"]),
        })
        return ev

    def _forti_dns(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "forward")
        ev.update({
            "srcip": _corp_ip(),
            "srcport": random.randint(49152, 65535),
            "srcintf": "internal",
            "dstip": random.choice(["10.10.1.10", "8.8.8.8", "1.1.1.1"]),
            "dstport": 53,
            "dstintf": random.choice(["internal", "wan1"]),
            "action": "accept",
            "sentbyte": random.randint(40, 120),
            "rcvdbyte": random.randint(60, 300),
            "duration": 0,
            "service": "DNS",
        })
        return ev

    def _forti_corp(self) -> dict[str, Any]:
        ev = self._forti_base("traffic", "forward")
        ev.update({
            "srcip": _corp_ip(1),
            "srcport": random.randint(49152, 65535),
            "srcintf": "internal",
            "dstip": _corp_ip(random.randint(1, 3)),
            "dstport": random.choice([8080, 3389, 445, 22, 443]),
            "dstintf": "internal",
            "action": "accept",
            "sentbyte": random.randint(1_000, 100_000),
            "rcvdbyte": random.randint(1_000, 100_000),
            "duration": random.randint(1, 300),
            "service": random.choice(_FORTINET_SERVICES),
        })
        return ev

    # ── dispatch tables ───────────────────────────────────────────────────────

    _PANOS_MALICIOUS = [
        _panos_c2_traffic, _panos_c2_traffic,
        _panos_exfil_traffic,
        _panos_lateral_movement, _panos_lateral_movement,
        _panos_port_scan,
        _panos_threat_event,
    ]

    _PANOS_BENIGN = [
        _panos_web_browse, _panos_web_browse, _panos_web_browse,
        _panos_dns, _panos_dns,
        _panos_corp_app, _panos_corp_app,
    ]

    _FORTI_MALICIOUS = [
        _forti_c2, _forti_c2,
        _forti_exfil,
        _forti_lateral, _forti_lateral,
        _forti_portscan,
    ]

    _FORTI_BENIGN = [
        _forti_web, _forti_web, _forti_web,
        _forti_dns, _forti_dns,
        _forti_corp, _forti_corp,
    ]

    # ── public API ────────────────────────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        if self.vendor == "fortinet":
            pool = self._FORTI_MALICIOUS if malicious else self._FORTI_BENIGN
        else:
            pool = self._PANOS_MALICIOUS if malicious else self._PANOS_BENIGN
        gen_fn = random.choice(pool)
        return gen_fn(self)

    def generate_batch(
        self,
        count: int = 10,
        malicious_ratio: float = 0.1,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        malicious_count = max(0, min(count, round(count * malicious_ratio)))
        for i in range(count):
            is_malicious = i < malicious_count
            events.append(self.generate(malicious=is_malicious, technique_id=technique_id))
        random.shuffle(events)
        return events
