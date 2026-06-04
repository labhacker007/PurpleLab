"""DNS query/response log source generator.

Generates realistic DNS log entries matching common SIEM DNS log schemas.
Simulates both benign corporate DNS traffic and DNS-based attack techniques:
  - T1568.002 — DGA domains
  - T1071.004 — DNS tunneling
  - C2 beaconing via DNS
  - Fast-flux domain resolution

source_type = "dns"
"""
from __future__ import annotations

import random
import string
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

# Internal client IPs
_CLIENT_IPS = [
    f"10.10.{b}.{d}"
    for b in range(1, 4)
    for d in [10, 20, 30, 40, 50, 100, 120, 150, 180, 200]
]

# Internal DNS resolvers
_DNS_SERVERS = [
    "10.10.1.10",
    "10.10.1.11",
    "10.10.2.10",
]

# External resolvers (for some clients)
_EXT_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]

# Benign: Microsoft / Windows Update
_MSFT_DOMAINS = [
    "update.microsoft.com",
    "download.windowsupdate.com",
    "windowsupdate.com",
    "dl.delivery.mp.microsoft.com",
    "officecdn.microsoft.com",
    "go.microsoft.com",
    "live.com",
    "login.microsoftonline.com",
    "outlook.office365.com",
    "smtp.office365.com",
]

# Benign: CDN / public services
_CDN_DOMAINS = [
    "s3.amazonaws.com",
    "cdn.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "www.google.com",
    "www.gstatic.com",
    "clients1.google.com",
    "ssl.gstatic.com",
    "github.com",
    "objects.githubusercontent.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "www.cloudflare.com",
    "api.github.com",
    "www.youtube.com",
    "ytimg.com",
]

# Benign: corporate internal AD / email
_CORP_INTERNAL_DOMAINS = [
    "dc01.corp.internal",
    "mail.corp.internal",
    "sharepoint.corp.internal",
    "helpdesk.corp.internal",
    "intranet.corp.internal",
    "sccm.corp.internal",
    "_kerberos._tcp.corp.internal",
    "_ldap._tcp.corp.internal",
    "_msdcs.corp.internal",
    "smtp.corp.internal",
]

# Benign: typical browsing
_BROWSE_DOMAINS = [
    "www.stackoverflow.com",
    "www.reddit.com",
    "www.wikipedia.org",
    "www.linkedin.com",
    "www.slack.com",
    "api.slack.com",
    "zoom.us",
    "www.zoom.us",
    "salesforce.com",
    "login.salesforce.com",
    "www.dropbox.com",
    "api.dropbox.com",
]

# Malicious: C2 beaconing — realistic-looking but fake update/cdn domains
_C2_BEACON_DOMAINS = [
    "beacon.updateservice-cdn.net",
    "telemetry.sys-metrics.com",
    "health.softwareupdate-api.io",
    "ping.cdn-delivery-svc.com",
    "check.patch-distribution.net",
    "sync.update-analytics-svc.org",
    "heartbeat.software-telemetry.io",
    "callback.update-center-api.com",
]

# External IP pools for malicious resolutions
_MALICIOUS_IPS = [
    f"45.{random.randint(80, 150)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    for _ in range(20)
] + [
    f"185.{random.randint(200, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    for _ in range(10)
] + [
    f"91.219.{random.randint(1, 254)}.{random.randint(1, 254)}"
    for _ in range(10)
]

# Benign IP answers (CDN / public service ranges)
_BENIGN_IPS = _CDN_DOMAINS  # placeholder; actual IPs generated inline


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp, optionally shifted."""
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _rand_hex(length: int) -> str:
    return "".join(random.choices("0123456789abcdef", k=length))


def _query_id() -> str:
    """Return a hex DNS query ID like '0x1a2b'."""
    return f"0x{_rand_hex(4)}"


def _dga_domain() -> str:
    """Generate a random DGA-style domain name."""
    tld = random.choice([".ru", ".xyz", ".cc", ".tk", ".top", ".bid", ".pw", ".info"])
    length = random.randint(10, 18)
    name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return name + tld


def _tunnel_label() -> str:
    """Generate a base64-ish subdomain label used for DNS tunneling."""
    chars = string.ascii_letters + string.digits + "+/="
    length = random.randint(30, 60)
    return "".join(random.choices(chars, k=length))


def _rand_ext_ip() -> str:
    return random.choice([
        f"203.0.113.{random.randint(1, 254)}",
        f"198.51.100.{random.randint(1, 254)}",
        f"45.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"91.219.{random.randint(1, 254)}.{random.randint(1, 254)}",
    ])


def _benign_ip() -> str:
    return random.choice([
        f"104.18.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"172.64.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"151.101.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"13.32.{random.randint(1, 254)}.{random.randint(1, 254)}",
        f"52.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
    ])


class DNSLogSource(AbstractLogSource):
    """DNS query/response log generator."""

    source_type = "dns"
    description = "DNS query and response logs (SIEM-compatible schema)"

    # ── internal event builders ───────────────────────────────────────────────

    def _base(self, src_ip: str, query_name: str, query_type: str) -> dict[str, Any]:
        offset = random.randint(0, 3600)
        use_tcp = query_type in ("TXT", "ANY") or random.random() < 0.05
        dns_server = random.choice(_DNS_SERVERS + _EXT_DNS_SERVERS[:2])
        return {
            "timestamp": _ts(offset),
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dns_server,
            "dst_port": 53,
            "query_name": query_name,
            "query_type": query_type,
            "protocol": "TCP" if use_tcp else "UDP",
            "query_id": _query_id(),
            "malicious_indicator": False,
        }

    # ── Malicious patterns ────────────────────────────────────────────────────

    def _gen_dga(self) -> dict[str, Any]:
        """T1568.002 — DGA domain lookup, NXDOMAIN response."""
        domain = _dga_domain()
        ev = self._base(random.choice(_CLIENT_IPS), domain, "A")
        ev.update({
            "response_code": "NXDOMAIN",
            "answers": [],
            "ttl": 0,
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(40, 60),
            "malicious_indicator": True,
        })
        return ev

    def _gen_dns_tunnel(self) -> dict[str, Any]:
        """T1071.004 — DNS tunneling via long TXT subdomains."""
        c2_apex = random.choice([
            "exfil.attacker-c2.com",
            "tunnel.data-relay.net",
            "pipe.cdn-update-svc.io",
            "xfr.base-relay.org",
        ])
        label = _tunnel_label()
        domain = f"{label}.{c2_apex}"
        ev = self._base(random.choice(_CLIENT_IPS), domain, "TXT")
        # Large TXT response carrying tunneled data
        payload = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 180)))
        ev.update({
            "response_code": "NOERROR",
            "answers": [payload],
            "ttl": random.randint(1, 30),
            "bytes_sent": len(domain) + random.randint(20, 40),
            "bytes_received": len(payload) + random.randint(20, 60),
            "malicious_indicator": True,
        })
        return ev

    def _gen_c2_beacon(self) -> dict[str, Any]:
        """Repeated beaconing to a C2 domain resolving to an external IP."""
        domain = random.choice(_C2_BEACON_DOMAINS)
        c2_ip = random.choice(_MALICIOUS_IPS)
        ev = self._base(random.choice(_CLIENT_IPS), domain, "A")
        ev.update({
            "response_code": "NOERROR",
            "answers": [c2_ip],
            "ttl": random.randint(60, 300),
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(60, 120),
            "malicious_indicator": True,
        })
        return ev

    def _gen_fast_flux(self) -> dict[str, Any]:
        """Fast-flux: same hostname, different IPs per query, short TTL."""
        domain = random.choice([
            "delivery.flux-cdn-net.com",
            "api.rotating-edge.net",
            "assets.fast-relay-svc.io",
            "static.flux-host.org",
        ])
        # Different IP each call, very short TTL
        ip = _rand_ext_ip()
        ev = self._base(random.choice(_CLIENT_IPS), domain, "A")
        ev.update({
            "response_code": "NOERROR",
            "answers": [ip],
            "ttl": random.randint(1, 30),
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(60, 100),
            "malicious_indicator": True,
        })
        return ev

    def _gen_dga_burst(self) -> dict[str, Any]:
        """Burst of DGA lookups — same client, many NXDOMAIN responses.

        Returns a single event; the batch method handles the burst pattern
        by generating multiple DGA events in sequence.
        """
        return self._gen_dga()

    # ── Benign patterns ───────────────────────────────────────────────────────

    def _gen_windows_update(self) -> dict[str, Any]:
        """Windows / Office Update domain lookup."""
        domain = random.choice(_MSFT_DOMAINS)
        qtype = "MX" if "smtp" in domain or "mail" in domain else "A"
        ev = self._base(random.choice(_CLIENT_IPS), domain, qtype)
        answers: list[str] = (
            [f"10 {domain}"] if qtype == "MX"
            else [_benign_ip()]
        )
        ev.update({
            "response_code": "NOERROR",
            "answers": answers,
            "ttl": random.randint(300, 3600),
            "bytes_sent": random.randint(40, 100),
            "bytes_received": random.randint(60, 200),
        })
        return ev

    def _gen_cdn_lookup(self) -> dict[str, Any]:
        """CDN asset resolution — A or CNAME."""
        domain = random.choice(_CDN_DOMAINS)
        qtype = random.choice(["A", "AAAA", "CNAME"])
        ev = self._base(random.choice(_CLIENT_IPS), domain, qtype)
        if qtype == "CNAME":
            answers = [f"cname.{domain}"]
        elif qtype == "AAAA":
            answers = [f"2606:4700::{random.randint(1,254):x}:{random.randint(1,254):x}"]
        else:
            answers = [_benign_ip(), _benign_ip()]
        ev.update({
            "response_code": "NOERROR",
            "answers": answers,
            "ttl": random.randint(60, 300),
            "bytes_sent": random.randint(40, 100),
            "bytes_received": random.randint(80, 300),
        })
        return ev

    def _gen_corp_internal(self) -> dict[str, Any]:
        """Corporate AD / internal service lookup."""
        domain = random.choice(_CORP_INTERNAL_DOMAINS)
        is_srv = domain.startswith("_")
        qtype = "SRV" if is_srv else random.choice(["A", "PTR"])
        src_ip = random.choice(_CLIENT_IPS)
        dst_ip = random.choice(_DNS_SERVERS)  # internal DNS only
        ev = self._base(src_ip, domain, qtype)
        ev["dst_ip"] = dst_ip
        if is_srv:
            answers = [f"0 100 88 dc01.corp.internal"]
        else:
            answers = [f"10.10.{random.randint(1,3)}.{random.randint(10,50)}"]
        ev.update({
            "response_code": "NOERROR",
            "answers": answers,
            "ttl": random.randint(300, 1200),
            "bytes_sent": random.randint(40, 100),
            "bytes_received": random.randint(60, 200),
        })
        return ev

    def _gen_browse(self) -> dict[str, Any]:
        """Typical web browsing domain resolution."""
        domain = random.choice(_BROWSE_DOMAINS)
        ev = self._base(random.choice(_CLIENT_IPS), domain, "A")
        ev.update({
            "response_code": "NOERROR",
            "answers": [_benign_ip()],
            "ttl": random.randint(60, 600),
            "bytes_sent": random.randint(40, 90),
            "bytes_received": random.randint(60, 180),
        })
        return ev

    def _gen_nxdomain_benign(self) -> dict[str, Any]:
        """Benign NXDOMAIN — mistyped domain or stale DNS record."""
        typo_base = random.choice(["ww.google.com", "gogle.com", "facbook.com",
                                   "microsft.com", "amazn.com", "githb.com"])
        ev = self._base(random.choice(_CLIENT_IPS), typo_base, "A")
        ev.update({
            "response_code": "NXDOMAIN",
            "answers": [],
            "ttl": 0,
            "bytes_sent": random.randint(40, 80),
            "bytes_received": random.randint(40, 60),
        })
        return ev

    def _gen_ptr_lookup(self) -> dict[str, Any]:
        """Reverse PTR lookup for an internal IP."""
        ip_parts = random.choice(_CLIENT_IPS).split(".")
        ptr_name = f"{ip_parts[3]}.{ip_parts[2]}.{ip_parts[1]}.{ip_parts[0]}.in-addr.arpa"
        ev = self._base(random.choice(_CLIENT_IPS), ptr_name, "PTR")
        hostname = random.choice([
            "wkstn-fin-042.corp.internal",
            "srv-dc-01.corp.internal",
            "laptop-remote-22.corp.internal",
        ])
        ev.update({
            "response_code": "NOERROR",
            "answers": [hostname],
            "ttl": random.randint(300, 3600),
            "bytes_sent": random.randint(50, 90),
            "bytes_received": random.randint(70, 150),
        })
        return ev

    # ── dispatch tables ───────────────────────────────────────────────────────

    _MALICIOUS_GENERATORS = [
        _gen_dga, _gen_dga, _gen_dga,          # DGA most common attack pattern
        _gen_dns_tunnel,
        _gen_c2_beacon, _gen_c2_beacon,
        _gen_fast_flux,
    ]

    _BENIGN_GENERATORS = [
        _gen_browse, _gen_browse, _gen_browse,  # browsing most frequent
        _gen_cdn_lookup, _gen_cdn_lookup,
        _gen_windows_update,
        _gen_corp_internal, _gen_corp_internal,
        _gen_nxdomain_benign,
        _gen_ptr_lookup,
    ]

    # ── technique routing ─────────────────────────────────────────────────────

    _TECHNIQUE_MAP: dict[str, Any] = {
        "T1568.002": "_gen_dga",
        "T1071.004": "_gen_dns_tunnel",
        "T1071":     "_gen_c2_beacon",
        "T1568":     "_gen_fast_flux",
    }

    # ── public API ────────────────────────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        if malicious and technique_id:
            method_name = self._TECHNIQUE_MAP.get(technique_id)
            if method_name:
                gen_fn = getattr(self, method_name)
                return gen_fn()

        pool = self._MALICIOUS_GENERATORS if malicious else self._BENIGN_GENERATORS
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

        # For DGA: cluster the malicious events together to simulate a burst
        # (same client, rapid-fire NXDOMAIN responses)
        if technique_id == "T1568.002" and malicious_count > 1:
            burst_ip = random.choice(_CLIENT_IPS)
            for i in range(malicious_count):
                ev = self._gen_dga()
                ev["src_ip"] = burst_ip          # same source = realistic burst
                events.append(ev)
            for _ in range(count - malicious_count):
                events.append(self.generate(malicious=False))
        else:
            for i in range(count):
                is_malicious = i < malicious_count
                events.append(
                    self.generate(malicious=is_malicious, technique_id=technique_id)
                )

        random.shuffle(events)
        return events
