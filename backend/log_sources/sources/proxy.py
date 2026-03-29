"""Web proxy log source generator.

Generates realistic HTTP/HTTPS proxy log events including benign corporate
traffic, C2 beaconing, data exfiltration, and suspicious user agents.
"""
from __future__ import annotations

import base64
import random
import string
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

_INTERNAL_IPS = [
    f"10.10.{b}.{d}"
    for b in range(1, 6)
    for d in [10, 20, 30, 40, 50, 60, 100, 110, 120, 150, 200, 210]
]

_BENIGN_DOMAINS = [
    ("login.microsoftonline.com",    443),
    ("outlook.office365.com",        443),
    ("teams.microsoft.com",          443),
    ("github.com",                   443),
    ("api.github.com",               443),
    ("raw.githubusercontent.com",    443),
    ("update.microsoft.com",         443),
    ("go.microsoft.com",             443),
    ("dl.delivery.mp.microsoft.com", 443),
    ("docs.google.com",              443),
    ("drive.google.com",             443),
    ("slack.com",                    443),
    ("api.slack.com",                443),
    ("cdn.jsdelivr.net",             443),
    ("pypi.org",                     443),
    ("registry.npmjs.org",           443),
    ("download.docker.com",          443),
    ("security.ubuntu.com",          80),
    ("archive.ubuntu.com",           80),
    ("packages.microsoft.com",       443),
]

_C2_DOMAINS = [
    ("185.220.101.34",     80),
    ("45.155.205.233",     443),
    ("91.219.236.174",     8080),
    ("update-cdn.example-svc.com",   80),
    ("telemetry.example-analytics.net", 443),
    ("cdn-sync.example-ms.org",      443),
    ("check.example-safety.com",     443),
    ("sync.example-cloud9.net",      443),
]

_EXFIL_DOMAINS = [
    ("file-share.example-paste.com", 443),
    ("uploads.example-storage.net",  443),
    ("api.example-transfer.io",      443),
    ("195.176.3.23",                 4433),
    ("162.247.74.74",                443),
]

_BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Microsoft-CryptoAPI/10.0",
    "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33",
    "Microsoft BITS/7.8",
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
]

_SUSPICIOUS_USER_AGENTS = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",   # outdated
    "python-urllib/3.9",
    "Wget/1.20.3 (linux-gnu)",
    "libwww-perl/6.67",
    "Cobalt Strike Beacon/4.5",
    "Go-http-client/2.0",
    "",  # empty UA
    "curl/7.29.0",
    "AutoIt v3 Script/3.3.16.0",
    "powershell/7.3",
]

_BENIGN_PATHS = [
    "/", "/index.html", "/login", "/api/v1/status", "/health",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/static/main.css", "/static/app.js",
    "/api/v2/user/profile", "/api/v2/notifications",
    "/auth/token", "/oauth/authorize",
]

_C2_PATHS = [
    "/jquery-3.3.1.min.js",
    "/pixel.gif",
    f"/cdn/{''.join(random.choices(string.ascii_lowercase, k=8))}.js",
    "/wp-admin/admin-ajax.php",
    "/api/update",
    "/news/latest",
    "/search",
]

_STATUS_CODES_BENIGN = [200, 200, 200, 204, 301, 302, 304, 404]
_STATUS_CODES_C2 = [200, 200, 204, 404, 302]

_HOSTNAMES = [
    "WKSTN-FIN-042", "WKSTN-HR-019", "WKSTN-ENG-107", "WKSTN-EXEC-003",
    "WKSTN-IT-055", "LAPTOP-REMOTE-22", "WKSTN-SALES-08", "WKSTN-DEV-33",
]


def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _rand_b64(length: int = 32) -> str:
    raw = "".join(random.choices(string.ascii_letters + string.digits, k=length))
    return base64.b64encode(raw.encode()).decode().rstrip("=")


def _rand_query_string(malicious: bool) -> str:
    if malicious:
        # Base64-encoded data in query params — common C2 pattern
        return f"data={_rand_b64(random.randint(24, 64))}&id={random.randint(100, 999)}"
    params = random.choice([
        f"q={random.choice(['search', 'query', 'update', 'status'])}",
        f"page={random.randint(1, 10)}&size=20",
        f"v={random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
        "",
    ])
    return params


class ProxySource(AbstractLogSource):
    source_type = "proxy"
    description = "Web proxy HTTP/HTTPS log events"

    # ── individual traffic generators ─────────────────────────────────────────

    def _gen_benign(self) -> dict[str, Any]:
        host, port = random.choice(_BENIGN_DOMAINS)
        scheme = "https" if port == 443 else "http"
        path = random.choice(_BENIGN_PATHS)
        qs = _rand_query_string(False)
        url = f"{scheme}://{host}{path}" + (f"?{qs}" if qs else "")
        method = random.choices(["GET", "POST", "PUT", "DELETE"], weights=[70, 20, 5, 5])[0]
        status = random.choice(_STATUS_CODES_BENIGN)
        return {
            "timestamp": _ts(random.randint(0, 3600)),
            "src_ip": random.choice(_INTERNAL_IPS),
            "src_host": random.choice(_HOSTNAMES),
            "dst_ip": f"52.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": port,
            "method": method,
            "url": url,
            "host": host,
            "path": path,
            "query_string": qs,
            "status_code": status,
            "bytes_sent": random.randint(300, 2048) if method in ("POST", "PUT") else random.randint(0, 512),
            "bytes_recv": random.randint(512, 51200),
            "duration_ms": random.randint(20, 800),
            "user_agent": random.choice(_BENIGN_USER_AGENTS),
            "content_type": random.choice(["application/json", "text/html", "application/javascript", "text/css"]),
            "action": "allowed",
            "category": "business",
            "malicious_indicator": False,
        }

    def _gen_c2_beacon(self) -> dict[str, Any]:
        """Simulate C2 beaconing: regular small GETs, suspicious UA, encoded params."""
        host, port = random.choice(_C2_DOMAINS)
        scheme = "https" if port in (443, 8080) else "http"
        path = random.choice(_C2_PATHS)
        qs = _rand_query_string(True)
        url = f"{scheme}://{host}{path}" + (f"?{qs}" if qs else "")
        return {
            "timestamp": _ts(random.randint(0, 300)),  # recent — beaconing
            "src_ip": random.choice(_INTERNAL_IPS),
            "src_host": random.choice(_HOSTNAMES),
            "dst_ip": host if host[0].isdigit() else f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": port,
            "method": "GET",
            "url": url,
            "host": host,
            "path": path,
            "query_string": qs,
            "status_code": random.choice(_STATUS_CODES_C2),
            "bytes_sent": random.randint(100, 512),        # small request
            "bytes_recv": random.randint(50, 4096),
            "duration_ms": random.randint(100, 3000),
            "user_agent": random.choice(_SUSPICIOUS_USER_AGENTS),
            "content_type": random.choice(["text/plain", "application/octet-stream", "text/html"]),
            "action": random.choice(["allowed", "allowed", "blocked"]),
            "category": "uncategorized",
            "malicious_indicator": True,
            "threat_type": "c2_beacon",
        }

    def _gen_exfil(self) -> dict[str, Any]:
        """Simulate data exfiltration: large POST bodies to unusual domains."""
        host, port = random.choice(_EXFIL_DOMAINS)
        scheme = "https" if port == 443 else "http"
        path = random.choice(["/upload", "/submit", "/data", "/collect", "/api/store"])
        url = f"{scheme}://{host}{path}"
        return {
            "timestamp": _ts(random.randint(0, 1800)),
            "src_ip": random.choice(_INTERNAL_IPS),
            "src_host": random.choice(_HOSTNAMES),
            "dst_ip": host if host[0].isdigit() else f"195.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": port,
            "method": "POST",
            "url": url,
            "host": host,
            "path": path,
            "query_string": "",
            "status_code": random.choice([200, 201, 202]),
            "bytes_sent": random.randint(524288, 104857600),  # 512KB – 100MB
            "bytes_recv": random.randint(50, 512),
            "duration_ms": random.randint(5000, 120000),
            "user_agent": random.choice(_SUSPICIOUS_USER_AGENTS),
            "content_type": random.choice(["application/zip", "application/octet-stream", "multipart/form-data"]),
            "action": random.choice(["allowed", "blocked"]),
            "category": "file-sharing",
            "malicious_indicator": True,
            "threat_type": "data_exfiltration",
        }

    def _gen_suspicious_ua(self) -> dict[str, Any]:
        """Known-bad or anomalous user agent hitting internal resources."""
        host, port = random.choice(_BENIGN_DOMAINS[:5])  # legitimate destinations
        scheme = "https"
        path = random.choice(_BENIGN_PATHS)
        qs = _rand_query_string(True)
        url = f"{scheme}://{host}{path}" + (f"?{qs}" if qs else "")
        return {
            "timestamp": _ts(random.randint(0, 3600)),
            "src_ip": random.choice(_INTERNAL_IPS),
            "src_host": random.choice(_HOSTNAMES),
            "dst_ip": f"40.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": port,
            "method": random.choice(["GET", "POST"]),
            "url": url,
            "host": host,
            "path": path,
            "query_string": qs,
            "status_code": random.choice([200, 403, 401]),
            "bytes_sent": random.randint(200, 8192),
            "bytes_recv": random.randint(200, 4096),
            "duration_ms": random.randint(50, 2000),
            "user_agent": random.choice(_SUSPICIOUS_USER_AGENTS),
            "content_type": "application/json",
            "action": random.choice(["allowed", "blocked"]),
            "category": "suspicious",
            "malicious_indicator": True,
            "threat_type": "suspicious_user_agent",
        }

    # ── dispatch ──────────────────────────────────────────────────────────────

    _BENIGN_GENERATORS = [_gen_benign]
    _MALICIOUS_GENERATORS = [_gen_c2_beacon, _gen_exfil, _gen_suspicious_ua]

    # ── public API ────────────────────────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        if malicious:
            return random.choice(self._MALICIOUS_GENERATORS)(self)
        return self._gen_benign()

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
