"""SimulationContext — shared entity model for all log generators.

THE CORE REALISM FIX: previously every generator picked random users,
hostnames and IPs independently. An analyst could immediately spot the
simulation because CrowdStrike showed user "jsmith" while Okta showed
"alice.martinez" for the same attack chain.

SimulationContext is created ONCE per simulation session and passed to
every generator — EDR, identity, firewall, cloud, email. All generators
read from it instead of calling random.choice(). Result: every log source
references the same victim, the same attacker IP, the same malware hash,
the same C2 domain — forming a coherent attack narrative.

Entity loading priority:
  1. CMDB (real org data) — CMDBPerson + CMDBHardwareAsset + cloud accounts
  2. Synthetic fallback (realistic random, but stable within a session)

Storing/loading: the context is pickled to Redis keyed by session_id so
it survives Celery task handoffs without being re-generated.
"""
from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

# ── Realistic synthetic fallback data pools ───────────────────────────────────

_FIRST_NAMES = [
    "James", "Sarah", "Michael", "Emily", "David", "Jessica",
    "Robert", "Ashley", "William", "Jennifer", "Daniel", "Amanda",
    "Matthew", "Stephanie", "Christopher", "Nicole", "Andrew", "Megan",
    "Joshua", "Lauren", "John", "Rachel", "Ryan", "Samantha",
    "Justin", "Brittany", "Brandon", "Kayla", "Tyler", "Alexis",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Jones", "Brown", "Davis",
    "Miller", "Wilson", "Moore", "Taylor", "Anderson", "Thomas",
    "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia",
    "Martinez", "Robinson", "Clark", "Rodriguez", "Lewis", "Lee",
    "Walker", "Hall", "Allen", "Young", "Hernandez", "King",
]
_DEPARTMENTS = [
    "Finance", "Human Resources", "Engineering", "Sales",
    "Marketing", "Operations", "Legal", "IT", "Executive", "Procurement",
]
_OS_VERSIONS = [
    "Windows 10 Pro 22H2", "Windows 11 Pro 23H2", "Windows 11 Enterprise 22H2",
    "Windows 10 Enterprise 21H2", "Ubuntu 22.04.3 LTS", "macOS 14.2 Sonoma",
]
_SERVER_OS = [
    "Windows Server 2022 Standard", "Windows Server 2019 Datacenter",
    "Ubuntu 22.04 LTS", "Red Hat Enterprise Linux 9.2",
]
_COMPANY_NAMES = [
    "Contoso", "Fabrikam", "Northwind", "Tailspin", "Woodgrove",
    "Adventure Works", "Alpine Ski House", "Bellows College",
]
_ATTACKER_IPS = [
    "185.220.101.34", "45.155.205.233", "91.219.236.174", "23.129.64.130",
    "104.244.76.13", "193.42.33.7", "5.188.86.114", "212.102.35.102",
    "185.56.83.82", "77.247.181.163", "195.176.3.23", "162.247.74.74",
    "198.98.56.149", "89.34.111.113", "103.75.201.4", "45.61.185.90",
    "194.165.16.78", "81.161.64.78", "176.111.174.26", "193.239.84.100",
]
_C2_DOMAINS = [
    "updates.microsoftservices.cc", "cdn-static.akamai-edge.io",
    "telemetry.google-analytics-api.com", "api.cloudfront-cdn.net",
    "sync.dropbox-content.cc", "update.windows-defender-atp.net",
    "cdn.jquery-cdn.io", "api.microsoft-telemetry.cc",
    "relay.fastly-edge.net", "beacon.cloudflare-analytics.cc",
]
_MALWARE_FILENAMES = [
    "svchost32.exe", "lsass_dump.exe", "winupd.exe", "chrome_helper.exe",
    "AdobeUpdater.exe", "OneDriveHelper.exe", "MicrosoftEdgeCP.exe",
    "taskmgr32.exe", "RuntimeBroker32.exe", "SearchIndexer32.exe",
]
_MALWARE_PATHS = [
    r"C:\Windows\Temp\{}", r"C:\Users\Public\Downloads\{}",
    r"C:\ProgramData\Microsoft\Windows\{}", r"C:\Windows\System32\{}",
    r"C:\Users\{user}\AppData\Local\Temp\{}",
    r"C:\Users\{user}\AppData\Roaming\Microsoft\{}",
]
_AWS_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]


def _rand_ip(subnet: str) -> str:
    return f"{subnet}.{random.randint(10, 250)}"


def _rand_hash_sha256() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _rand_hash_md5() -> str:
    return hashlib.md5(uuid.uuid4().bytes).hexdigest()


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _rand_guid() -> str:
    return str(uuid.uuid4()).upper()


# ── SimulationContext dataclass ───────────────────────────────────────────────

@dataclass
class SimulationContext:
    """All shared entities for one simulation session.

    Every log generator receives this object and reads entities from it
    instead of picking random values. This ensures cross-source coherence:
    the same user/host/IP/hash appears in EDR, SIEM, firewall, and cloud logs.
    """

    # ── Session identity ──────────────────────────────────────────────────
    session_id: str
    environment_id: str | None = None

    # ── Attacker / threat infrastructure ────────────────────────────────
    attacker_ip: str = ""           # primary C2 / attacker egress IP
    attacker_ip_2: str = ""         # secondary C2 IP
    c2_domain: str = ""             # primary C2 domain (looks legitimate)
    c2_domain_2: str = ""           # secondary C2 domain
    malware_hash_sha256: str = ""   # malware hash — same across EDR + network
    malware_hash_md5: str = ""
    malware_filename: str = ""      # e.g. "svchost32.exe"
    malware_filepath: str = ""      # full path including filename
    malware_parent_process: str = "explorer.exe"  # spawning process

    # ── Primary victim (patient zero) ───────────────────────────────────
    victim_username: str = ""       # short login name e.g. "jsmith"
    victim_display_name: str = ""   # full name e.g. "John Smith"
    victim_email: str = ""          # e.g. "jsmith@corp.local"
    victim_hostname: str = ""       # e.g. "WKSTN-FIN-042"
    victim_ip: str = ""             # e.g. "192.168.1.45"
    victim_os: str = ""             # e.g. "Windows 10 Pro 22H2"
    victim_department: str = ""     # e.g. "Finance"
    victim_asset_tag: str = ""      # physical asset tag from CMDB
    victim_serial: str = ""         # device serial number

    # ── Secondary target (lateral movement destination) ─────────────────
    lateral_username: str = ""
    lateral_display_name: str = ""
    lateral_hostname: str = ""
    lateral_ip: str = ""
    lateral_department: str = ""

    # ── Privileged account (escalation target) ──────────────────────────
    admin_username: str = "administrator"
    admin_display_name: str = "Domain Administrator"
    admin_email: str = ""

    # ── Service accounts ────────────────────────────────────────────────
    svc_account_1: str = "svc_backup"
    svc_account_2: str = "svc_sql"

    # ── Domain controller / servers ─────────────────────────────────────
    dc_hostname: str = ""
    dc_ip: str = ""
    fileserver_hostname: str = ""
    fileserver_ip: str = ""
    appserver_hostname: str = ""
    appserver_ip: str = ""

    # ── Network infrastructure ───────────────────────────────────────────
    domain: str = ""                # Windows domain e.g. "corp.local"
    domain_fqdn: str = ""           # e.g. "corp.contoso.local"
    company_name: str = ""          # e.g. "Contoso"
    subnet_internal: str = ""       # e.g. "192.168.1" (no trailing dot)
    subnet_servers: str = ""        # e.g. "10.0.0"
    gateway_ip: str = ""
    dns_server_ip: str = ""
    proxy_ip: str = ""

    # ── Cloud identity / infrastructure ─────────────────────────────────
    cloud_user_email: str = ""      # e.g. "jsmith@contoso.com"
    cloud_tenant_id: str = ""       # Azure tenant / GSuite customer ID
    aws_account_id: str = ""        # e.g. "123456789012"
    aws_region: str = ""            # e.g. "us-east-1"
    azure_subscription_id: str = ""
    s3_bucket_name: str = ""        # target bucket for exfil scenario
    aws_iam_role: str = ""          # e.g. "DevOpsRole"

    # ── Timeline (attack phases) ─────────────────────────────────────────
    attack_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    phase_timings: dict[str, str] = field(default_factory=dict)

    # ── Product context ──────────────────────────────────────────────────
    products: dict[str, str] = field(default_factory=dict)

    # ── Source metadata ──────────────────────────────────────────────────
    from_cmdb: bool = False         # True when entities loaded from CMDB
    org_id: int | None = None

    # ── Computed helpers ──────────────────────────────────────────────────

    @property
    def victim_sid(self) -> str:
        """Deterministic Windows SID-style string from username."""
        h = int(hashlib.md5(self.victim_username.encode()).hexdigest()[:8], 16)
        return f"S-1-5-21-{h % 4294967295}-{(h >> 8) % 4294967295}-{(h >> 16) % 4294967295}-1234"

    @property
    def attack_start_iso(self) -> str:
        return self.attack_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def phase_time(self, phase: str, offset_minutes: int = 0) -> str:
        """Get ISO timestamp for a named attack phase (or offset from start)."""
        if phase in self.phase_timings:
            return self.phase_timings[phase]
        t = self.attack_start + timedelta(minutes=offset_minutes)
        return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def to_substitution_map(self) -> dict[str, str]:
        """Flat dict for template placeholder substitution.

        Keys match the ``__PLACEHOLDER__`` tokens used in agentic_generator
        templates AND the ``{field}`` tokens in benign_library/ttp_library.
        """
        return {
            # Attacker
            "__ATTACKER_IP__": self.attacker_ip,
            "__ATTACKER_IP_2__": self.attacker_ip_2,
            "__C2_DOMAIN__": self.c2_domain,
            "__C2_DOMAIN_2__": self.c2_domain_2,
            "__MALWARE_HASH_SHA256__": self.malware_hash_sha256,
            "__MALWARE_HASH_MD5__": self.malware_hash_md5,
            "__MALWARE_FILENAME__": self.malware_filename,
            "__MALWARE_FILEPATH__": self.malware_filepath,
            "__MALWARE_PARENT__": self.malware_parent_process,
            # Legacy tokens (used in agentic_generator._render_template)
            "__EXTERNAL_IP__": self.attacker_ip,
            # Victim
            "__USER__": self.victim_username,
            "__USERNAME__": self.victim_username,
            "__DISPLAY_NAME__": self.victim_display_name,
            "__EMAIL__": self.victim_email,
            "__HOST__": self.victim_hostname,
            "__HOSTNAME__": self.victim_hostname,
            "__INTERNAL_IP__": self.victim_ip,
            "__VICTIM_IP__": self.victim_ip,
            "__OS__": self.victim_os,
            "__DEPARTMENT__": self.victim_department,
            "__ASSET_TAG__": self.victim_asset_tag,
            "__SERIAL__": self.victim_serial,
            "__SID__": self.victim_sid,
            # Lateral target
            "__LATERAL_USER__": self.lateral_username,
            "__LATERAL_HOST__": self.lateral_hostname,
            "__LATERAL_IP__": self.lateral_ip,
            # Admin
            "__ADMIN_USER__": self.admin_username,
            "__ADMIN_EMAIL__": self.admin_email,
            # Service accounts
            "__SVC_ACCOUNT_1__": self.svc_account_1,
            "__SVC_ACCOUNT_2__": self.svc_account_2,
            # Infrastructure
            "__DC_HOST__": self.dc_hostname,
            "__DC_IP__": self.dc_ip,
            "__FILESERVER_HOST__": self.fileserver_hostname,
            "__FILESERVER_IP__": self.fileserver_ip,
            "__APPSERVER_HOST__": self.appserver_hostname,
            "__APPSERVER_IP__": self.appserver_ip,
            # Network
            "__DOMAIN__": self.domain,
            "__DOMAIN_FQDN__": self.domain_fqdn,
            "__COMPANY__": self.company_name,
            "__GATEWAY_IP__": self.gateway_ip,
            "__DNS_IP__": self.dns_server_ip,
            # Cloud
            "__CLOUD_EMAIL__": self.cloud_user_email,
            "__AWS_ACCOUNT__": self.aws_account_id,
            "__AWS_REGION__": self.aws_region,
            "__AZURE_SUBSCRIPTION__": self.azure_subscription_id,
            "__AZURE_TENANT__": self.cloud_tenant_id,
            "__S3_BUCKET__": self.s3_bucket_name,
            "__IAM_ROLE__": self.aws_iam_role,
            # Timestamps
            "__TIMESTAMP__": self.attack_start_iso,
        }

    def to_prompt_context(self) -> str:
        """Formatted block for injection into LLM generation prompts.

        The generator agent includes this block so every LLM-generated
        log uses the correct entities instead of inventing new ones.
        """
        lines = [
            "## SIMULATION CONTEXT — DO NOT DEVIATE FROM THESE VALUES",
            "Use EXACTLY these entity values in every generated event:\n",
            f"  Victim user:      {self.victim_username} ({self.victim_display_name})",
            f"  Victim email:     {self.victim_email}",
            f"  Victim host:      {self.victim_hostname}  [{self.victim_ip}]",
            f"  Victim OS:        {self.victim_os}",
            f"  Victim dept:      {self.victim_department}",
            f"  Lateral target:   {self.lateral_hostname}  [{self.lateral_ip}]  user={self.lateral_username}",
            f"  Domain:           {self.domain}  ({self.domain_fqdn})",
            f"  Domain controller:{self.dc_hostname}  [{self.dc_ip}]",
            f"  Admin account:    {self.admin_username}",
            "",
            f"  Attacker IP:      {self.attacker_ip}  (also: {self.attacker_ip_2})",
            f"  C2 domain:        {self.c2_domain}  (also: {self.c2_domain_2})",
            f"  Malware file:     {self.malware_filename}",
            f"  Malware path:     {self.malware_filepath}",
            f"  SHA256:           {self.malware_hash_sha256}",
            f"  MD5:              {self.malware_hash_md5}",
            "",
            f"  AWS account:      {self.aws_account_id}  region={self.aws_region}",
            f"  Cloud email:      {self.cloud_user_email}",
            "",
            f"  Attack started:   {self.attack_start_iso}",
            "  Timestamps must progress chronologically from attack_start.",
            "",
            "RULE: Every field that refers to user/host/IP/hash/domain MUST use",
            "      one of the values above. Never invent different ones.",
        ]
        if self.from_cmdb:
            lines.insert(1, "  ⚡ Entities loaded from live CMDB — these are real org assets.\n")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["attack_start"] = self.attack_start.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SimulationContext":
        d = dict(d)
        if isinstance(d.get("attack_start"), str):
            d["attack_start"] = datetime.fromisoformat(d["attack_start"])
        return cls(**d)


# ── ContextBuilder ────────────────────────────────────────────────────────────

class ContextBuilder:
    """Build a SimulationContext for a session.

    Usage:
        ctx = await ContextBuilder.build(session_id, environment_id, db)
        # → tries CMDB first, falls back to synthetic
    """

    @staticmethod
    async def build(
        session_id: str,
        environment_id: str | None,
        db: Any,                            # AsyncSession
        products: dict[str, str] | None = None,
    ) -> SimulationContext:
        """Create context, loading from CMDB when data is available."""
        try:
            ctx = await ContextBuilder._from_cmdb(session_id, environment_id, db, products or {})
            if ctx:
                return ctx
        except Exception:
            pass
        return ContextBuilder._synthetic(session_id, environment_id, products or {})

    @staticmethod
    async def _from_cmdb(
        session_id: str,
        environment_id: str | None,
        db: Any,
        products: dict[str, str],
    ) -> SimulationContext | None:
        """Try to build context from real CMDB data."""
        from sqlalchemy import select, func
        from backend.db.models import CMDBPerson, CMDBHardwareAsset, ProductCloudAccount

        # Need at least 2 people + 2 assets
        people_count = await db.scalar(select(func.count()).select_from(CMDBPerson))
        asset_count = await db.scalar(select(func.count()).select_from(CMDBHardwareAsset))
        if not people_count or people_count < 2 or not asset_count or asset_count < 2:
            return None

        # Pick victim — prefer non-IT/non-admin departments (more interesting)
        victim_q = await db.execute(
            select(CMDBPerson)
            .where(CMDBPerson.status == "active")
            .where(CMDBPerson.department.notin_(["IT", "Information Technology", "Security"]))
            .order_by(func.random())
            .limit(1)
        )
        victim_person = victim_q.scalar_one_or_none()
        if not victim_person:
            victim_q = await db.execute(
                select(CMDBPerson).where(CMDBPerson.status == "active").order_by(func.random()).limit(1)
            )
            victim_person = victim_q.scalar_one_or_none()
        if not victim_person:
            return None

        # Get victim's assigned hardware asset
        victim_asset_q = await db.execute(
            select(CMDBHardwareAsset)
            .where(CMDBHardwareAsset.assigned_to_id == victim_person.id)
            .where(CMDBHardwareAsset.asset_type.in_(["laptop", "desktop", "workstation"]))
            .limit(1)
        )
        victim_asset = victim_asset_q.scalar_one_or_none()
        if not victim_asset:
            # Just pick any laptop
            victim_asset_q = await db.execute(
                select(CMDBHardwareAsset)
                .where(CMDBHardwareAsset.asset_type.in_(["laptop", "desktop", "workstation"]))
                .order_by(func.random()).limit(1)
            )
            victim_asset = victim_asset_q.scalar_one_or_none()

        # Pick lateral movement target — different person, preferably IT or admin
        lateral_q = await db.execute(
            select(CMDBPerson)
            .where(CMDBPerson.id != victim_person.id)
            .where(CMDBPerson.status == "active")
            .order_by(func.random())
            .limit(1)
        )
        lateral_person = lateral_q.scalar_one_or_none()

        # Get a server asset for DC simulation
        server_q = await db.execute(
            select(CMDBHardwareAsset)
            .where(CMDBHardwareAsset.asset_type == "server")
            .order_by(func.random()).limit(2)
        )
        servers = server_q.scalars().all()

        # Get cloud account
        cloud_q = await db.execute(
            select(ProductCloudAccount).order_by(func.random()).limit(1)
        )
        cloud_account = cloud_q.scalar_one_or_none()

        # Build username from person
        def make_username(p: CMDBPerson) -> str:
            if p.email:
                return p.email.split("@")[0]
            first = (p.first_name or "").lower()
            last = (p.last_name or "").lower()
            return f"{first[0]}{last}" if first and last else f"user{p.id}"[:8]

        victim_username = make_username(victim_person)
        company = (victim_person.email or "").split("@")[-1].split(".")[0].capitalize() or "Contoso"
        domain = (victim_person.email or "corp.local").split("@")[-1] if victim_person.email else "corp.local"

        subnet_internal = "192.168.1"
        subnet_servers = "10.0.0"

        ctx = ContextBuilder._build_common(
            session_id=session_id,
            environment_id=environment_id,
            products=products,
            victim_username=victim_username,
            victim_display_name=f"{victim_person.first_name or ''} {victim_person.last_name or ''}".strip(),
            victim_email=victim_person.email or f"{victim_username}@{domain}",
            victim_hostname=getattr(victim_asset, "hostname", None) or _rand_hostname("WKSTN", victim_person.department or "USR"),
            victim_ip=getattr(victim_asset, "ip_address", None) or _rand_ip(subnet_internal),
            victim_os=getattr(victim_asset, "os_version", None) or random.choice(_OS_VERSIONS),
            victim_department=victim_person.department or "Finance",
            victim_asset_tag=getattr(victim_asset, "asset_tag", None) or "",
            victim_serial=getattr(victim_asset, "serial_number", None) or "",
            lateral_username=make_username(lateral_person) if lateral_person else "agarcia",
            lateral_display_name=f"{(lateral_person.first_name or '')} {(lateral_person.last_name or '')}".strip() if lateral_person else "Alex Garcia",
            lateral_hostname=_rand_hostname("WKSTN", lateral_person.department if lateral_person else "IT"),
            lateral_ip=_rand_ip(subnet_internal),
            lateral_department=lateral_person.department if lateral_person else "IT",
            domain=domain,
            company_name=company,
            subnet_internal=subnet_internal,
            subnet_servers=subnet_servers,
            dc_hostname=getattr(servers[0], "hostname", None) if servers else _rand_hostname("SRV-DC"),
            dc_ip=getattr(servers[0], "ip_address", None) if servers else _rand_ip(subnet_servers),
            fileserver_hostname=getattr(servers[1], "hostname", None) if len(servers) > 1 else _rand_hostname("SRV-FILE"),
            fileserver_ip=getattr(servers[1], "ip_address", None) if len(servers) > 1 else _rand_ip(subnet_servers),
            aws_account_id=getattr(cloud_account, "account_id", None) or f"{random.randint(100000000000, 999999999999)}",
            aws_region=getattr(cloud_account, "primary_region", None) or random.choice(_AWS_REGIONS),
            from_cmdb=True,
        )
        return ctx

    @staticmethod
    def _synthetic(
        session_id: str,
        environment_id: str | None,
        products: dict[str, str],
    ) -> SimulationContext:
        """Build a fully synthetic context — realistic random but session-stable."""
        subnet_internal = f"192.168.{random.randint(1, 10)}"
        subnet_servers = f"10.{random.randint(0, 5)}.{random.randint(0, 5)}"
        company = random.choice(_COMPANY_NAMES)
        domain = f"corp.{company.lower().replace(' ', '')}.local"

        first = random.choice(_FIRST_NAMES)
        last = random.choice(_LAST_NAMES)
        victim_username = f"{first[0].lower()}{last.lower()}"
        dept = random.choice(_DEPARTMENTS)

        lat_first = random.choice(_FIRST_NAMES)
        lat_last = random.choice(_LAST_NAMES)
        lateral_username = f"{lat_first[0].lower()}{lat_last.lower()}"

        return ContextBuilder._build_common(
            session_id=session_id,
            environment_id=environment_id,
            products=products,
            victim_username=victim_username,
            victim_display_name=f"{first} {last}",
            victim_email=f"{victim_username}@{domain}",
            victim_hostname=_rand_hostname("WKSTN", dept),
            victim_ip=_rand_ip(subnet_internal),
            victim_os=random.choice(_OS_VERSIONS),
            victim_department=dept,
            victim_asset_tag=f"ASSET-{random.randint(1000, 9999)}",
            victim_serial=f"SN{random.randint(100000, 999999)}",
            lateral_username=lateral_username,
            lateral_display_name=f"{lat_first} {lat_last}",
            lateral_hostname=_rand_hostname("WKSTN", "IT"),
            lateral_ip=_rand_ip(subnet_internal),
            lateral_department="IT",
            domain=domain,
            company_name=company,
            subnet_internal=subnet_internal,
            subnet_servers=subnet_servers,
            dc_hostname=_rand_hostname("SRV-DC"),
            dc_ip=_rand_ip(subnet_servers),
            fileserver_hostname=_rand_hostname("SRV-FILE"),
            fileserver_ip=_rand_ip(subnet_servers),
            aws_account_id=str(random.randint(100000000000, 999999999999)),
            aws_region=random.choice(_AWS_REGIONS),
            from_cmdb=False,
        )

    @staticmethod
    def _build_common(
        session_id: str,
        environment_id: str | None,
        products: dict[str, str],
        victim_username: str,
        victim_display_name: str,
        victim_email: str,
        victim_hostname: str,
        victim_ip: str,
        victim_os: str,
        victim_department: str,
        victim_asset_tag: str,
        victim_serial: str,
        lateral_username: str,
        lateral_display_name: str,
        lateral_hostname: str,
        lateral_ip: str,
        lateral_department: str,
        domain: str,
        company_name: str,
        subnet_internal: str,
        subnet_servers: str,
        dc_hostname: str,
        dc_ip: str,
        fileserver_hostname: str,
        fileserver_ip: str,
        aws_account_id: str,
        aws_region: str,
        from_cmdb: bool = False,
        appserver_hostname: str = "",
        appserver_ip: str = "",
    ) -> SimulationContext:
        attacker_ip = random.choice(_ATTACKER_IPS)
        attacker_ip_2 = random.choice([ip for ip in _ATTACKER_IPS if ip != attacker_ip])
        c2_domain = random.choice(_C2_DOMAINS)
        c2_domain_2 = random.choice([d for d in _C2_DOMAINS if d != c2_domain])
        malware_filename = random.choice(_MALWARE_FILENAMES)
        malware_path_tpl = random.choice(_MALWARE_PATHS)
        malware_filepath = malware_path_tpl.format(malware_filename, user=victim_username)
        attack_start = datetime.now(timezone.utc) - timedelta(minutes=random.randint(30, 120))

        # Phase timings — chronological attack chain offsets in minutes
        phase_timings = {
            "initial_access":     (attack_start + timedelta(minutes=0)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "execution":          (attack_start + timedelta(minutes=random.randint(2, 8))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "persistence":        (attack_start + timedelta(minutes=random.randint(10, 20))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "privilege_esc":      (attack_start + timedelta(minutes=random.randint(22, 40))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "defense_evasion":    (attack_start + timedelta(minutes=random.randint(42, 60))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "credential_access":  (attack_start + timedelta(minutes=random.randint(62, 90))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "discovery":          (attack_start + timedelta(minutes=random.randint(92, 120))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lateral_movement":   (attack_start + timedelta(minutes=random.randint(122, 160))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "collection":         (attack_start + timedelta(minutes=random.randint(162, 200))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "exfiltration":       (attack_start + timedelta(minutes=random.randint(202, 240))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "impact":             (attack_start + timedelta(minutes=random.randint(242, 300))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

        cloud_user_email = f"{victim_username}@{company_name.lower()}.com" if not victim_email.endswith(".com") else victim_email
        domain_fqdn = f"corp.{domain}" if not domain.startswith("corp.") else domain
        admin_email = f"administrator@{domain}"
        appserver_hostname = appserver_hostname or _rand_hostname("SRV-APP")
        appserver_ip = appserver_ip or _rand_ip(subnet_servers)

        return SimulationContext(
            session_id=session_id,
            environment_id=environment_id,
            attacker_ip=attacker_ip,
            attacker_ip_2=attacker_ip_2,
            c2_domain=c2_domain,
            c2_domain_2=c2_domain_2,
            malware_hash_sha256=_rand_hash_sha256(),
            malware_hash_md5=_rand_hash_md5(),
            malware_filename=malware_filename,
            malware_filepath=malware_filepath,
            malware_parent_process="explorer.exe",
            victim_username=victim_username,
            victim_display_name=victim_display_name,
            victim_email=victim_email,
            victim_hostname=victim_hostname,
            victim_ip=victim_ip,
            victim_os=victim_os,
            victim_department=victim_department,
            victim_asset_tag=victim_asset_tag,
            victim_serial=victim_serial,
            lateral_username=lateral_username,
            lateral_display_name=lateral_display_name,
            lateral_hostname=lateral_hostname,
            lateral_ip=lateral_ip,
            lateral_department=lateral_department,
            admin_username="administrator",
            admin_display_name="Domain Administrator",
            admin_email=admin_email,
            svc_account_1="svc_backup",
            svc_account_2="svc_sql",
            dc_hostname=dc_hostname,
            dc_ip=dc_ip,
            fileserver_hostname=fileserver_hostname,
            fileserver_ip=fileserver_ip,
            appserver_hostname=appserver_hostname,
            appserver_ip=appserver_ip,
            domain=domain,
            domain_fqdn=domain_fqdn,
            company_name=company_name,
            subnet_internal=subnet_internal,
            subnet_servers=subnet_servers,
            gateway_ip=f"{subnet_internal}.1",
            dns_server_ip=f"{subnet_internal}.5",
            proxy_ip=f"{subnet_internal}.254",
            cloud_user_email=cloud_user_email,
            cloud_tenant_id=str(uuid.uuid4()),
            aws_account_id=aws_account_id,
            aws_region=aws_region,
            azure_subscription_id=str(uuid.uuid4()),
            s3_bucket_name=f"{company_name.lower().replace(' ', '-')}-prod-data",
            aws_iam_role="DevOpsRole",
            attack_start=attack_start,
            phase_timings=phase_timings,
            products=products,
            from_cmdb=from_cmdb,
        )


# ── Redis persistence helpers ──────────────────────────────────────────────────

_CTX_PREFIX = "simctx:"
_CTX_TTL = 86400  # 24 hours


async def save_context(ctx: SimulationContext, redis: Any) -> None:
    """Persist SimulationContext to Redis for cross-task sharing."""
    key = f"{_CTX_PREFIX}{ctx.session_id}"
    await redis.set(key, json.dumps(ctx.to_dict()), ex=_CTX_TTL)


async def load_context(session_id: str, redis: Any) -> SimulationContext | None:
    """Load SimulationContext from Redis."""
    key = f"{_CTX_PREFIX}{session_id}"
    raw = await redis.get(key)
    if not raw:
        return None
    return SimulationContext.from_dict(json.loads(raw))


# ── Utility ───────────────────────────────────────────────────────────────────

def _rand_hostname(prefix: str, dept: str = "") -> str:
    dept_code = {
        "Finance": "FIN", "Human Resources": "HR", "Engineering": "ENG",
        "Sales": "SLS", "Marketing": "MKT", "Operations": "OPS",
        "Legal": "LGL", "IT": "IT", "Executive": "EXEC", "Procurement": "PROC",
    }.get(dept, dept[:3].upper() if dept else "GEN")
    return f"{prefix}-{dept_code}-{random.randint(100, 999):03d}"
