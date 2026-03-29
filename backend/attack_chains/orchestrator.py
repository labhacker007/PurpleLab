"""Attack Chain Orchestrator.

Executes multi-stage attack simulations defined as YAML chain files.
Each chain specifies a sequence of MITRE ATT&CK techniques with the
log sources that should produce evidence and timing between stages.

Chain YAML schema::

    id: lateral_movement_to_exfil
    name: "Lateral Movement to Exfiltration"
    threat_actor: "APT29"          # optional — links to Joti intel
    description: "..."
    stages:
      - id: initial_access
        technique: T1566.001        # Spearphishing Attachment
        sources: [windows_security]
        delay_seconds: 0
        count: 3

      - id: execution
        technique: T1059.001        # PowerShell
        sources: [windows_sysmon, windows_security]
        delay_seconds: 30
        count: 5
        depends_on: initial_access  # optional ordering dependency

      - id: credential_access
        technique: T1003.001        # LSASS Memory
        sources: [windows_sysmon]
        delay_seconds: 60
        count: 3
        depends_on: execution

      - id: lateral_movement
        technique: T1078
        sources: [windows_security]
        delay_seconds: 90
        count: 5
        depends_on: credential_access

      - id: exfiltration
        technique: T1048
        sources: [palo_alto_panos, dns]
        delay_seconds: 120
        count: 3
        depends_on: lateral_movement

    snr_ratio: 0.15    # 15% attack events, 85% noise — realistic ratio

A shared correlation_id is injected into every event so analysts can
trace the full chain across log sources.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ChainStage:
    id: str
    technique: str
    sources: list[str]
    delay_seconds: float = 0.0
    count: int = 5
    depends_on: str | None = None


@dataclass
class AttackChain:
    id: str
    name: str
    description: str
    stages: list[ChainStage]
    threat_actor: str | None = None
    snr_ratio: float = 0.15

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackChain":
        stages = [
            ChainStage(
                id=s["id"],
                technique=s["technique"],
                sources=s.get("sources", []),
                delay_seconds=float(s.get("delay_seconds", 0)),
                count=int(s.get("count", 5)),
                depends_on=s.get("depends_on"),
            )
            for s in data.get("stages", [])
        ]
        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            description=data.get("description", ""),
            stages=stages,
            threat_actor=data.get("threat_actor"),
            snr_ratio=float(data.get("snr_ratio", 0.15)),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "AttackChain":
        with open(path, "r") as fh:
            data = yaml.safe_load(fh)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_str(cls, content: str) -> "AttackChain":
        return cls.from_dict(yaml.safe_load(content))


@dataclass
class StageResult:
    stage_id: str
    technique: str
    events: list[dict[str, Any]]
    duration_ms: float
    error: str | None = None

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass
class ChainRunResult:
    chain_id: str
    run_id: str
    correlation_id: str
    total_events: int
    stage_results: list[StageResult]
    started_at: str
    completed_at: str
    duration_seconds: float
    threat_actor: str | None = None
    errors: list[str] = field(default_factory=list)

    def all_events(self) -> list[dict[str, Any]]:
        events = []
        for sr in self.stage_results:
            events.extend(sr.events)
        return events

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "run_id": self.run_id,
            "correlation_id": self.correlation_id,
            "total_events": self.total_events,
            "threat_actor": self.threat_actor,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "stages": [
                {
                    "stage_id": sr.stage_id,
                    "technique": sr.technique,
                    "event_count": sr.event_count,
                    "duration_ms": round(sr.duration_ms, 1),
                    "error": sr.error,
                }
                for sr in self.stage_results
            ],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AttackChainOrchestrator:
    """Executes attack chains by coordinating the AgenticLogGenerator.

    Stages run sequentially by default (respecting depends_on) but stages
    at the same dependency level can run in parallel when parallelise=True.
    """

    def __init__(self) -> None:
        from backend.log_sources.agentic_generator import get_generator
        self._gen = get_generator()
        self._builtin_chains: dict[str, AttackChain] = {}
        self._load_builtin_chains()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        chain: AttackChain,
        simulate_delays: bool = False,
        parallelise: bool = False,
    ) -> ChainRunResult:
        """Execute all stages of an attack chain.

        Args:
            chain: AttackChain definition.
            simulate_delays: If True, add real async sleep between stages
                             (useful for real-time testing in a SIEM).
            parallelise: If True, stages without dependencies run concurrently.

        Returns:
            ChainRunResult with all generated events tagged with correlation_id.
        """
        run_id = str(uuid.uuid4())
        correlation_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc)

        logger.info(
            "Starting chain '%s' run_id=%s corr=%s",
            chain.id, run_id, correlation_id
        )

        stage_results: list[StageResult] = []
        errors: list[str] = []

        if parallelise:
            stage_results = await self._run_parallel(
                chain, correlation_id, simulate_delays
            )
        else:
            stage_results = await self._run_sequential(
                chain, correlation_id, simulate_delays
            )

        errors = [sr.error for sr in stage_results if sr.error]
        completed = datetime.now(timezone.utc)
        total_events = sum(sr.event_count for sr in stage_results)

        logger.info(
            "Chain '%s' completed: %d events in %.1fs",
            chain.id,
            total_events,
            (completed - started).total_seconds(),
        )

        return ChainRunResult(
            chain_id=chain.id,
            run_id=run_id,
            correlation_id=correlation_id,
            total_events=total_events,
            stage_results=stage_results,
            started_at=started.isoformat(),
            completed_at=completed.isoformat(),
            duration_seconds=(completed - started).total_seconds(),
            threat_actor=chain.threat_actor,
            errors=errors,
        )

    async def run_yaml(
        self,
        yaml_content: str,
        simulate_delays: bool = False,
    ) -> ChainRunResult:
        """Parse YAML string and run the chain."""
        chain = AttackChain.from_yaml_str(yaml_content)
        return await self.run(chain, simulate_delays=simulate_delays)

    def get_builtin_chain(self, chain_id: str) -> AttackChain | None:
        return self._builtin_chains.get(chain_id)

    def list_builtin_chains(self) -> list[dict[str, Any]]:
        return [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "threat_actor": c.threat_actor,
                "stage_count": len(c.stages),
                "techniques": [s.technique for s in c.stages],
            }
            for c in self._builtin_chains.values()
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_sequential(
        self,
        chain: AttackChain,
        correlation_id: str,
        simulate_delays: bool,
    ) -> list[StageResult]:
        results = []
        for stage in chain.stages:
            if simulate_delays and stage.delay_seconds > 0:
                await asyncio.sleep(stage.delay_seconds)
            result = await self._run_stage(stage, chain.snr_ratio, correlation_id)
            results.append(result)
        return results

    async def _run_parallel(
        self,
        chain: AttackChain,
        correlation_id: str,
        simulate_delays: bool,
    ) -> list[StageResult]:
        """Run stages in parallel where possible (no dependency ordering)."""
        tasks = [
            self._run_stage(stage, chain.snr_ratio, correlation_id)
            for stage in chain.stages
        ]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    async def _run_stage(
        self,
        stage: ChainStage,
        snr_ratio: float,
        correlation_id: str,
    ) -> StageResult:
        t0 = asyncio.get_event_loop().time()
        all_events: list[dict[str, Any]] = []
        error = None

        try:
            per_source = max(1, stage.count // max(len(stage.sources), 1))
            tasks = [
                self._gen.generate(
                    source_id=src,
                    technique_id=stage.technique,
                    count=per_source,
                    snr_ratio=snr_ratio,
                )
                for src in stage.sources
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for src, res in zip(stage.sources, results):
                if isinstance(res, Exception):
                    logger.warning("Stage %s / %s failed: %s", stage.id, src, res)
                    error = str(res)
                else:
                    events = res.get("events", [])
                    for e in events:
                        e["_chain_correlation_id"] = correlation_id
                        e["_chain_stage"] = stage.id
                    all_events.extend(events)

        except Exception as exc:
            logger.exception("Stage '%s' failed", stage.id)
            error = str(exc)

        duration_ms = (asyncio.get_event_loop().time() - t0) * 1000
        return StageResult(
            stage_id=stage.id,
            technique=stage.technique,
            events=all_events,
            duration_ms=duration_ms,
            error=error,
        )

    def _load_builtin_chains(self) -> None:
        """Load the bundled attack chain definitions."""
        for chain_dict in _BUILTIN_CHAIN_DEFS:
            try:
                chain = AttackChain.from_dict(chain_dict)
                self._builtin_chains[chain.id] = chain
            except Exception as exc:
                logger.warning("Failed to load builtin chain: %s", exc)


# ---------------------------------------------------------------------------
# Built-in chain definitions
# ---------------------------------------------------------------------------

_BUILTIN_CHAIN_DEFS: list[dict[str, Any]] = [
    {
        "id": "apt29_credential_harvest",
        "name": "APT29 Credential Harvest & Lateral Movement",
        "description": (
            "Simulates APT29 phishing → PowerShell execution → credential dumping "
            "→ lateral movement using valid accounts."
        ),
        "threat_actor": "APT29",
        "snr_ratio": 0.15,
        "stages": [
            {
                "id": "phishing_delivery",
                "technique": "T1566.001",
                "sources": ["windows_security"],
                "delay_seconds": 0,
                "count": 2,
            },
            {
                "id": "powershell_execution",
                "technique": "T1059.001",
                "sources": ["windows_sysmon", "windows_security"],
                "delay_seconds": 30,
                "count": 5,
                "depends_on": "phishing_delivery",
            },
            {
                "id": "credential_dump",
                "technique": "T1003.001",
                "sources": ["windows_sysmon"],
                "delay_seconds": 60,
                "count": 3,
                "depends_on": "powershell_execution",
            },
            {
                "id": "lateral_movement",
                "technique": "T1078",
                "sources": ["windows_security"],
                "delay_seconds": 90,
                "count": 5,
                "depends_on": "credential_dump",
            },
        ],
    },
    {
        "id": "cloud_account_takeover",
        "name": "Cloud Account Takeover & Data Exfiltration",
        "description": (
            "Simulates password spraying → cloud console access → data enumeration "
            "→ S3/GCS exfiltration."
        ),
        "snr_ratio": 0.10,
        "stages": [
            {
                "id": "password_spray",
                "technique": "T1110.003",
                "sources": ["aws_cloudtrail"],
                "delay_seconds": 0,
                "count": 10,
            },
            {
                "id": "console_login",
                "technique": "T1078",
                "sources": ["aws_cloudtrail"],
                "delay_seconds": 30,
                "count": 3,
                "depends_on": "password_spray",
            },
            {
                "id": "resource_discovery",
                "technique": "T1087",
                "sources": ["aws_cloudtrail", "gcp_audit"],
                "delay_seconds": 60,
                "count": 5,
                "depends_on": "console_login",
            },
            {
                "id": "exfiltration",
                "technique": "T1048",
                "sources": ["aws_cloudtrail", "cloudflare"],
                "delay_seconds": 90,
                "count": 4,
                "depends_on": "resource_discovery",
            },
        ],
    },
    {
        "id": "ransomware_precursor",
        "name": "Ransomware Precursor (Initial Access → Persistence → Impact)",
        "description": (
            "Simulates exploitation → service installation → inhibit recovery "
            "→ data encryption — typical ransomware precursor TTPs."
        ),
        "snr_ratio": 0.20,
        "stages": [
            {
                "id": "exploitation",
                "technique": "T1190",
                "sources": ["palo_alto_panos"],
                "delay_seconds": 0,
                "count": 3,
            },
            {
                "id": "service_persistence",
                "technique": "T1543.003",
                "sources": ["windows_security", "windows_sysmon"],
                "delay_seconds": 60,
                "count": 3,
                "depends_on": "exploitation",
            },
            {
                "id": "inhibit_recovery",
                "technique": "T1490",
                "sources": ["windows_sysmon"],
                "delay_seconds": 120,
                "count": 2,
                "depends_on": "service_persistence",
            },
            {
                "id": "encryption",
                "technique": "T1486",
                "sources": ["windows_security", "windows_sysmon"],
                "delay_seconds": 180,
                "count": 5,
                "depends_on": "inhibit_recovery",
            },
        ],
    },
    {
        "id": "k8s_container_escape",
        "name": "Kubernetes Container Escape & Cluster Takeover",
        "description": (
            "Simulates exec-into-pod → secret theft → privileged pod creation "
            "→ cluster admin escalation."
        ),
        "snr_ratio": 0.12,
        "stages": [
            {
                "id": "initial_pod_exec",
                "technique": "T1611",
                "sources": ["kubernetes_audit"],
                "delay_seconds": 0,
                "count": 2,
            },
            {
                "id": "secret_access",
                "technique": "T1552.007",
                "sources": ["kubernetes_audit"],
                "delay_seconds": 20,
                "count": 4,
                "depends_on": "initial_pod_exec",
            },
            {
                "id": "privileged_container",
                "technique": "T1610",
                "sources": ["kubernetes_audit"],
                "delay_seconds": 40,
                "count": 2,
                "depends_on": "secret_access",
            },
            {
                "id": "cluster_admin_escalation",
                "technique": "T1098",
                "sources": ["kubernetes_audit"],
                "delay_seconds": 60,
                "count": 2,
                "depends_on": "privileged_container",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_orchestrator: AttackChainOrchestrator | None = None


def get_orchestrator() -> AttackChainOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AttackChainOrchestrator()
    return _orchestrator
