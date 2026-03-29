"""Joti Integration Client.

Provides a typed async client for the Joti SOC operations platform
(labhacker007/joti). PurpleLab uses Joti as the hunt/intel layer —
we send simulated alerts to Joti and pull HCCS, TES, and MITRE coverage
back to compute IHDS.

Auth: Joti API key format ``joti_<64 hex chars>``
SDK:  Also supports Joti's Python SDK if installed (joti.sdk).

Capabilities:
  - Send simulated alerts to Joti's webhook ingestion endpoint
  - Pull HCCS (Hunt Coverage Completeness Score)
  - Pull TES (Threat Exposure Score) with component breakdown
  - Pull MITRE coverage heatmap
  - Pull hunt gaps (high-prevalence techniques with no hunts)
  - Pull Sigma detection rules with MITRE tags
  - Pull threat actor intelligence with TTPs
  - Request attack chain predictions (Bayesian technique transitions)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

JOTI_API_V1 = "/api"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class JotiConfig:
    base_url: str                       # e.g. "https://joti.yourorg.com"
    api_key: str                        # "joti_<64 hex>"
    webhook_token: str = ""             # For alert ingestion
    timeout_seconds: float = 30.0
    verify_ssl: bool = True


@dataclass
class JotiHCCS:
    """Hunt Coverage Completeness Score from Joti."""
    score: float                        # 0.0–100.0
    covered_techniques: int
    total_techniques: int
    gaps: list[dict[str, Any]] = field(default_factory=list)
    computed_at: str = ""


@dataclass
class JotiTES:
    """Threat Exposure Score from Joti."""
    score: float                        # 0.0–100.0
    components: dict[str, float] = field(default_factory=dict)
    computed_at: str = ""


@dataclass
class AlertIngestionResult:
    """Result of sending an alert batch to Joti."""
    accepted: int
    rejected: int
    alert_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class JotiClient:
    """Async HTTP client for the Joti platform API.

    Usage::

        async with JotiClient(config) as client:
            hccs = await client.get_hccs()
            await client.send_alerts(events)
    """

    def __init__(self, config: JotiConfig) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "JotiClient":
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url,
            headers={
                "Authorization": f"Bearer {self._config.api_key}",
                "Content-Type": "application/json",
                "X-Source": "purplelab",
            },
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_ssl,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Alert Ingestion
    # ------------------------------------------------------------------

    async def send_alerts(
        self,
        events: list[dict[str, Any]],
        source_type: str = "purplelab_simulation",
    ) -> AlertIngestionResult:
        """Send simulated alert events to Joti for processing/scoring.

        Maps to: POST /api/alerts/ingest/{webhook_token}
        """
        if not self._config.webhook_token:
            return AlertIngestionResult(
                accepted=0,
                rejected=len(events),
                errors=["webhook_token not configured in JotiConfig"],
            )

        # Transform PurpleLab events to Joti alert format
        alerts = [_to_joti_alert(e, source_type) for e in events]

        try:
            resp = await self._post(
                f"/alerts/ingest/{self._config.webhook_token}",
                {"alerts": alerts},
            )
            return AlertIngestionResult(
                accepted=resp.get("accepted", len(alerts)),
                rejected=resp.get("rejected", 0),
                alert_ids=resp.get("alert_ids", []),
            )
        except Exception as exc:
            logger.error("Failed to send alerts to Joti: %s", exc)
            return AlertIngestionResult(
                accepted=0,
                rejected=len(events),
                errors=[str(exc)],
            )

    # ------------------------------------------------------------------
    # Scores
    # ------------------------------------------------------------------

    async def get_hccs(self) -> JotiHCCS | None:
        """GET /api/hunt-coverage/score — Hunt Coverage Completeness Score."""
        try:
            data = await self._get("/hunt-coverage/score")
            return JotiHCCS(
                score=float(data.get("score", 0.0)),
                covered_techniques=data.get("covered_techniques", 0),
                total_techniques=data.get("total_techniques", 0),
                computed_at=data.get("computed_at", ""),
            )
        except Exception as exc:
            logger.warning("get_hccs failed: %s", exc)
            return None

    async def get_hunt_gaps(self) -> list[dict[str, Any]]:
        """GET /api/hunt-coverage/gaps — High-prevalence techniques with no hunts."""
        try:
            data = await self._get("/hunt-coverage/gaps")
            return data.get("gaps", [])
        except Exception as exc:
            logger.warning("get_hunt_gaps failed: %s", exc)
            return []

    async def get_tes(self) -> JotiTES | None:
        """GET /api/analytics/threat-exposure-score — Threat Exposure Score."""
        try:
            data = await self._get("/analytics/threat-exposure-score")
            return JotiTES(
                score=float(data.get("score", 0.0)),
                components=data.get("components", {}),
                computed_at=data.get("computed_at", ""),
            )
        except Exception as exc:
            logger.warning("get_tes failed: %s", exc)
            return None

    async def get_mitre_coverage(self) -> dict[str, Any]:
        """GET /api/analytics/mitre-coverage — Per-technique coverage heatmap."""
        try:
            return await self._get("/analytics/mitre-coverage")
        except Exception as exc:
            logger.warning("get_mitre_coverage failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Detection Rules
    # ------------------------------------------------------------------

    async def get_sigma_rules(
        self,
        technique_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """GET /api/sigma/rules — Sigma rules with MITRE tags."""
        params: dict[str, Any] = {"limit": limit}
        if technique_id:
            params["technique_id"] = technique_id
        try:
            data = await self._get("/sigma/rules", params=params)
            return data.get("rules", [])
        except Exception as exc:
            logger.warning("get_sigma_rules failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Threat Intelligence
    # ------------------------------------------------------------------

    async def get_threat_actor_intel(
        self, actor_id: str
    ) -> dict[str, Any]:
        """GET /api/threat-actors/{id}/intelligence — Actor TTPs and tools."""
        try:
            return await self._get(f"/threat-actors/{actor_id}/intelligence")
        except Exception as exc:
            logger.warning("get_threat_actor_intel(%s) failed: %s", actor_id, exc)
            return {}

    async def predict_attack_chain(
        self,
        seed_techniques: list[str],
        actor_id: str | None = None,
        depth: int = 3,
    ) -> dict[str, Any]:
        """POST /api/attack-chain/predict — Bayesian next-technique prediction."""
        payload: dict[str, Any] = {
            "seed_techniques": seed_techniques,
            "depth": depth,
        }
        if actor_id:
            payload["actor_id"] = actor_id
        try:
            return await self._post("/attack-chain/predict", payload)
        except Exception as exc:
            logger.warning("predict_attack_chain failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Composite: Pull everything needed for IHDS
    # ------------------------------------------------------------------

    async def get_ihds_inputs(self) -> dict[str, Any]:
        """Pull all Joti data needed to compute IHDS in PurpleLab.

        Returns a dict with keys: hccs, hunt_gaps, tes, mitre_coverage.
        """
        hccs, gaps, tes, coverage = await _gather(
            self.get_hccs(),
            self.get_hunt_gaps(),
            self.get_tes(),
            self.get_mitre_coverage(),
        )
        return {
            "hccs": hccs,
            "hunt_gaps": gaps,
            "tes": tes,
            "mitre_coverage": coverage,
        }

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        assert self._client, "Use as async context manager"
        resp = await self._client.get(
            f"{JOTI_API_V1}{path}", params=params
        )
        resp.raise_for_status()
        return resp.json()

    async def _post(
        self, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        assert self._client, "Use as async context manager"
        resp = await self._client.post(
            f"{JOTI_API_V1}{path}", json=body
        )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_joti_alert(event: dict[str, Any], source_type: str) -> dict[str, Any]:
    """Transform a PurpleLab event into a Joti alert ingestion payload."""
    return {
        "source_type": event.get("_purplelab_source", source_type),
        "technique_id": event.get("_purplelab_technique"),
        "is_simulated": True,
        "severity": event.get("severity", event.get("Severity", "medium")),
        "title": (
            f"[PurpleLab Simulation] {event.get('_purplelab_technique', 'Unknown')} "
            f"via {event.get('_purplelab_source', source_type)}"
        ),
        "raw_event": event,
        "tags": ["purplelab", "simulation"],
    }


async def _gather(*coros: Any) -> list[Any]:
    """Gather coroutines, returning None for each that raises."""
    import asyncio
    results = []
    for coro in coros:
        try:
            results.append(await coro)
        except Exception:
            results.append(None)
    return results


# ---------------------------------------------------------------------------
# Factory — reads from settings
# ---------------------------------------------------------------------------

def get_joti_client() -> JotiClient | None:
    """Create a JotiClient from application settings.

    Returns None if Joti is not configured.
    """
    try:
        from backend.config import settings
        joti_url = getattr(settings, "JOTI_BASE_URL", None)
        joti_key = getattr(settings, "JOTI_API_KEY", None)
        joti_webhook = getattr(settings, "JOTI_WEBHOOK_TOKEN", "")
        if not joti_url or not joti_key:
            return None
        return JotiClient(
            JotiConfig(
                base_url=joti_url,
                api_key=joti_key,
                webhook_token=joti_webhook,
            )
        )
    except Exception as exc:
        logger.warning("Could not create JotiClient: %s", exc)
        return None
