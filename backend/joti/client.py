"""Joti API client for PurpleLab.

Provides an async HTTP client that talks to the Joti platform API.
All public methods catch all exceptions and return None/False/empty —
they never raise.

Usage::

    client = get_joti_client()
    if client:
        score = await client.get_coverage_score()
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from backend.config import settings

logger = logging.getLogger(__name__)


class JotiClient:
    """Async client for the Joti platform API.

    Can be used standalone (methods open/close their own session) or as
    an async context manager for connection reuse across multiple calls.
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Source": "purplelab",
        }
        self._timeout = httpx.Timeout(10.0)
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager support (optional — enables connection reuse)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "JotiClient":
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    async def get_coverage_score(self) -> dict | None:
        """GET /api/v2/coverage/score — returns HCCS (Hunt Coverage Completeness Score).

        Response shape: {score, covered_techniques, total_techniques, computed_at}
        """
        try:
            data = await self._get("/api/v2/coverage/score")
            return data
        except Exception as exc:
            logger.debug("get_coverage_score failed: %s", exc)
            return None

    async def get_technique_coverage(self, technique_ids: list[str]) -> dict:
        """GET /api/v2/coverage/techniques?ids=T1059,T1003 — per-technique coverage.

        Returns dict mapping technique_id -> coverage detail.
        """
        try:
            ids_param = ",".join(technique_ids)
            data = await self._get("/api/v2/coverage/techniques", params={"ids": ids_param})
            return data
        except Exception as exc:
            logger.debug("get_technique_coverage failed: %s", exc)
            return {}

    async def get_active_alerts(self, limit: int = 100) -> list[dict]:
        """GET /api/v2/alerts?status=active&limit=N — active alerts from Joti."""
        try:
            data = await self._get("/api/v2/alerts", params={"status": "active", "limit": limit})
            if isinstance(data, list):
                return data
            return data.get("alerts", data.get("items", []))
        except Exception as exc:
            logger.debug("get_active_alerts failed: %s", exc)
            return []

    async def get_threat_profile(self) -> dict | None:
        """GET /api/v2/threat-profile — TES (Threat Exposure Score) and profile data.

        Response shape: {score, components, computed_at}
        """
        try:
            data = await self._get("/api/v2/threat-profile")
            return data
        except Exception as exc:
            logger.debug("get_threat_profile failed: %s", exc)
            return None

    async def push_simulation_result(self, result: dict) -> bool:
        """POST /api/v2/simulations — notify Joti of a completed purple team run.

        Returns True if Joti accepted the result.
        """
        try:
            await self._post("/api/v2/simulations", result)
            return True
        except Exception as exc:
            logger.debug("push_simulation_result failed: %s", exc)
            return False

    async def is_connected(self) -> bool:
        """GET /api/v2/health — returns True if Joti is reachable."""
        try:
            await self._get("/api/v2/health")
            return True
        except Exception as exc:
            logger.debug("is_connected check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Perform a GET request, reusing existing client if inside context manager."""
        if self._client is not None:
            resp = await self._client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()

        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=self._timeout,
        ) as client:
            resp = await client.get(path, params=params)
            resp.raise_for_status()
            return resp.json()

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        """Perform a POST request, reusing existing client if inside context manager."""
        if self._client is not None:
            resp = await self._client.post(path, json=body)
            resp.raise_for_status()
            return resp.json()

        async with httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=self._timeout,
        ) as client:
            resp = await client.post(path, json=body)
            resp.raise_for_status()
            return resp.json()


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

def get_joti_client() -> JotiClient | None:
    """Create a JotiClient from application settings.

    Returns None if JOTI_BASE_URL or JOTI_API_KEY is not configured.
    This is the primary entry point for all code that needs to call Joti.
    """
    try:
        base_url = getattr(settings, "JOTI_BASE_URL", "")
        api_key = getattr(settings, "JOTI_API_KEY", "")
        if not base_url or not api_key:
            return None
        return JotiClient(base_url=base_url, api_key=api_key)
    except Exception as exc:
        logger.warning("Could not create JotiClient: %s", exc)
        return None
