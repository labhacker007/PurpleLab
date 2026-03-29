"""Joti webhook receiver.

Provides a FastAPI router that accepts inbound alerts from the Joti platform.
When Joti sends an alert webhook, PurpleLab looks up matching use cases by
technique_id and creates UseCaseRun records so the pipeline can score them.

Endpoint: POST /joti/webhook/alerts
Auth:      X-Joti-Token header must match settings.JOTI_WEBHOOK_TOKEN
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from backend.db.session import async_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/joti", tags=["joti"])


# ---------------------------------------------------------------------------
# Severity → UseCaseRun status mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_STATUS: dict[str, str] = {
    "critical": "failed",
    "high": "failed",
    "medium": "partial",
    "low": "passed",
    "info": "passed",
}


# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/webhook/alerts",
    status_code=status.HTTP_200_OK,
    summary="Receive alert ingestion from Joti",
    description=(
        "Joti calls this endpoint when it processes a simulated alert or "
        "detects a real event that PurpleLab should be notified about. "
        "Validates the X-Joti-Token header, looks up matching use cases by "
        "technique_id, and creates UseCaseRun records."
    ),
)
async def receive_alert_webhook(request: Request) -> dict[str, Any]:
    """Receive alert ingestion from Joti.

    Validates the ``X-Joti-Token`` header against ``settings.JOTI_WEBHOOK_TOKEN``.
    Parses the body as either a JSON list of alert dicts or an object with an
    ``alerts`` key. For each alert, looks up matching use cases by ``technique_id``
    and creates a ``UseCaseRun`` with ``triggered_by="joti_webhook"``.

    Returns ``{"accepted": N}`` where N is the number of runs created.
    """
    # ── Auth ────────────────────────────────────────────────────────────
    _verify_token(request)

    # ── Parse body ──────────────────────────────────────────────────────
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body must be valid JSON",
        )

    alerts: list[dict[str, Any]]
    if isinstance(body, list):
        alerts = body
    elif isinstance(body, dict):
        alerts = body.get("alerts", [body])
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Expected a JSON list or object with 'alerts' key",
        )

    if not alerts:
        return {"accepted": 0}

    # ── Process each alert ───────────────────────────────────────────────
    accepted = await _process_alerts(alerts)
    logger.info("Joti webhook: accepted %d run(s) from %d alert(s)", accepted, len(alerts))
    return {"accepted": accepted}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _verify_token(request: Request) -> None:
    """Raise 401 if the X-Joti-Token header is missing or wrong."""
    try:
        from backend.config import settings
        expected = getattr(settings, "JOTI_WEBHOOK_TOKEN", "")
    except Exception:
        expected = ""

    if not expected:
        # Webhook token not configured — reject all inbound webhooks to avoid
        # open unauthenticated ingestion.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Joti webhook token not configured on this server",
        )

    incoming = request.headers.get("X-Joti-Token", "")
    if not incoming or incoming != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Joti-Token header",
        )


async def _process_alerts(alerts: list[dict[str, Any]]) -> int:
    """For each alert, find matching use cases and create UseCaseRun records.

    Returns the count of UseCaseRun rows created.
    """
    from backend.db.models import UseCase, UseCaseRun
    from sqlalchemy import select

    now = datetime.now(timezone.utc)
    accepted = 0

    async with async_session() as db:
        for alert in alerts:
            technique_id: str | None = (
                alert.get("technique_id")
                or alert.get("mitre_technique")
                or alert.get("technique")
            )
            severity: str = str(alert.get("severity", "medium")).lower()
            run_status = _SEVERITY_TO_STATUS.get(severity, "partial")

            if not technique_id:
                # No technique tag — create a run against *no* use case
                # (orphaned run) so the alert is still recorded.
                run = UseCaseRun(
                    id=uuid.uuid4(),
                    use_case_id=None,  # type: ignore[arg-type]
                    status=run_status,
                    triggered_by="joti_webhook",
                    events_generated=0,
                    rules_tested=0,
                    rules_fired=0,
                    run_details={
                        "joti_alert": alert,
                        "note": "No technique_id in alert; no use case matched",
                    },
                    started_at=now,
                    completed_at=now,
                )
                db.add(run)
                accepted += 1
                continue

            # Find all active use cases that cover this technique
            tech_upper = technique_id.upper()
            try:
                result = await db.execute(
                    select(UseCase).where(UseCase.is_active == True)  # noqa: E712
                )
                use_cases = result.scalars().all()
            except Exception as exc:
                logger.warning("Failed to query use cases for alert %s: %s", technique_id, exc)
                use_cases = []

            matched = [
                uc for uc in use_cases
                if uc.technique_ids and tech_upper in [t.upper() for t in (uc.technique_ids or [])]
            ]

            if not matched:
                # No matching use case — create a standalone run so the alert
                # is still tracked in the system.
                run = UseCaseRun(
                    id=uuid.uuid4(),
                    use_case_id=None,  # type: ignore[arg-type]
                    status=run_status,
                    triggered_by="joti_webhook",
                    events_generated=0,
                    rules_tested=0,
                    rules_fired=0,
                    run_details={
                        "joti_alert": alert,
                        "technique_id": tech_upper,
                        "note": f"No active use case matched technique {tech_upper}",
                    },
                    started_at=now,
                    completed_at=now,
                )
                db.add(run)
                accepted += 1
            else:
                for uc in matched:
                    run = UseCaseRun(
                        id=uuid.uuid4(),
                        use_case_id=uc.id,
                        status=run_status,
                        triggered_by="joti_webhook",
                        events_generated=0,
                        rules_tested=0,
                        rules_fired=0,
                        run_details={
                            "joti_alert": alert,
                            "technique_id": tech_upper,
                        },
                        started_at=now,
                        completed_at=now,
                    )
                    db.add(run)
                    accepted += 1

        try:
            await db.commit()
        except Exception as exc:
            logger.error("Failed to commit webhook runs: %s", exc)
            await db.rollback()
            return 0

    return accepted
