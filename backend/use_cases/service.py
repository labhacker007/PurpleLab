"""Use case CRUD service and validation orchestrator."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import async_session
from backend.db import models

logger = logging.getLogger(__name__)


def _uc_to_dict(uc: models.UseCase) -> dict[str, Any]:
    return {
        "id": str(uc.id),
        "name": uc.name,
        "description": uc.description,
        "technique_ids": uc.technique_ids or [],
        "tactic": uc.tactic,
        "threat_actor": uc.threat_actor,
        "attack_chain_id": uc.attack_chain_id,
        "expected_log_sources": uc.expected_log_sources or [],
        "severity": uc.severity,
        "tags": uc.tags or [],
        "is_active": uc.is_active,
        "is_builtin": uc.is_builtin,
        "last_validated_at": uc.last_validated_at.isoformat() if uc.last_validated_at else None,
        "created_at": uc.created_at.isoformat() if uc.created_at else None,
        "updated_at": uc.updated_at.isoformat() if uc.updated_at else None,
    }


def _run_to_dict(run: models.UseCaseRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "use_case_id": str(run.use_case_id),
        "status": run.status,
        "triggered_by": run.triggered_by,
        "events_generated": run.events_generated,
        "rules_tested": run.rules_tested,
        "rules_fired": run.rules_fired,
        "pass_rate": run.pass_rate,
        "run_details": run.run_details or {},
        "error_message": run.error_message,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


class UseCaseService:
    """CRUD and orchestration service for use cases."""

    # ------------------------------------------------------------------
    # List / Get
    # ------------------------------------------------------------------

    async def list_use_cases(
        self,
        active_only: bool = False,
        tactic: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        async with async_session() as db:
            q = select(models.UseCase)
            if active_only:
                q = q.where(models.UseCase.is_active.is_(True))
            if tactic:
                q = q.where(models.UseCase.tactic == tactic)
            if severity:
                q = q.where(models.UseCase.severity == severity)
            if search:
                like = f"%{search}%"
                q = q.where(
                    models.UseCase.name.ilike(like)
                    | models.UseCase.description.ilike(like)
                )
            q = q.order_by(models.UseCase.created_at.desc()).offset(offset).limit(limit)
            rows = (await db.scalars(q)).all()
            return [_uc_to_dict(r) for r in rows]

    async def get_use_case(self, use_case_id: str) -> dict[str, Any] | None:
        async with async_session() as db:
            uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
            if not uc:
                return None
            result = _uc_to_dict(uc)
            # Include recent run history
            runs_q = (
                select(models.UseCaseRun)
                .where(models.UseCaseRun.use_case_id == uc.id)
                .order_by(models.UseCaseRun.created_at.desc())
                .limit(10)
            )
            runs = (await db.scalars(runs_q)).all()
            result["recent_runs"] = [_run_to_dict(r) for r in runs]
            return result

    # ------------------------------------------------------------------
    # Create / Update / Delete
    # ------------------------------------------------------------------

    async def create_use_case(
        self, data: dict[str, Any], created_by: str = "user"
    ) -> dict[str, Any]:
        async with async_session() as db:
            uc = models.UseCase(
                name=data["name"],
                description=data.get("description", ""),
                technique_ids=data.get("technique_ids", []),
                tactic=data.get("tactic", ""),
                threat_actor=data.get("threat_actor", ""),
                attack_chain_id=data.get("attack_chain_id", ""),
                expected_log_sources=data.get("expected_log_sources", []),
                severity=data.get("severity", "high"),
                tags=data.get("tags", []),
                is_active=data.get("is_active", True),
                is_builtin=data.get("is_builtin", False),
            )
            db.add(uc)
            await db.commit()
            await db.refresh(uc)
            return _uc_to_dict(uc)

    async def update_use_case(
        self, use_case_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        async with async_session() as db:
            uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
            if not uc:
                return None
            updatable = {
                "name", "description", "technique_ids", "tactic", "threat_actor",
                "attack_chain_id", "expected_log_sources", "severity", "tags",
                "is_active",
            }
            for field, value in data.items():
                if field in updatable:
                    setattr(uc, field, value)
            await db.commit()
            await db.refresh(uc)
            return _uc_to_dict(uc)

    async def delete_use_case(self, use_case_id: str) -> bool:
        async with async_session() as db:
            uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
            if not uc:
                return False
            await db.delete(uc)
            await db.commit()
            return True

    # ------------------------------------------------------------------
    # Seed
    # ------------------------------------------------------------------

    async def seed_builtin_use_cases(self) -> int:
        """Insert BUILTIN_USE_CASES if not already present. Idempotent — matches by name.

        Returns:
            Number of use cases newly inserted.
        """
        from backend.use_cases.library import BUILTIN_USE_CASES

        inserted = 0
        async with async_session() as db:
            for uc_data in BUILTIN_USE_CASES:
                existing = await db.scalar(
                    select(models.UseCase).where(models.UseCase.name == uc_data["name"])
                )
                if existing:
                    continue
                uc = models.UseCase(
                    name=uc_data["name"],
                    description=uc_data.get("description", ""),
                    technique_ids=uc_data.get("technique_ids", []),
                    tactic=uc_data.get("tactic", ""),
                    threat_actor=uc_data.get("threat_actor", ""),
                    attack_chain_id=uc_data.get("attack_chain_id", ""),
                    expected_log_sources=uc_data.get("expected_log_sources", []),
                    severity=uc_data.get("severity", "high"),
                    tags=uc_data.get("tags", []),
                    is_active=True,
                    is_builtin=True,
                )
                db.add(uc)
                inserted += 1
            if inserted:
                await db.commit()

        return inserted

    # ------------------------------------------------------------------
    # Run / Validate
    # ------------------------------------------------------------------

    async def run_use_case(
        self, use_case_id: str, triggered_by: str = "manual"
    ) -> dict[str, Any]:
        """Validate a use case by simulating attack logs and testing detection rules.

        1. Creates a UseCaseRun with status='running'
        2. Calls UseCaseValidator.validate(use_case)
        3. Updates run with results
        4. Updates use_case.last_validated_at
        5. Returns run summary dict
        """
        async with async_session() as db:
            uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
            if not uc:
                raise ValueError(f"Use case {use_case_id} not found")

            run = models.UseCaseRun(
                use_case_id=uc.id,
                status="running",
                triggered_by=triggered_by,
                started_at=datetime.now(timezone.utc),
            )
            db.add(run)
            await db.commit()
            await db.refresh(run)
            run_id = run.id

        # Run validation outside the session to avoid long-held connections
        try:
            from backend.use_cases.validator import UseCaseValidator
            validator = UseCaseValidator()

            async with async_session() as db:
                uc = await db.get(models.UseCase, uuid.UUID(use_case_id))
                result = await validator.validate(uc)

            async with async_session() as db:
                run = await db.get(models.UseCaseRun, run_id)
                uc = await db.get(models.UseCase, uuid.UUID(use_case_id))

                run.status = result["status"]
                run.events_generated = result.get("events_generated", 0)
                run.rules_tested = result.get("rules_tested", 0)
                run.rules_fired = result.get("rules_fired", 0)
                run.pass_rate = result.get("pass_rate")
                run.run_details = {
                    "rule_results": result.get("rule_results", []),
                    "expected_rules_fired": result.get("expected_rules_fired", 0),
                }
                run.completed_at = datetime.now(timezone.utc)

                if uc:
                    uc.last_validated_at = datetime.now(timezone.utc)

                await db.commit()
                await db.refresh(run)
                return _run_to_dict(run)

        except Exception as exc:
            logger.exception("Use case run failed for %s: %s", use_case_id, exc)
            async with async_session() as db:
                run = await db.get(models.UseCaseRun, run_id)
                if run:
                    run.status = "error"
                    run.error_message = str(exc)
                    run.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await db.refresh(run)
                    return _run_to_dict(run)
            raise

    # ------------------------------------------------------------------
    # Run history
    # ------------------------------------------------------------------

    async def get_run_history(
        self, use_case_id: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        async with async_session() as db:
            q = (
                select(models.UseCaseRun)
                .where(models.UseCaseRun.use_case_id == uuid.UUID(use_case_id))
                .order_by(models.UseCaseRun.created_at.desc())
                .limit(limit)
            )
            runs = (await db.scalars(q)).all()
            return [_run_to_dict(r) for r in runs]

    # ------------------------------------------------------------------
    # Coverage summary
    # ------------------------------------------------------------------

    async def get_coverage_summary(self) -> dict[str, Any]:
        """Per-tactic pass/fail stats and overall coverage percentage.

        For each tactic, reports how many use cases have at least one passing
        run vs failing/never run. Overall coverage is the percentage of active
        use cases that have a passing run.
        """
        async with async_session() as db:
            all_uc = (await db.scalars(
                select(models.UseCase).where(models.UseCase.is_active.is_(True))
            )).all()

            if not all_uc:
                return {
                    "total": 0,
                    "passing": 0,
                    "failing": 0,
                    "never_run": 0,
                    "overall_coverage_pct": 0.0,
                    "by_tactic": {},
                }

            uc_ids = [uc.id for uc in all_uc]

            # Latest run per use case
            latest_runs: dict[uuid.UUID, models.UseCaseRun] = {}
            for uc_id in uc_ids:
                run = await db.scalar(
                    select(models.UseCaseRun)
                    .where(models.UseCaseRun.use_case_id == uc_id)
                    .order_by(models.UseCaseRun.created_at.desc())
                    .limit(1)
                )
                if run:
                    latest_runs[uc_id] = run

            # Aggregate
            by_tactic: dict[str, dict[str, int]] = {}
            total_passing = 0
            total_failing = 0
            total_never_run = 0

            for uc in all_uc:
                tactic = uc.tactic or "unknown"
                if tactic not in by_tactic:
                    by_tactic[tactic] = {"passing": 0, "failing": 0, "never_run": 0, "total": 0}
                by_tactic[tactic]["total"] += 1

                run = latest_runs.get(uc.id)
                if run is None:
                    by_tactic[tactic]["never_run"] += 1
                    total_never_run += 1
                elif run.status == "passed":
                    by_tactic[tactic]["passing"] += 1
                    total_passing += 1
                else:
                    by_tactic[tactic]["failing"] += 1
                    total_failing += 1

            total = len(all_uc)
            coverage_pct = round(total_passing / total * 100, 1) if total else 0.0

            return {
                "total": total,
                "passing": total_passing,
                "failing": total_failing,
                "never_run": total_never_run,
                "overall_coverage_pct": coverage_pct,
                "by_tactic": by_tactic,
            }

    # ------------------------------------------------------------------
    # Failing use cases
    # ------------------------------------------------------------------

    async def get_failing_use_cases(self) -> list[dict[str, Any]]:
        """Use cases where the last run failed or that have never been run."""
        async with async_session() as db:
            all_uc = (await db.scalars(
                select(models.UseCase).where(models.UseCase.is_active.is_(True))
            )).all()

            failing: list[dict[str, Any]] = []
            for uc in all_uc:
                run = await db.scalar(
                    select(models.UseCaseRun)
                    .where(models.UseCaseRun.use_case_id == uc.id)
                    .order_by(models.UseCaseRun.created_at.desc())
                    .limit(1)
                )
                if run is None or run.status not in ("passed",):
                    entry = _uc_to_dict(uc)
                    entry["last_run_status"] = run.status if run else "never_run"
                    entry["last_run_at"] = (
                        run.created_at.isoformat() if run and run.created_at else None
                    )
                    failing.append(entry)

            return failing
