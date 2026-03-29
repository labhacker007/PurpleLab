"""Continuous purple team pipeline engine.

Runs automated attack chain simulations on a schedule:
1. Pull MITRE coverage gaps (from local rules or Joti)
2. Select attack chains that cover those gaps
3. Request HITL approval (L1_SOFT — auto-proceeds after grace period)
4. Run selected attack chains → generate log events
5. Test detection rules against generated events
6. Compute DES delta (coverage improvement)
7. Notify team via Slack/webhook
8. Store run results in DB
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Known MITRE techniques universe (top-level techniques from coverage map)
_KNOWN_TECHNIQUES = [
    "T1595", "T1592", "T1589", "T1590", "T1591",
    "T1583", "T1584", "T1587", "T1588",
    "T1566", "T1190", "T1133", "T1078",
    "T1059", "T1053", "T1047", "T1204", "T1203",
    "T1547", "T1546", "T1543", "T1098",
    "T1548", "T1134", "T1055",
    "T1036", "T1027", "T1070", "T1562", "T1140", "T1218",
    "T1003", "T1110", "T1555", "T1558", "T1552",
    "T1083", "T1082", "T1057", "T1018", "T1016",
    "T1021", "T1570", "T1080",
    "T1560", "T1005", "T1074",
    "T1071", "T1105", "T1095", "T1572", "T1573",
    "T1041", "T1048", "T1567",
    "T1486", "T1490", "T1489", "T1485", "T1529",
    # sub-techniques that appear in builtin chains
    "T1566.001", "T1059.001", "T1003.001", "T1110.003",
    "T1543.003", "T1552.007", "T1611", "T1610",
]


class PipelineEngine:
    """Core pipeline execution engine."""

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run_pipeline(
        self, pipeline_id: str, triggered_by: str = "scheduler"
    ) -> dict[str, Any]:
        """Execute a full pipeline run. Returns run summary dict."""
        from backend.db.session import async_session
        from backend.db.models import PipelineConfig, PipelineRun
        from sqlalchemy import select

        run_id: str | None = None

        # ── 1. Load PipelineConfig and create PipelineRun ─────────────
        try:
            async with async_session() as db:
                result = await db.execute(
                    select(PipelineConfig).where(
                        PipelineConfig.id == uuid.UUID(pipeline_id)
                    )
                )
                config = result.scalar_one_or_none()
                if config is None:
                    return {"error": f"Pipeline {pipeline_id} not found"}

                run = PipelineRun(
                    id=uuid.uuid4(),
                    pipeline_id=uuid.UUID(pipeline_id),
                    status="running",
                    triggered_by=triggered_by,
                    started_at=datetime.now(timezone.utc),
                )
                db.add(run)
                await db.commit()
                await db.refresh(run)
                run_id = str(run.id)

                # Capture config values before closing session
                chain_ids: list[str] = list(config.chain_ids or [])
                slack_channel: str = config.notify_slack_channel or ""
                hitl_override: int | None = config.hitl_level_override
        except Exception as exc:
            logger.exception("Pipeline %s: failed to init run: %s", pipeline_id, exc)
            return {"error": str(exc)}

        logger.info(
            "Pipeline %s run %s started (triggered_by=%s)",
            pipeline_id, run_id, triggered_by,
        )

        # ── 2. Pull coverage gaps ──────────────────────────────────────
        try:
            gap_techniques = await self.get_coverage_gaps()
        except Exception as exc:
            logger.warning("Coverage gap analysis failed: %s", exc)
            gap_techniques = []

        # ── 3. Select chains ───────────────────────────────────────────
        try:
            chains = await self._resolve_chains(chain_ids, gap_techniques)
        except Exception as exc:
            logger.warning("Chain selection failed: %s", exc)
            chains = []

        if not chains:
            await self._update_run(run_id, "completed",
                                   error_message="No chains selected")
            return {
                "run_id": run_id,
                "status": "completed",
                "chains_run": 0,
                "events_generated": 0,
                "detections_fired": 0,
                "des_before": None,
                "des_after": None,
                "gap_techniques": gap_techniques,
                "note": "No attack chains matched gap techniques",
            }

        # ── 4. HITL gate ───────────────────────────────────────────────
        hitl_approved = await self._hitl_gate(
            run_id=run_id,
            chains=chains,
            hitl_override=hitl_override,
        )
        if not hitl_approved:
            await self._update_run(run_id, "cancelled",
                                   error_message="Rejected by HITL")
            logger.info("Pipeline run %s cancelled by HITL", run_id)
            return {"run_id": run_id, "status": "cancelled"}

        # ── 5. Run chains ──────────────────────────────────────────────
        all_events: list[dict[str, Any]] = []
        chains_run = 0
        try:
            from backend.attack_chains.orchestrator import get_orchestrator
            orchestrator = get_orchestrator()
            for chain in chains:
                try:
                    result = await orchestrator.run(chain)
                    all_events.extend(result.all_events())
                    chains_run += 1
                    logger.info(
                        "Chain '%s' completed: %d events",
                        chain.id, result.total_events,
                    )
                except Exception as exc:
                    logger.warning("Chain '%s' run failed: %s", chain.id, exc)
        except Exception as exc:
            logger.exception("Attack chain execution error: %s", exc)

        events_generated = len(all_events)

        # ── 6. Test detection rules ────────────────────────────────────
        detections_fired = 0
        try:
            detections_fired = await self._test_rules_against_events(all_events)
        except Exception as exc:
            logger.warning("Rule testing failed: %s", exc)

        # ── 7. Compute DES delta ───────────────────────────────────────
        des_before: float | None = None
        des_after: float | None = None
        try:
            des_before, des_after = await self._compute_des_delta(all_events)
        except Exception as exc:
            logger.warning("DES computation failed: %s", exc)

        # ── 8. Notify (fire-and-forget) ────────────────────────────────
        summary = {
            "run_id": run_id,
            "pipeline_id": pipeline_id,
            "status": "completed",
            "triggered_by": triggered_by,
            "chains_run": chains_run,
            "events_generated": events_generated,
            "detections_fired": detections_fired,
            "des_before": des_before,
            "des_after": des_after,
            "gap_techniques": gap_techniques,
        }

        if slack_channel:
            asyncio.create_task(self._notify_slack(slack_channel, summary))

        # Send events to Joti (fire-and-forget)
        if all_events:
            asyncio.create_task(self._notify_joti(all_events))

        # Push in-app notification to the triggering user
        if triggered_by and triggered_by not in ("scheduler", "pipeline"):
            asyncio.create_task(
                self._notify_user(triggered_by, des_before, des_after)
            )

        # ── 9. Update PipelineRun ──────────────────────────────────────
        await self._update_run(
            run_id,
            "completed",
            chains_run=chains_run,
            events_generated=events_generated,
            detections_fired=detections_fired,
            des_before=des_before,
            des_after=des_after,
        )

        logger.info(
            "Pipeline run %s complete: chains=%d events=%d detections=%d "
            "DES %s→%s",
            run_id, chains_run, events_generated, detections_fired,
            des_before, des_after,
        )
        return summary

    # ------------------------------------------------------------------
    # Coverage gaps
    # ------------------------------------------------------------------

    async def get_coverage_gaps(self) -> list[str]:
        """Return list of MITRE technique IDs with no detection coverage."""
        from backend.db.session import async_session
        from backend.db.models import ImportedRule
        from sqlalchemy import select

        covered: set[str] = set()
        try:
            async with async_session() as db:
                result = await db.execute(
                    select(ImportedRule).where(ImportedRule.enabled == True)
                )
                rules = result.scalars().all()

            for rule in rules:
                techs: list[str] = rule.mitre_techniques or []
                for t in techs:
                    t_upper = t.upper()
                    covered.add(t_upper)
                    covered.add(t_upper.split(".")[0])
        except Exception as exc:
            logger.warning("get_coverage_gaps DB query failed: %s", exc)

        # Also pull Joti gaps if connected
        joti_gap_techniques: list[str] = []
        try:
            from backend.integrations.joti_client import get_joti_client
            joti_client = get_joti_client()
            if joti_client:
                async with joti_client as client:
                    gaps = await client.get_hunt_gaps()
                    joti_gap_techniques = [
                        g.get("technique_id", "") for g in gaps
                        if g.get("technique_id")
                    ]
        except Exception as exc:
            logger.debug("Joti gap pull failed (non-fatal): %s", exc)

        # Gaps = known techniques not in covered set
        all_known = set(_KNOWN_TECHNIQUES)
        # Add Joti-identified gaps to our universe
        for t in joti_gap_techniques:
            all_known.add(t.upper())

        gaps = sorted(all_known - covered)
        logger.debug("Coverage gaps: %d techniques uncovered", len(gaps))
        return gaps

    # ------------------------------------------------------------------
    # Chain selection
    # ------------------------------------------------------------------

    def _select_chains_for_gaps(
        self,
        gap_techniques: list[str],
        available_chain_ids: list[str],
    ) -> list:
        """Select attack chains that cover the most gap techniques."""
        from backend.attack_chains.orchestrator import get_orchestrator

        orchestrator = get_orchestrator()
        gap_set = {t.upper() for t in gap_techniques}

        candidates = []
        if available_chain_ids:
            for cid in available_chain_ids:
                chain = orchestrator.get_builtin_chain(cid)
                if chain:
                    candidates.append(chain)
        else:
            # All builtin chains
            for cid, chain in orchestrator._builtin_chains.items():
                candidates.append(chain)

        # Score each chain by gap coverage
        scored: list[tuple[int, Any]] = []
        for chain in candidates:
            chain_techs = {s.technique.upper() for s in chain.stages}
            # Also check parent techniques
            chain_parents = {t.split(".")[0] for t in chain_techs}
            coverage = len((chain_techs | chain_parents) & gap_set)
            scored.append((coverage, chain))

        # Sort descending by coverage, return top chains that add value
        scored.sort(key=lambda x: x[0], reverse=True)
        selected = []
        seen_techniques: set[str] = set()
        for score, chain in scored:
            chain_techs = {s.technique.upper() for s in chain.stages}
            chain_parents = {t.split(".")[0] for t in chain_techs}
            new_coverage = (chain_techs | chain_parents) & gap_set - seen_techniques
            if new_coverage or not gap_set:
                selected.append(chain)
                seen_techniques.update(chain_techs | chain_parents)
            if len(selected) >= 3:  # cap at 3 chains per run
                break

        return selected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _resolve_chains(
        self,
        chain_ids: list[str],
        gap_techniques: list[str],
    ) -> list:
        """Resolve the list of attack chains to run."""
        auto_select = not chain_ids or chain_ids == ["auto"]
        if auto_select:
            return self._select_chains_for_gaps(gap_techniques, [])
        else:
            return self._select_chains_for_gaps(gap_techniques, chain_ids)

    async def _hitl_gate(
        self,
        run_id: str,
        chains: list,
        hitl_override: int | None,
    ) -> bool:
        """Request HITL approval for a pipeline run. Returns True if approved."""
        try:
            from backend.hitl.engine import get_hitl_engine
            from backend.hitl.models import HITLLevel

            engine = get_hitl_engine()
            override_level = (
                HITLLevel(hitl_override)
                if hitl_override is not None
                else HITLLevel.L1_SOFT
            )

            payload = {
                "run_id": run_id,
                "chains": [c.id for c in chains],
                "chain_count": len(chains),
            }

            req = await engine.request(
                action_type="run_attack_chain",
                payload=payload,
                requested_by="pipeline",
                override_level=override_level,
            )

            # For L0 (auto-approved immediately) or L1_SOFT we wait
            if req.status in ("auto_approved",):
                return True
            if req.status == "approved":
                return True
            if req.status == "rejected":
                return False

            # Wait for resolution (L1_SOFT auto-approves after 30s)
            resolved = await engine.wait_for_approval(req.id, timeout=120)
            if resolved is None:
                return True  # Treat unresolved as approved for pipelines
            return resolved.status in ("approved", "auto_approved")

        except Exception as exc:
            logger.warning("HITL gate failed (defaulting to approved): %s", exc)
            return True  # Fail open for pipeline automation

    async def _test_rules_against_events(
        self, events: list[dict[str, Any]]
    ) -> int:
        """Test enabled detection rules against generated events. Returns fired count."""
        if not events:
            return 0

        from backend.db.session import async_session
        from backend.db.models import ImportedRule
        from backend.detection.rule_manager import RuleManager
        from sqlalchemy import select

        try:
            async with async_session() as db:
                result = await db.execute(
                    select(ImportedRule).where(ImportedRule.enabled == True)
                )
                db_rules = result.scalars().all()
        except Exception as exc:
            logger.warning("Failed to load rules for testing: %s", exc)
            return 0

        if not db_rules:
            return 0

        # Parse rules into ParsedRule objects
        manager = RuleManager()
        parsed_rules = []
        for r in db_rules:
            try:
                parsed = await manager.import_rules(
                    r.source_query, r.language or "sigma"
                )
                parsed_rules.extend(parsed)
            except Exception:
                pass  # Skip unparseable rules silently

        if not parsed_rules:
            return 0

        try:
            run_result = await manager.batch_evaluate(parsed_rules, events)
            return run_result.rules_fired
        except Exception as exc:
            logger.warning("batch_evaluate failed: %s", exc)
            return 0

    async def _compute_des_delta(
        self, events: list[dict[str, Any]]
    ) -> tuple[float | None, float | None]:
        """Compute DES before and after. Returns (des_before, des_after)."""
        from backend.db.session import async_session
        from backend.db.models import ImportedRule
        from backend.scoring.des import DetectionEfficacyScore, RuleSummary
        from sqlalchemy import select

        try:
            async with async_session() as db:
                result = await db.execute(
                    select(ImportedRule).where(ImportedRule.enabled == True)
                )
                db_rules = result.scalars().all()
        except Exception as exc:
            logger.warning("DES: failed to load rules: %s", exc)
            return None, None

        if not db_rules:
            return None, None

        scorer = DetectionEfficacyScore()
        now = datetime.now(timezone.utc)

        # Build RuleSummary objects from existing rules (no test history)
        summaries_before: list[RuleSummary] = []
        for r in db_rules:
            techs: list[str] = r.mitre_techniques or []
            for tech in techs:
                summaries_before.append(
                    RuleSummary(
                        rule_id=str(r.id),
                        technique_id=tech.upper(),
                        total_tests=0,
                        successes=0,
                        last_tested_at=r.updated_at,
                        false_positive_rate=0.0,
                    )
                )

        des_before_result = scorer.compute(summaries_before, _KNOWN_TECHNIQUES, now)
        des_before = des_before_result.score

        # des_after: add test successes for events that matched techniques
        if events:
            # Extract techniques from events and count as successes
            technique_counts: dict[str, int] = {}
            for e in events:
                t = e.get("_purplelab_technique") or e.get("technique_id", "")
                if t:
                    t = t.upper()
                    technique_counts[t] = technique_counts.get(t, 0) + 1

            summaries_after = list(summaries_before)
            for tech, count in technique_counts.items():
                summaries_after.append(
                    RuleSummary(
                        rule_id=f"pipeline_test_{tech}",
                        technique_id=tech,
                        total_tests=count,
                        successes=count,
                        last_tested_at=now,
                        false_positive_rate=0.0,
                    )
                )
            des_after_result = scorer.compute(summaries_after, _KNOWN_TECHNIQUES, now)
            des_after = des_after_result.score
        else:
            des_after = des_before

        return des_before, des_after

    async def _update_run(
        self,
        run_id: str,
        status: str,
        chains_run: int = 0,
        events_generated: int = 0,
        detections_fired: int = 0,
        des_before: float | None = None,
        des_after: float | None = None,
        error_message: str | None = None,
    ) -> None:
        """Update PipelineRun row in DB."""
        from backend.db.session import async_session
        from backend.db.models import PipelineRun
        from sqlalchemy import select

        try:
            async with async_session() as db:
                result = await db.execute(
                    select(PipelineRun).where(
                        PipelineRun.id == uuid.UUID(run_id)
                    )
                )
                row = result.scalar_one_or_none()
                if row:
                    row.status = status
                    row.chains_run = chains_run
                    row.events_generated = events_generated
                    row.detections_fired = detections_fired
                    row.des_before = des_before
                    row.des_after = des_after
                    row.error_message = error_message
                    row.completed_at = datetime.now(timezone.utc)
                    await db.commit()
        except Exception as exc:
            logger.warning("Failed to update pipeline run %s: %s", run_id, exc)

    async def _notify_slack(
        self, channel: str, run_summary: dict[str, Any]
    ) -> None:
        """Post pipeline completion to Slack."""
        if not channel:
            return

        if not channel.startswith("http"):
            # Channel name (e.g. #purple-team) — use Slack Bot Token if available
            import os
            slack_token = os.environ.get("SLACK_BOT_TOKEN", "")
            if not slack_token:
                logger.debug(
                    "SLACK_BOT_TOKEN not set — cannot notify channel %s", channel
                )
                return

            des_before = run_summary.get("des_before")
            des_after = run_summary.get("des_after")
            des_delta_str = ""
            if des_before is not None and des_after is not None:
                delta = round(des_after - des_before, 1)
                sign = "+" if delta >= 0 else ""
                des_delta_str = f"DES: {des_before} → {des_after} ({sign}{delta})"

            text = (
                f"PurpleLab Pipeline Run Completed\n"
                f"Run ID: {run_summary.get('run_id')}\n"
                f"Status: {run_summary.get('status')}\n"
                f"Chains run: {run_summary.get('chains_run')}\n"
                f"Events generated: {run_summary.get('events_generated')}\n"
                f"Detections fired: {run_summary.get('detections_fired')}\n"
                f"{des_delta_str}"
            )
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    await client.post(
                        "https://slack.com/api/chat.postMessage",
                        headers={"Authorization": f"Bearer {slack_token}"},
                        json={"channel": channel, "text": text},
                        timeout=10.0,
                    )
            except Exception as exc:
                logger.warning("Slack notify failed: %s", exc)
        else:
            # Webhook URL
            try:
                import httpx
                async with httpx.AsyncClient() as client:
                    await client.post(
                        channel,
                        json={"event": "pipeline_run_completed", "data": run_summary},
                        timeout=10.0,
                    )
            except Exception as exc:
                logger.warning("Slack webhook notify failed: %s", exc)

    async def _notify_user(
        self,
        user_id: str,
        des_before: float | None,
        des_after: float | None,
    ) -> None:
        """Send in-app notification to the user who triggered the pipeline run."""
        try:
            from backend.api.v2.notifications import send_notification

            if des_before is not None and des_after is not None:
                msg = f"Run finished: DES {des_before * 100:.0f}% \u2192 {des_after * 100:.0f}%"
            else:
                msg = "Pipeline run completed"

            await send_notification(
                user_id=user_id,
                notif_type="success",
                title="Pipeline Complete",
                message=msg,
                link="/pipeline",
            )
        except Exception as exc:
            logger.warning("Pipeline user notification failed: %s", exc)

    async def _notify_joti(self, events: list[dict[str, Any]]) -> None:
        """Send generated events to Joti as alerts (fire-and-forget)."""
        try:
            from backend.integrations.joti_client import get_joti_client
            joti_client = get_joti_client()
            if joti_client:
                async with joti_client as client:
                    result = await client.send_alerts(events)
                    logger.debug(
                        "Joti alert ingestion: accepted=%d rejected=%d",
                        result.accepted, result.rejected,
                    )
        except Exception as exc:
            logger.debug("Joti notify failed (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Singleton factory
# ---------------------------------------------------------------------------

_engine: PipelineEngine | None = None


async def get_pipeline_engine() -> PipelineEngine:
    """Singleton factory."""
    global _engine
    if _engine is None:
        _engine = PipelineEngine()
    return _engine
