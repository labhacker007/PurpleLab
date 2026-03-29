"""Reports API — generate and serve coverage, use case, pipeline, and full reports.

GET    /reports                 — list all saved reports
POST   /reports/generate        — trigger background report generation
GET    /reports/{id}            — get report by id with full data
GET    /reports/{id}/download   — stream the report file
DELETE /reports/{id}            — delete a report
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.db.session import async_session
from backend.db.models import Report

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class GenerateReportRequest(BaseModel):
    name: str = ""
    type: str  # coverage | use_cases | pipeline | full
    format: str = "json"  # json | html
    date_range_days: int = 30


# ---------------------------------------------------------------------------
# GET /reports
# ---------------------------------------------------------------------------

@router.get("")
async def list_reports() -> dict[str, Any]:
    """List all saved reports."""
    from sqlalchemy import select

    async with async_session() as db:
        result = await db.execute(
            select(Report).order_by(Report.created_at.desc())
        )
        reports = result.scalars().all()

    return {
        "reports": [
            {
                "id": str(r.id),
                "name": r.name,
                "type": r.type,
                "format": r.format,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "created_by": r.created_by,
                "download_url": f"/api/v2/reports/{r.id}/download" if r.status == "ready" else None,
            }
            for r in reports
        ]
    }


# ---------------------------------------------------------------------------
# POST /reports/generate
# ---------------------------------------------------------------------------

@router.post("/generate")
async def generate_report(
    req: GenerateReportRequest,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """Trigger background report generation. Returns report_id immediately."""
    if req.type not in ("coverage", "use_cases", "pipeline", "full"):
        raise HTTPException(status_code=400, detail=f"Unknown report type: {req.type}")
    if req.format not in ("json", "html"):
        raise HTTPException(status_code=400, detail=f"Unknown format: {req.format}")

    report_id = uuid.uuid4()
    name = req.name or f"{req.type.replace('_', ' ').title()} Report — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

    async with async_session() as db:
        report = Report(
            id=report_id,
            name=name,
            type=req.type,
            format=req.format,
            status="generating",
            data=None,
            created_by="system",
        )
        db.add(report)
        await db.commit()

    background_tasks.add_task(
        _generate_report_background,
        str(report_id),
        req.type,
        req.format,
        req.date_range_days,
    )

    return {"report_id": str(report_id), "status": "generating"}


# ---------------------------------------------------------------------------
# GET /reports/{id}
# ---------------------------------------------------------------------------

@router.get("/{report_id}")
async def get_report(report_id: str) -> dict[str, Any]:
    """Get a report by ID with full data."""
    from sqlalchemy import select

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    async with async_session() as db:
        result = await db.execute(select(Report).where(Report.id == rid))
        report = result.scalar_one_or_none()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "id": str(report.id),
        "name": report.name,
        "type": report.type,
        "format": report.format,
        "status": report.status,
        "data": report.data,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "created_by": report.created_by,
        "download_url": f"/api/v2/reports/{report.id}/download" if report.status == "ready" else None,
    }


# ---------------------------------------------------------------------------
# GET /reports/{id}/download
# ---------------------------------------------------------------------------

@router.get("/{report_id}/download")
async def download_report(report_id: str) -> Any:
    """Stream the report file."""
    from sqlalchemy import select

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    async with async_session() as db:
        result = await db.execute(select(Report).where(Report.id == rid))
        report = result.scalar_one_or_none()

    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != "ready":
        raise HTTPException(status_code=400, detail=f"Report is not ready (status: {report.status})")

    if report.format == "html":
        html = _render_html_report(report)
        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition": f'attachment; filename="{_safe_filename(report.name)}.html"',
            },
        )
    else:
        import json
        content = json.dumps(report.data or {}, indent=2, default=str)
        return JSONResponse(
            content=report.data or {},
            headers={
                "Content-Disposition": f'attachment; filename="{_safe_filename(report.name)}.json"',
            },
        )


# ---------------------------------------------------------------------------
# DELETE /reports/{id}
# ---------------------------------------------------------------------------

@router.delete("/{report_id}")
async def delete_report(report_id: str) -> dict[str, str]:
    """Delete a report."""
    from sqlalchemy import select

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    async with async_session() as db:
        result = await db.execute(select(Report).where(Report.id == rid))
        report = result.scalar_one_or_none()
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found")
        await db.delete(report)
        await db.commit()

    return {"status": "deleted"}


# ---------------------------------------------------------------------------
# Background generation
# ---------------------------------------------------------------------------

async def _generate_report_background(
    report_id: str,
    report_type: str,
    report_format: str,
    date_range_days: int,
) -> None:
    """Compute report data and persist to DB."""
    from sqlalchemy import select

    rid = uuid.UUID(report_id)
    try:
        data = await _compute_report_data(report_type, date_range_days)
        status = "ready"
    except Exception as exc:
        logger.error("Report generation failed for %s: %s", report_id, exc)
        data = {"error": str(exc)}
        status = "failed"

    try:
        async with async_session() as db:
            result = await db.execute(select(Report).where(Report.id == rid))
            report = result.scalar_one_or_none()
            if report:
                report.status = status
                report.data = data
                await db.commit()
    except Exception as exc:
        logger.error("Failed to persist report result for %s: %s", report_id, exc)


async def _compute_report_data(report_type: str, date_range_days: int) -> dict[str, Any]:
    """Compute the appropriate report data depending on type."""
    since = datetime.now(timezone.utc) - timedelta(days=date_range_days)

    if report_type == "coverage":
        return await _compute_coverage(since)
    if report_type == "use_cases":
        return await _compute_use_cases(since)
    if report_type == "pipeline":
        return await _compute_pipeline(since)
    if report_type == "full":
        coverage, use_cases, pipeline = await _gather_all(since)
        return {"coverage": coverage, "use_cases": use_cases, "pipeline": pipeline}
    raise ValueError(f"Unknown report type: {report_type}")


async def _gather_all(since: datetime) -> tuple[dict, dict, dict]:
    """Compute all three report sections concurrently."""
    import asyncio
    results = await asyncio.gather(
        _compute_coverage(since),
        _compute_use_cases(since),
        _compute_pipeline(since),
        return_exceptions=True,
    )
    def _safe(r: Any) -> dict:
        if isinstance(r, Exception):
            return {"error": str(r)}
        return r  # type: ignore[return-value]
    return _safe(results[0]), _safe(results[1]), _safe(results[2])


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------

async def _compute_coverage(since: datetime) -> dict[str, Any]:
    """DES score + per-tactic breakdown + top uncovered techniques."""
    from sqlalchemy import select
    from backend.db.models import ImportedRule

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
        "T1566.001", "T1059.001", "T1003.001", "T1110.003",
        "T1543.003", "T1552.007", "T1611", "T1610",
    ]

    _TACTIC_MAP: dict[str, str] = {
        "T1595": "reconnaissance", "T1592": "reconnaissance", "T1589": "reconnaissance",
        "T1590": "reconnaissance", "T1591": "reconnaissance",
        "T1583": "resource_development", "T1584": "resource_development",
        "T1587": "resource_development", "T1588": "resource_development",
        "T1566": "initial_access", "T1190": "initial_access",
        "T1133": "initial_access", "T1078": "initial_access",
        "T1059": "execution", "T1053": "execution", "T1047": "execution",
        "T1204": "execution", "T1203": "execution",
        "T1059.001": "execution", "T1047": "execution",
        "T1547": "persistence", "T1546": "persistence", "T1543": "persistence",
        "T1098": "persistence", "T1543.003": "persistence",
        "T1548": "privilege_escalation", "T1134": "privilege_escalation", "T1055": "privilege_escalation",
        "T1036": "defense_evasion", "T1027": "defense_evasion", "T1070": "defense_evasion",
        "T1562": "defense_evasion", "T1140": "defense_evasion", "T1218": "defense_evasion",
        "T1003": "credential_access", "T1110": "credential_access", "T1555": "credential_access",
        "T1558": "credential_access", "T1552": "credential_access",
        "T1003.001": "credential_access", "T1110.003": "credential_access", "T1552.007": "credential_access",
        "T1083": "discovery", "T1082": "discovery", "T1057": "discovery",
        "T1018": "discovery", "T1016": "discovery",
        "T1021": "lateral_movement", "T1570": "lateral_movement", "T1080": "lateral_movement",
        "T1560": "collection", "T1005": "collection", "T1074": "collection",
        "T1071": "command_and_control", "T1105": "command_and_control", "T1095": "command_and_control",
        "T1572": "command_and_control", "T1573": "command_and_control",
        "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
        "T1486": "impact", "T1490": "impact", "T1489": "impact",
        "T1485": "impact", "T1529": "impact",
        "T1566.001": "initial_access",
        "T1611": "privilege_escalation", "T1610": "defense_evasion",
    }

    async with async_session() as db:
        result = await db.execute(
            select(ImportedRule).where(ImportedRule.enabled == True)
        )
        rules = result.scalars().all()

    covered_techniques: set[str] = set()
    for rule in rules:
        for tech in (rule.mitre_techniques or []):
            covered_techniques.add(tech.upper())

    # Per-tactic breakdown
    tactic_totals: dict[str, int] = {}
    tactic_covered: dict[str, int] = {}
    for tech in _KNOWN_TECHNIQUES:
        tactic = _TACTIC_MAP.get(tech, "other")
        tactic_totals[tactic] = tactic_totals.get(tactic, 0) + 1
        if tech in covered_techniques:
            tactic_covered[tactic] = tactic_covered.get(tactic, 0) + 1

    tactic_breakdown = [
        {
            "tactic": tactic,
            "total": tactic_totals[tactic],
            "covered": tactic_covered.get(tactic, 0),
            "pct": round(tactic_covered.get(tactic, 0) / tactic_totals[tactic] * 100, 1),
        }
        for tactic in sorted(tactic_totals)
    ]

    uncovered = [t for t in _KNOWN_TECHNIQUES if t not in covered_techniques]

    total = len(_KNOWN_TECHNIQUES)
    cov_count = len([t for t in _KNOWN_TECHNIQUES if t in covered_techniques])
    des_score = round(cov_count / total * 100, 1) if total > 0 else 0.0

    # Attempt real DES computation
    try:
        from backend.scoring.des import DetectionEfficacyScore, RuleSummary
        now = datetime.now(timezone.utc)
        summaries = [
            RuleSummary(
                rule_id=str(r.id),
                technique_id=tech.upper(),
                total_tests=0,
                successes=0,
                last_tested_at=r.updated_at,
                false_positive_rate=0.0,
            )
            for r in rules
            for tech in (r.mitre_techniques or [])
        ]
        scorer = DetectionEfficacyScore()
        des = scorer.compute(summaries, _KNOWN_TECHNIQUES, now)
        des_score = round(des.score, 2)
    except Exception as exc:
        logger.debug("DES scorer unavailable, using simple coverage ratio: %s", exc)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "date_range_days": (datetime.now(timezone.utc) - since).days,
        "des_score": des_score,
        "total_rules": len(rules),
        "total_techniques": total,
        "covered_techniques": cov_count,
        "coverage_pct": round(cov_count / total * 100, 1) if total > 0 else 0.0,
        "tactic_breakdown": tactic_breakdown,
        "top_uncovered_techniques": uncovered[:20],
    }


# ---------------------------------------------------------------------------
# Use cases report
# ---------------------------------------------------------------------------

async def _compute_use_cases(since: datetime) -> dict[str, Any]:
    """Total use cases, pass/fail/partial counts, per-tactic, failing list."""
    from sqlalchemy import select
    from backend.db.models import UseCase, UseCaseRun

    async with async_session() as db:
        uc_result = await db.execute(select(UseCase))
        use_cases = uc_result.scalars().all()

        run_result = await db.execute(
            select(UseCaseRun).where(
                UseCaseRun.created_at >= since
            ).order_by(UseCaseRun.created_at.desc())
        )
        runs = run_result.scalars().all()

    # Latest run per use case
    latest_run: dict[str, Any] = {}
    for run in runs:
        uid = str(run.use_case_id)
        if uid not in latest_run:
            latest_run[uid] = run

    pass_count = 0
    fail_count = 0
    partial_count = 0
    never_count = 0
    failing_list: list[dict[str, Any]] = []
    tactic_stats: dict[str, dict[str, int]] = {}

    for uc in use_cases:
        uid = str(uc.id)
        run = latest_run.get(uid)
        status = run.status if run else "never"

        tactic = uc.tactic or "unknown"
        if tactic not in tactic_stats:
            tactic_stats[tactic] = {"total": 0, "pass": 0, "fail": 0, "partial": 0}
        tactic_stats[tactic]["total"] += 1

        if status == "passed":
            pass_count += 1
            tactic_stats[tactic]["pass"] += 1
        elif status == "failed":
            fail_count += 1
            tactic_stats[tactic]["fail"] += 1
            failing_list.append({
                "id": uid,
                "name": uc.name,
                "tactic": tactic,
                "severity": uc.severity,
                "technique_ids": list(uc.technique_ids or []),
                "last_run_at": run.created_at.isoformat() if run and run.created_at else None,
            })
        elif status == "partial":
            partial_count += 1
            tactic_stats[tactic]["partial"] += 1
        else:
            never_count += 1

    tactic_breakdown = [
        {
            "tactic": tactic,
            "total": stats["total"],
            "pass": stats["pass"],
            "fail": stats["fail"],
            "partial": stats["partial"],
        }
        for tactic, stats in sorted(tactic_stats.items())
    ]

    total = len(use_cases)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "date_range_days": (datetime.now(timezone.utc) - since).days,
        "total_use_cases": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "partial_count": partial_count,
        "never_run_count": never_count,
        "pass_rate_pct": round(pass_count / total * 100, 1) if total > 0 else 0.0,
        "tactic_breakdown": tactic_breakdown,
        "failing_use_cases": failing_list,
    }


# ---------------------------------------------------------------------------
# Pipeline report
# ---------------------------------------------------------------------------

async def _compute_pipeline(since: datetime) -> dict[str, Any]:
    """Pipeline run history, avg DES improvement, chains used."""
    from sqlalchemy import select
    from backend.db.models import PipelineRun, PipelineConfig

    async with async_session() as db:
        runs_result = await db.execute(
            select(PipelineRun).where(
                PipelineRun.created_at >= since
            ).order_by(PipelineRun.created_at.desc())
        )
        runs = runs_result.scalars().all()

        configs_result = await db.execute(select(PipelineConfig))
        configs = configs_result.scalars().all()

    config_names: dict[str, str] = {str(c.id): c.name for c in configs}

    total_runs = len(runs)
    completed_runs = [r for r in runs if r.status == "completed"]
    failed_runs = [r for r in runs if r.status == "failed"]

    des_improvements: list[float] = []
    for r in completed_runs:
        if r.des_before is not None and r.des_after is not None:
            des_improvements.append(r.des_after - r.des_before)

    avg_des_improvement = (
        round(sum(des_improvements) / len(des_improvements), 4)
        if des_improvements else 0.0
    )

    run_history = [
        {
            "id": str(r.id),
            "pipeline_name": config_names.get(str(r.pipeline_id), str(r.pipeline_id)),
            "status": r.status,
            "triggered_by": r.triggered_by,
            "chains_run": r.chains_run,
            "events_generated": r.events_generated,
            "detections_fired": r.detections_fired,
            "des_before": r.des_before,
            "des_after": r.des_after,
            "des_delta": round(r.des_after - r.des_before, 4) if r.des_before is not None and r.des_after is not None else None,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs[:50]
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "date_range_days": (datetime.now(timezone.utc) - since).days,
        "total_runs": total_runs,
        "completed_runs": len(completed_runs),
        "failed_runs": len(failed_runs),
        "avg_des_improvement": avg_des_improvement,
        "total_des_improvements": len(des_improvements),
        "run_history": run_history,
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def _render_html_report(report: Report) -> str:
    """Generate a clean, printable HTML string from report data."""
    data = report.data or {}
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = report.name

    body_parts: list[str] = []

    def _section(heading: str, content: str) -> str:
        return f'<section><h2>{heading}</h2>{content}</section>'

    def _kv_table(rows: list[tuple[str, Any]]) -> str:
        cells = "".join(
            f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows
        )
        return f'<table class="kv">{cells}</table>'

    def _data_table(headers: list[str], rows: list[list[Any]]) -> str:
        ths = "".join(f"<th>{h}</th>" for h in headers)
        tbody = "".join(
            "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{ths}</tr></thead><tbody>{tbody}</tbody></table>"

    if report.type in ("coverage", "full"):
        section_data = data.get("coverage", data) if report.type == "full" else data
        kv = _kv_table([
            ("DES Score", section_data.get("des_score", "—")),
            ("Total Rules", section_data.get("total_rules", "—")),
            ("Techniques Covered", section_data.get("covered_techniques", "—")),
            ("Total Techniques", section_data.get("total_techniques", "—")),
            ("Coverage %", f"{section_data.get('coverage_pct', 0)}%"),
        ])
        tactic_rows = [
            [t["tactic"].replace("_", " ").title(), t["total"], t["covered"], f"{t['pct']}%"]
            for t in section_data.get("tactic_breakdown", [])
        ]
        tactic_tbl = _data_table(["Tactic", "Total Techniques", "Covered", "Coverage"], tactic_rows) if tactic_rows else "<p>No tactic data.</p>"
        uncovered = section_data.get("top_uncovered_techniques", [])
        uncov_str = ", ".join(uncovered) if uncovered else "None"
        body_parts.append(_section("Coverage Report", kv + tactic_tbl + f"<p><strong>Top Uncovered Techniques:</strong> {uncov_str}</p>"))

    if report.type in ("use_cases", "full"):
        section_data = data.get("use_cases", data) if report.type == "full" else data
        kv = _kv_table([
            ("Total Use Cases", section_data.get("total_use_cases", "—")),
            ("Passed", section_data.get("pass_count", "—")),
            ("Failed", section_data.get("fail_count", "—")),
            ("Partial", section_data.get("partial_count", "—")),
            ("Never Run", section_data.get("never_run_count", "—")),
            ("Pass Rate", f"{section_data.get('pass_rate_pct', 0)}%"),
        ])
        fail_rows = [
            [f["name"], f["tactic"], f["severity"], ", ".join(f.get("technique_ids", [])), f.get("last_run_at", "—")]
            for f in section_data.get("failing_use_cases", [])
        ]
        fail_tbl = _data_table(["Use Case", "Tactic", "Severity", "Techniques", "Last Run"], fail_rows) if fail_rows else "<p>No failing use cases.</p>"
        body_parts.append(_section("Use Case Report", kv + "<h3>Failing Use Cases</h3>" + fail_tbl))

    if report.type in ("pipeline", "full"):
        section_data = data.get("pipeline", data) if report.type == "full" else data
        kv = _kv_table([
            ("Total Runs", section_data.get("total_runs", "—")),
            ("Completed", section_data.get("completed_runs", "—")),
            ("Failed", section_data.get("failed_runs", "—")),
            ("Avg DES Improvement", section_data.get("avg_des_improvement", "—")),
        ])
        run_rows = [
            [r["pipeline_name"], r["status"], r["triggered_by"], r["chains_run"],
             r["events_generated"], r["detections_fired"],
             r["des_delta"] if r["des_delta"] is not None else "—",
             r.get("started_at", "—")]
            for r in section_data.get("run_history", [])[:20]
        ]
        run_tbl = _data_table(["Pipeline", "Status", "Triggered By", "Chains", "Events", "Detections", "DES Delta", "Started At"], run_rows) if run_rows else "<p>No run history.</p>"
        body_parts.append(_section("Pipeline Report", kv + run_tbl))

    body_html = "\n".join(body_parts) if body_parts else "<p>No data available.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1e293b; background: #fff; padding: 40px; max-width: 1100px; margin: 0 auto; }}
  header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }}
  header h1 {{ font-size: 22px; font-weight: 700; color: #0f172a; }}
  header p {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
  section {{ margin-bottom: 36px; }}
  h2 {{ font-size: 16px; font-weight: 700; color: #0f172a; border-left: 3px solid #6366f1; padding-left: 10px; margin-bottom: 14px; }}
  h3 {{ font-size: 13px; font-weight: 600; color: #334155; margin: 16px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 14px; }}
  th {{ background: #f1f5f9; text-align: left; padding: 7px 10px; font-weight: 600; color: #475569; border: 1px solid #e2e8f0; }}
  td {{ padding: 6px 10px; border: 1px solid #e2e8f0; color: #334155; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}
  table.kv {{ max-width: 480px; }}
  table.kv th {{ width: 45%; }}
  p {{ font-size: 13px; color: #475569; margin: 8px 0; }}
  @media print {{ body {{ padding: 20px; }} }}
</style>
</head>
<body>
<header>
  <h1>PurpleLab — {title}</h1>
  <p>Generated {now_str} &nbsp;·&nbsp; Type: {report.type} &nbsp;·&nbsp; Date range: {data.get('date_range_days', '?')} days</p>
</header>
{body_html}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_filename(name: str) -> str:
    """Strip unsafe characters for use in Content-Disposition filename."""
    safe = "".join(c if c.isalnum() or c in (" ", "-", "_") else "_" for c in name)
    return safe.strip()[:80] or "report"
