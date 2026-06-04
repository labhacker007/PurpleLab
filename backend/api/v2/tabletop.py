"""Tabletop Exercise API endpoints."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.engine.tabletop import (
    compute_final_score,
    generate_aar,
    get_scenario,
    list_scenarios,
    score_response,
)

router = APIRouter(prefix="/api/v2/tabletop", tags=["tabletop"])


# ── Models ────────────────────────────────────────────────────────────────────

class CreateExerciseRequest(BaseModel):
    name: str = ""
    scenario_key: str
    session_id: Optional[str] = None
    environment_id: Optional[str] = None
    team_size: int = 4


class RespondRequest(BaseModel):
    decision_index: int
    rationale: str = ""


# ── Scenarios ─────────────────────────────────────────────────────────────────

@router.get("/scenarios")
async def get_scenarios():
    """List all available tabletop scenario templates."""
    return {"scenarios": list_scenarios()}


@router.get("/scenarios/{scenario_key}")
async def get_scenario_detail(scenario_key: str):
    s = get_scenario(scenario_key)
    if not s:
        raise HTTPException(404, detail=f"Scenario '{scenario_key}' not found")
    phases_meta = [
        {
            "phase": p["phase"],
            "title": p["title"],
            "timer_minutes": p.get("timer_minutes", 10),
            "decision_count": len(p.get("decisions", [])),
        }
        for p in s.get("phases", [])
    ]
    return {
        "key": scenario_key,
        "name": s["name"],
        "description": s["description"],
        "total_phases": s["total_phases"],
        "expected_duration_minutes": s["expected_duration_minutes"],
        "phases": phases_meta,
    }


# ── Exercise CRUD + Orchestration ─────────────────────────────────────────────

@router.post("/exercises")
async def create_exercise(req: CreateExerciseRequest):
    """Create a new tabletop exercise from a scenario template."""
    scenario = get_scenario(req.scenario_key)
    if not scenario:
        raise HTTPException(400, detail=f"Unknown scenario: {req.scenario_key}")

    exc_id = uuid.uuid4()
    name = req.name or scenario["name"]

    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as db:
            await db.execute(text("""
                INSERT INTO tabletop_exercises
                    (id, name, description, scenario_key, status, session_id, environment_id, team_size, script, current_phase, responses, created_at, updated_at)
                VALUES
                    (:id, :name, :desc, :scenario_key, 'draft', :session_id, :env_id, :team_size, CAST(:script AS JSONB), 0, '[]'::JSONB, now(), now())
            """), {
                "id": exc_id,
                "name": name,
                "desc": scenario["description"],
                "scenario_key": req.scenario_key,
                "session_id": uuid.UUID(req.session_id) if req.session_id else None,
                "env_id": uuid.UUID(req.environment_id) if req.environment_id else None,
                "team_size": req.team_size,
                "script": json.dumps(scenario["phases"]),
            })
            await db.commit()
    except Exception as exc:
        pass

    return {
        "id": str(exc_id),
        "name": name,
        "scenario_key": req.scenario_key,
        "status": "draft",
        "total_phases": scenario["total_phases"],
        "session_id": req.session_id,
    }


@router.post("/exercises/{exercise_id}/start")
async def start_exercise(exercise_id: str):
    """Begin a tabletop exercise — returns the first inject."""
    exc = await _get_exercise(exercise_id)
    if not exc:
        raise HTTPException(404, detail="Exercise not found")

    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as db:
            await db.execute(text("""
                UPDATE tabletop_exercises
                SET status='running', current_phase=1, started_at=now(), updated_at=now()
                WHERE id=:id
            """), {"id": uuid.UUID(exercise_id)})
            await db.commit()
    except Exception:
        pass

    scenario = get_scenario(exc.get("scenario_key", ""))
    if not scenario or not scenario.get("phases"):
        raise HTTPException(400, detail="Scenario has no phases")

    first_phase = scenario["phases"][0]
    return {
        "status": "running",
        "current_phase": 1,
        "total_phases": scenario["total_phases"],
        "inject": {
            "phase": 1,
            "title": first_phase["title"],
            "narrative": first_phase["inject"],
            "observables": first_phase.get("observables", []),
            "decisions": first_phase["decisions"],
            "timer_minutes": first_phase.get("timer_minutes", 10),
        },
    }


@router.get("/exercises/{exercise_id}/status")
async def get_exercise_status(exercise_id: str):
    """Get current exercise state — what phase, pending decisions."""
    exc = await _get_exercise(exercise_id)
    if not exc:
        raise HTTPException(404, detail="Exercise not found")

    scenario = get_scenario(exc.get("scenario_key", ""))
    current_phase = exc.get("current_phase", 0)
    responses = exc.get("responses") or []

    result = {
        "id": exercise_id,
        "name": exc.get("name", ""),
        "scenario_key": exc.get("scenario_key"),
        "status": exc.get("status", "draft"),
        "current_phase": current_phase,
        "total_phases": exc.get("total_phases", 0),
        "phases_completed": len(responses),
        "score_so_far": exc.get("score"),
        "started_at": exc.get("started_at"),
    }

    if exc.get("status") == "running" and scenario:
        phases = scenario.get("phases", [])
        for phase in phases:
            if phase["phase"] == current_phase:
                result["current_inject"] = {
                    "phase": current_phase,
                    "title": phase["title"],
                    "narrative": phase["inject"],
                    "observables": phase.get("observables", []),
                    "decisions": phase["decisions"],
                    "timer_minutes": phase.get("timer_minutes", 10),
                }
                break

    return result


@router.post("/exercises/{exercise_id}/respond")
async def respond_to_phase(exercise_id: str, req: RespondRequest):
    """Record a team decision for the current phase."""
    exc = await _get_exercise(exercise_id)
    if not exc:
        raise HTTPException(404, detail="Exercise not found")

    if exc.get("status") != "running":
        raise HTTPException(400, detail=f"Exercise is not running (status={exc.get('status')})")

    current_phase = exc.get("current_phase", 1)
    scenario_key = exc.get("scenario_key", "")
    phase_score = score_response(scenario_key, current_phase, str(req.decision_index))

    responses = list(exc.get("responses") or [])
    response_record = {
        "phase": current_phase,
        "decision_index": req.decision_index,
        "rationale": req.rationale,
        "score": phase_score,
        "time_seconds": None,
    }
    responses.append(response_record)

    scenario = get_scenario(scenario_key)
    total_phases = scenario["total_phases"] if scenario else 0
    next_phase = current_phase + 1
    is_complete = next_phase > total_phases

    new_status = "completed" if is_complete else "running"
    final_score = compute_final_score(scenario_key, responses) if is_complete else None

    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as db:
            params: dict = {
                "id": uuid.UUID(exercise_id),
                "current_phase": next_phase if not is_complete else current_phase,
                "status": new_status,
                "responses": json.dumps(responses),
                "score": final_score,
            }
            score_clause = ", score=:score" if is_complete else ""
            ended_clause = ", ended_at=now()" if is_complete else ""
            await db.execute(text(f"""
                UPDATE tabletop_exercises
                SET current_phase=:current_phase, status=:status,
                    responses=CAST(:responses AS JSONB)
                    {score_clause}{ended_clause}, updated_at=now()
                WHERE id=:id
            """), params)
            await db.commit()
    except Exception:
        pass

    result: dict = {
        "phase_completed": current_phase,
        "score_this_phase": phase_score,
        "decision_taken": req.decision_index,
    }

    if is_complete:
        aar = generate_aar({
            "scenario_key": scenario_key,
            "responses": responses,
            "score": final_score,
        })
        result.update({
            "exercise_complete": True,
            "final_score": final_score,
            "performance_rating": aar["performance_rating"],
            "after_action_report": aar,
        })
    else:
        phases = scenario.get("phases", []) if scenario else []
        for phase in phases:
            if phase["phase"] == next_phase:
                result["next_inject"] = {
                    "phase": next_phase,
                    "title": phase["title"],
                    "narrative": phase["inject"],
                    "observables": phase.get("observables", []),
                    "decisions": phase["decisions"],
                    "timer_minutes": phase.get("timer_minutes", 10),
                }
                break

    return result


@router.get("/exercises/{exercise_id}/report")
async def get_after_action_report(exercise_id: str):
    """Generate or retrieve the after-action report for a completed exercise."""
    exc = await _get_exercise(exercise_id)
    if not exc:
        raise HTTPException(404, detail="Exercise not found")

    if exc.get("status") not in ("completed",):
        raise HTTPException(400, detail="Exercise is not yet complete")

    aar = generate_aar({
        "scenario_key": exc.get("scenario_key", ""),
        "responses": exc.get("responses") or [],
        "score": exc.get("score", 0),
    })
    return {"exercise_id": exercise_id, "report": aar}


@router.get("/exercises")
async def list_exercises(
    status: Optional[str] = Query(None),
    limit: int = Query(20),
):
    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as db:
            where = "WHERE status=:status" if status else ""
            params: dict = {"limit": limit}
            if status:
                params["status"] = status
            rows = (await db.execute(text(f"""
                SELECT id, name, scenario_key, status, current_phase, score, started_at, ended_at, created_at
                FROM tabletop_exercises {where}
                ORDER BY created_at DESC LIMIT :limit
            """), params)).fetchall()
        return {
            "exercises": [
                {
                    "id": str(r[0]),
                    "name": r[1],
                    "scenario_key": r[2],
                    "status": r[3],
                    "current_phase": r[4],
                    "score": r[5],
                    "started_at": r[6].isoformat() if r[6] else None,
                    "ended_at": r[7].isoformat() if r[7] else None,
                    "created_at": r[8].isoformat() if r[8] else None,
                }
                for r in rows
            ]
        }
    except Exception as exc:
        return {"exercises": [], "error": str(exc)}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_exercise(exercise_id: str) -> Optional[dict]:
    try:
        from backend.db.session import async_session
        from sqlalchemy import text
        async with async_session() as db:
            row = (await db.execute(text("""
                SELECT id, name, scenario_key, status, current_phase, score, responses,
                       session_id, started_at, ended_at
                FROM tabletop_exercises WHERE id=:id
            """), {"id": uuid.UUID(exercise_id)})).fetchone()
        if not row:
            return None
        scenario = get_scenario(row[2] or "")
        return {
            "id": str(row[0]),
            "name": row[1],
            "scenario_key": row[2],
            "status": row[3],
            "current_phase": row[4] or 0,
            "score": row[5],
            "responses": row[6] or [],
            "session_id": str(row[7]) if row[7] else None,
            "started_at": row[8].isoformat() if row[8] else None,
            "ended_at": row[9].isoformat() if row[9] else None,
            "total_phases": scenario["total_phases"] if scenario else 0,
        }
    except Exception:
        return None
