"""3-Agent LLM Synthesis Loop for simulated log quality improvement.

The loop runs up to MAX_ROUNDS iterations of:
  1. Generator  — produce initial batch of events for a technique + source
  2. Evaluator  — score and critique the batch (realism, vendor fidelity, detection signal)
  3. Improver   — apply the critique to generate a higher-quality batch

Early exit when the Evaluator scores the batch >= QUALITY_THRESHOLD.
Final result is cached at the same key as normal single-pass generation so
the improved events are served on the next call without re-running the loop.

Usage::

    from backend.engine.synthesis_loop import run_synthesis_loop

    result = await run_synthesis_loop(
        source_id="crowdstrike_edr",
        technique_id="T1059.001",
        count=10,
        schema_text="...",     # from SchemaRegistry.get_schema_text()
        max_rounds=3,
    )
    # result: {"events": [...], "rounds": 2, "final_score": 0.87, "critiques": [...]}
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

log = logging.getLogger(__name__)

MAX_ROUNDS = 3
QUALITY_THRESHOLD = 0.80   # Stop iterating when Evaluator score >= this


# ── Prompts ───────────────────────────────────────────────────────────────────

_GENERATOR_SYSTEM = """You are an expert cybersecurity simulation engineer that generates realistic,
vendor-accurate security log events for red team / blue team exercises.

Your events must:
- Match the exact field schema for the specified log source (vendor format)
- Accurately represent the MITRE ATT&CK technique being simulated
- Include realistic values (real tool names, plausible command lines, valid IP ranges)
- NOT include any markers that distinguish them from real production logs

Return ONLY a JSON array of events. No markdown, no explanation."""


_GENERATOR_USER = """Generate {count} realistic log events.

LOG SOURCE: {source_id}
MITRE TECHNIQUE: {technique_id}
SCHEMA REFERENCE:
{schema_text}

CONTEXT (use these exact values):
{context_block}

Requirements:
- Use the schema field names exactly as shown above
- Timestamps should span a 30-60 minute window
- Vary CommandLine / argument patterns to avoid repetition
- Include parent process chain where relevant
- Mix realistic benign-looking fields with the attack-specific fields"""


_EVALUATOR_SYSTEM = """You are a senior threat detection engineer evaluating simulated log quality.
Score the batch and provide actionable improvement critique.

Return a JSON object with exactly this structure:
{
  "score": <float 0.0-1.0>,
  "vendor_fidelity": <float 0.0-1.0>,
  "technique_accuracy": <float 0.0-1.0>,
  "detection_signal": <float 0.0-1.0>,
  "realism": <float 0.0-1.0>,
  "critiques": ["<specific issue 1>", "<specific issue 2>", ...],
  "improvements": ["<specific change 1>", "<specific change 2>", ...],
  "summary": "<one sentence>"
}

Scoring criteria:
- vendor_fidelity: Do fields match the vendor's actual log format?
- technique_accuracy: Does the activity accurately represent the MITRE technique?
- detection_signal: Would a Sigma/YARA rule reliably fire on these events?
- realism: Do values look like real production logs (not obviously fake)?
- score: Weighted average (vendor_fidelity×0.3 + technique_accuracy×0.25 + detection_signal×0.25 + realism×0.2)"""


_EVALUATOR_USER = """Evaluate this batch of {count} simulated {source_id} events for technique {technique_id}:

SCHEMA REFERENCE:
{schema_text}

EVENTS TO EVALUATE:
{events_json}"""


_IMPROVER_SYSTEM = """You are an expert cybersecurity simulation engineer improving simulated log events
based on a quality critique. Apply every suggested improvement precisely.

Return ONLY a JSON array of improved events. No markdown, no explanation."""


_IMPROVER_USER = """Improve this batch of {count} simulated {source_id} events for technique {technique_id}.

SCHEMA REFERENCE:
{schema_text}

CONTEXT (use these exact values):
{context_block}

QUALITY CRITIQUE (apply ALL improvements listed):
Score: {score:.2f}/1.0
Issues: {critiques}
Required improvements: {improvements}
Summary: {summary}

CURRENT EVENTS (improve these — keep the count at {count}):
{events_json}"""


# ── LLM helpers ───────────────────────────────────────────────────────────────

async def _call_llm(system: str, user: str, max_tokens: int = 4096) -> str:
    """Call the LLM using the LOG_GENERATION function route."""
    from backend.llm.config import LLMFunction
    from backend.llm.router import get_router

    router = get_router()
    client = router.get_client(LLMFunction.LOG_GENERATION)
    response = await client.complete(
        messages=[{"role": "user", "content": user}],
        system=system,
        max_tokens=max_tokens,
        temperature=0.7,
        json_mode=True,
    )
    return response.text.strip()


def _parse_events(text: str) -> list[dict[str, Any]]:
    """Parse LLM output to a list of event dicts."""
    raw = text
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    parsed = json.loads(raw)
    if isinstance(parsed, dict) and "events" in parsed:
        parsed = parsed["events"]
    if not isinstance(parsed, list):
        parsed = [parsed]
    return parsed


def _parse_eval(text: str) -> dict[str, Any]:
    """Parse the Evaluator's JSON critique."""
    raw = text
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    return json.loads(raw)


def _default_eval() -> dict[str, Any]:
    return {
        "score": 0.5,
        "vendor_fidelity": 0.5,
        "technique_accuracy": 0.5,
        "detection_signal": 0.5,
        "realism": 0.5,
        "critiques": ["Evaluation failed — using default score"],
        "improvements": [],
        "summary": "Evaluation error",
    }


# ── Public API ────────────────────────────────────────────────────────────────

async def run_synthesis_loop(
    source_id: str,
    technique_id: str,
    count: int,
    schema_text: str,
    context_block: str = "",
    max_rounds: int = MAX_ROUNDS,
    quality_threshold: float = QUALITY_THRESHOLD,
) -> dict[str, Any]:
    """Run the Generator → Evaluator → Improver loop.

    Args:
        source_id:         Log source ID (e.g. 'crowdstrike_edr').
        technique_id:      MITRE ATT&CK technique (e.g. 'T1059.001').
        count:             Number of events to generate.
        schema_text:       Vendor schema text from SchemaRegistry.
        context_block:     Optional SimulationContext text block for entity coherence.
        max_rounds:        Maximum improvement iterations (default 3).
        quality_threshold: Stop early when score >= this value (default 0.80).

    Returns:
        dict with keys: events, rounds, final_score, critiques, timing_ms
    """
    t_start = time.monotonic()
    events: list[dict[str, Any]] = []
    round_critiques: list[dict[str, Any]] = []
    rounds_run = 0
    final_score = 0.0

    for rnd in range(1, max_rounds + 1):
        rounds_run = rnd
        log.info("synthesis_loop round=%d source=%s technique=%s count=%d", rnd, source_id, technique_id, count)

        # ── Round 1: Generator ────────────────────────────────────────────────
        if rnd == 1:
            gen_user = _GENERATOR_USER.format(
                count=count,
                source_id=source_id,
                technique_id=technique_id,
                schema_text=schema_text[:3000],
                context_block=context_block or "(no specific entity context — use generic realistic values)",
            )
            try:
                raw = await _call_llm(_GENERATOR_SYSTEM, gen_user,
                                      max_tokens=max(2000, count * 200))
                events = _parse_events(raw)
                log.info("synthesis_loop round=1 generated=%d events", len(events))
            except Exception as exc:
                log.warning("synthesis_loop generator failed: %s", exc)
                return {
                    "events": [], "rounds": rounds_run, "final_score": 0.0,
                    "critiques": [{"error": str(exc)}], "timing_ms": int((time.monotonic() - t_start) * 1000),
                }

        # ── Evaluator ─────────────────────────────────────────────────────────
        eval_user = _EVALUATOR_USER.format(
            count=len(events),
            source_id=source_id,
            technique_id=technique_id,
            schema_text=schema_text[:2000],
            events_json=json.dumps(events[:10], indent=2)[:4000],  # Show up to 10 for eval
        )
        try:
            eval_raw = await _call_llm(_EVALUATOR_SYSTEM, eval_user, max_tokens=1024)
            critique = _parse_eval(eval_raw)
        except Exception as exc:
            log.warning("synthesis_loop evaluator failed round=%d: %s", rnd, exc)
            critique = _default_eval()

        final_score = float(critique.get("score", 0.5))
        round_critiques.append({
            "round": rnd,
            "score": final_score,
            "vendor_fidelity": critique.get("vendor_fidelity", 0.5),
            "technique_accuracy": critique.get("technique_accuracy", 0.5),
            "detection_signal": critique.get("detection_signal", 0.5),
            "realism": critique.get("realism", 0.5),
            "critiques": critique.get("critiques", []),
            "improvements": critique.get("improvements", []),
            "summary": critique.get("summary", ""),
        })
        log.info("synthesis_loop round=%d score=%.2f", rnd, final_score)

        # Early exit if quality is good enough
        if final_score >= quality_threshold:
            log.info("synthesis_loop early exit: score %.2f >= threshold %.2f", final_score, quality_threshold)
            break

        # ── Improver (runs if we haven't hit max_rounds yet) ──────────────────
        if rnd < max_rounds:
            imp_user = _IMPROVER_USER.format(
                count=count,
                source_id=source_id,
                technique_id=technique_id,
                schema_text=schema_text[:3000],
                context_block=context_block or "(use generic realistic values)",
                score=final_score,
                critiques="\n- ".join(critique.get("critiques", [])) or "None",
                improvements="\n- ".join(critique.get("improvements", [])) or "None",
                summary=critique.get("summary", ""),
                events_json=json.dumps(events[:count], indent=2)[:4000],
            )
            try:
                imp_raw = await _call_llm(_IMPROVER_SYSTEM, imp_user,
                                          max_tokens=max(2000, count * 200))
                improved = _parse_events(imp_raw)
                if improved:
                    events = improved
                    log.info("synthesis_loop round=%d improved=%d events", rnd, len(events))
            except Exception as exc:
                log.warning("synthesis_loop improver failed round=%d: %s", rnd, exc)
                # Keep existing events, don't bail — run evaluator next round

    timing_ms = int((time.monotonic() - t_start) * 1000)
    log.info(
        "synthesis_loop done source=%s technique=%s rounds=%d score=%.2f events=%d timing_ms=%d",
        source_id, technique_id, rounds_run, final_score, len(events), timing_ms,
    )

    return {
        "events": events,
        "rounds": rounds_run,
        "final_score": final_score,
        "critiques": round_critiques,
        "timing_ms": timing_ms,
    }
