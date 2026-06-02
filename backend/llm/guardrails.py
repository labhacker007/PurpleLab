"""AI Guardrails engine — wraps LLM function calls with safety controls.

Provides content filtering, rate limiting, input token estimation, and
PII detection/masking for all LLM function calls.
"""
from __future__ import annotations

import json
import logging
import re
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# In-memory rate limiter: function_name → list of call timestamps (sliding window)
_rate_windows: dict[str, list[float]] = defaultdict(list)

# Common PII patterns (pattern, replacement_tag)
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_ADDRESS]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "[CREDIT_CARD]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
]

_DEFAULT_GUARDRAIL_CONFIG: dict[str, Any] = {
    "enabled": True,
    "max_input_tokens": 32000,
    "max_output_tokens": 8192,
    "rate_limit_per_minute": 60,
    "block_patterns": [],
    "require_json_output": False,
    "pii_masking_enabled": False,
    "system_prompt_override": None,
}


def check_guardrails(
    function_name: str,
    input_text: str,
    config: dict[str, Any],
) -> tuple[bool, str]:
    """Check if the input passes all enabled guardrails.

    Returns (passed: bool, reason: str). If passed is False, reason
    describes which guardrail blocked the request.

    Checks (in order):
    1. Guardrails enabled flag
    2. Rate limit (sliding window per minute)
    3. Input token estimate (len(input_text) // 4)
    4. Block patterns (regex match against input)
    5. PII patterns if pii_masking_enabled is False (just detection, not blocking)
    """
    if not config.get("enabled", True):
        return False, "Guardrails are disabled for this function"

    # --- Rate limit check ---
    rate_limit = config.get("rate_limit_per_minute", 60)
    if rate_limit > 0:
        now = time.monotonic()
        window = _rate_windows[function_name]
        # Prune entries older than 60 seconds
        cutoff = now - 60.0
        _rate_windows[function_name] = [t for t in window if t > cutoff]
        if len(_rate_windows[function_name]) >= rate_limit:
            return False, (
                f"Rate limit exceeded for {function_name}: "
                f"{rate_limit} calls/minute"
            )
        _rate_windows[function_name].append(now)

    # --- Input token estimate ---
    max_input = config.get("max_input_tokens", 32000)
    estimated_tokens = len(input_text) // 4
    if estimated_tokens > max_input:
        return False, (
            f"Input too large: estimated {estimated_tokens} tokens exceeds "
            f"max_input_tokens={max_input}"
        )

    # --- Block patterns ---
    block_patterns: list[str] = config.get("block_patterns", []) or []
    for pattern_str in block_patterns:
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(input_text):
                return False, f"Input blocked by pattern: {pattern_str!r}"
        except re.error as exc:
            logger.warning("Invalid block pattern %r: %s", pattern_str, exc)

    return True, "ok"


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Detect and mask PII from text.

    Returns (masked_text, list_of_detected_pii_types).
    Replaces matched patterns with [EMAIL], [IP_ADDRESS], [SSN],
    [CREDIT_CARD], [PHONE] placeholders.
    """
    detected_types: list[str] = []
    masked = text

    for pattern, replacement in _PII_PATTERNS:
        pii_type = replacement.strip("[]")
        if pattern.search(masked):
            masked = pattern.sub(replacement, masked)
            detected_types.append(pii_type)

    return masked, detected_types


def validate_output(output: str, require_json: bool) -> tuple[bool, str]:
    """Validate LLM output.

    If require_json=True, attempt to parse output as JSON.
    Returns (valid: bool, error_message: str).
    """
    if not require_json:
        return True, ""

    # Strip markdown code fences if present
    stripped = output.strip()
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        # Remove first line (```json or ```) and last line (```)
        inner = "\n".join(lines[1:-1]) if len(lines) > 2 else stripped
        stripped = inner.strip()

    try:
        json.loads(stripped)
        return True, ""
    except (json.JSONDecodeError, ValueError) as exc:
        return False, f"Output is not valid JSON: {exc}"


async def load_guardrail_config(function_name: str) -> dict[str, Any]:
    """Load guardrail config from DB for a function.

    Returns default config dict if no DB record exists or if the DB
    is unavailable.
    """
    try:
        from backend.db.models import AIGuardrailConfig
        from backend.db.session import async_session
        from sqlalchemy import select

        async with async_session() as session:
            row = await session.scalar(
                select(AIGuardrailConfig).where(
                    AIGuardrailConfig.function_name == function_name
                )
            )
            if row:
                return {
                    "enabled": row.enabled,
                    "max_input_tokens": row.max_input_tokens,
                    "max_output_tokens": row.max_output_tokens,
                    "rate_limit_per_minute": row.rate_limit_per_minute,
                    "block_patterns": row.block_patterns or [],
                    "require_json_output": row.require_json_output,
                    "pii_masking_enabled": row.pii_masking_enabled,
                    "system_prompt_override": row.system_prompt_override,
                    "notes": row.notes or "",
                }
    except Exception as exc:
        logger.debug("Could not load guardrail config from DB for %s: %s", function_name, exc)

    return dict(_DEFAULT_GUARDRAIL_CONFIG)
