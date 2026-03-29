"""Agentic Log Generator.

Generates realistic log events dynamically using Claude as the reasoning engine.
Schemas are read from the SchemaRegistry (ChromaDB-backed), never hardcoded.

Caching strategy:
  - Cache key: ``log_template:{source_id}:{schema_version}:{technique_id}``
  - Backend: Redis (if available) → in-memory fallback
  - Invalidation: automatic when schema version changes; explicit via force_refresh
  - Each cached entry stores a list of event templates (not rendered events)
  - At generation time, templates are rendered with fresh timestamps/IPs/usernames
    to produce unique events without calling Claude again.

Flow:
  1. Caller requests N events for (source_id, technique_id).
  2. Check cache for a template batch.
  3. On miss → load schema from registry → call Claude → parse → cache.
  4. Render templates to concrete events (inject live timestamps, randomised fields).
  5. Optionally mix in benign noise at configurable signal-to-noise ratio.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cache Layer
# ---------------------------------------------------------------------------

class _MemoryCache:
    """Simple in-process TTL cache used when Redis is unavailable."""

    def __init__(self, default_ttl: int = 86400) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        ttl = ttl or self.default_ttl
        self._store[key] = (value, time.monotonic() + ttl)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def flush_prefix(self, prefix: str) -> int:
        keys = [k for k in self._store if k.startswith(prefix)]
        for k in keys:
            del self._store[k]
        return len(keys)


class _CacheBackend:
    """Unified cache backend — Redis preferred, memory fallback."""

    def __init__(self) -> None:
        self._redis: Any = None
        self._memory = _MemoryCache()
        self._redis_checked = False

    async def _get_redis(self) -> Any | None:
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            import redis.asyncio as aioredis
            r = aioredis.from_url("redis://localhost:6379", decode_responses=True)
            await r.ping()
            self._redis = r
            logger.info("AgenticGenerator: Redis cache connected")
        except Exception:
            logger.info("AgenticGenerator: Redis unavailable, using memory cache")
        return self._redis

    async def get(self, key: str) -> Any | None:
        r = await self._get_redis()
        if r:
            try:
                raw = await r.get(key)
                return json.loads(raw) if raw else None
            except Exception:
                pass
        return self._memory.get(key)

    async def set(self, key: str, value: Any, ttl: int = 86400) -> None:
        r = await self._get_redis()
        if r:
            try:
                await r.setex(key, ttl, json.dumps(value, default=str))
                return
            except Exception:
                pass
        self._memory.set(key, value, ttl)

    async def delete(self, key: str) -> None:
        r = await self._get_redis()
        if r:
            try:
                await r.delete(key)
            except Exception:
                pass
        self._memory.delete(key)

    async def flush_source(self, source_id: str) -> int:
        """Invalidate all cached templates for a source (schema update)."""
        prefix = f"log_template:{source_id}:"
        r = await self._get_redis()
        count = 0
        if r:
            try:
                keys = await r.keys(f"{prefix}*")
                if keys:
                    count = await r.delete(*keys)
                return count
            except Exception:
                pass
        return self._memory.flush_prefix(prefix)


_cache = _CacheBackend()


# ---------------------------------------------------------------------------
# Template Renderer — makes cached templates into live events
# ---------------------------------------------------------------------------

_FAKE_USERS = [
    "jsmith", "mwilson", "agarcia", "kwang", "tpatel", "rnguyen",
    "dbrown", "lmartinez", "clee", "sthompson",
]
_FAKE_HOSTS = [
    "WKSTN-FIN-042", "WKSTN-ENG-107", "SRV-DC-01", "SRV-APP-03",
    "WKSTN-HR-015", "SRV-WEB-02", "LAPTOP-SEC-001", "WKSTN-OPS-09",
]
_FAKE_INTERNAL_IPS = [
    "10.1.2.{}", "10.1.3.{}", "10.2.0.{}", "192.168.1.{}",
]
_FAKE_EXTERNAL_IPS = [
    "185.220.101.{}", "198.51.100.{}", "203.0.113.{}", "91.108.4.{}",
]


def _random_ip(internal: bool = True) -> str:
    template = random.choice(_FAKE_INTERNAL_IPS if internal else _FAKE_EXTERNAL_IPS)
    return template.format(random.randint(1, 254))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _jitter_time(base: datetime, max_seconds: int = 120) -> str:
    delta = timedelta(seconds=random.randint(0, max_seconds))
    return (base + delta).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _render_template(template: dict[str, Any], base_time: datetime) -> dict[str, Any]:
    """Deep-copy a template and inject live/randomised values."""
    event = json.loads(json.dumps(template, default=str))

    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(i) for i in obj]
        if isinstance(obj, str):
            if obj == "__TIMESTAMP__":
                return _jitter_time(base_time)
            if obj == "__USER__":
                return random.choice(_FAKE_USERS)
            if obj == "__HOST__":
                return random.choice(_FAKE_HOSTS)
            if obj == "__INTERNAL_IP__":
                return _random_ip(internal=True)
            if obj == "__EXTERNAL_IP__":
                return _random_ip(internal=False)
        return obj

    rendered = _walk(event)
    rendered["_purplelab_generated_at"] = _now_iso()
    return rendered


# ---------------------------------------------------------------------------
# Claude-based Template Generator
# ---------------------------------------------------------------------------

_GENERATION_PROMPT = """\
You are a cybersecurity log synthesis expert. Generate realistic log events for a purple team simulation.

## Log Source Schema
{schema_text}

## Task
Generate {count} realistic log events showing technique **{technique_id}** ({technique_name}).

## Rules
1. Events MUST conform strictly to the schema above (use correct field names and types).
2. Make events varied — different users, hosts, IPs, timestamps, command lines.
3. Use placeholder tokens for fields that should be randomised at render time:
   - `"__TIMESTAMP__"` for any timestamp field
   - `"__USER__"` for a username
   - `"__HOST__"` for a hostname
   - `"__INTERNAL_IP__"` for internal IP addresses
   - `"__EXTERNAL_IP__"` for attacker/external IPs
4. Include realistic attack-pattern indicators (not obviously fake).
5. Do NOT include markdown fences — return ONLY a valid JSON array of event objects.
6. Target event types from schema mitre_mappings for this technique where possible.

Return a JSON array of {count} event objects. No explanation, no markdown — raw JSON only.
"""

_BENIGN_PROMPT = """\
You are a cybersecurity log synthesis expert. Generate realistic BENIGN (normal) log events.

## Log Source Schema
{schema_text}

## Task
Generate {count} realistic normal/benign events from this log source — day-to-day business activity.

## Rules
1. Events MUST conform to the schema above.
2. Use placeholder tokens: `"__TIMESTAMP__"`, `"__USER__"`, `"__HOST__"`, `"__INTERNAL_IP__"`, `"__EXTERNAL_IP__"`.
3. Make events varied (different users, hosts, actions).
4. No attack indicators.
5. Return ONLY a valid JSON array — no markdown, no explanation.

Return a JSON array of {count} event objects.
"""


async def _call_claude_for_templates(
    prompt: str,
    max_tokens: int = 4096,
) -> list[dict[str, Any]]:
    """Call the configured LLM (via router) and parse the JSON array response.

    Routes to whatever provider is configured for LOG_GENERATION:
    Claude, GPT-4o, Gemini, or a local Ollama model.
    """
    from backend.llm.router import get_router
    from backend.llm.config import LLMFunction

    router = get_router()
    client = await router.get_client_async(LLMFunction.LOG_GENERATION)
    resp = await client.complete(
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        json_mode=True,
    )
    raw = resp.text.strip()

    # Strip accidental markdown fences (some models still add them)
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    try:
        events = json.loads(raw)
        if not isinstance(events, list):
            events = [events]
        return events
    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON for template generation: %s — %s", exc, raw[:300])
        return []


# ---------------------------------------------------------------------------
# Main Generator Class
# ---------------------------------------------------------------------------

class AgenticLogGenerator:
    """Generates log events using Claude + schema registry + caching.

    Usage::

        gen = AgenticLogGenerator()
        events = await gen.generate(
            source_id="windows_sysmon",
            technique_id="T1059.001",
            count=20,
        )
    """

    TEMPLATE_BATCH_SIZE = 10    # How many templates Claude generates per call
    TEMPLATE_CACHE_TTL = 86400  # 24 hours; invalidated on schema version change

    def __init__(self) -> None:
        from backend.log_sources.schema_registry import get_registry
        self._registry = get_registry()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        source_id: str,
        technique_id: str,
        count: int = 10,
        snr_ratio: float = 1.0,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Generate ``count`` log events for a source + technique pair.

        Args:
            source_id: Registry source ID (e.g. "windows_sysmon").
            technique_id: MITRE ATT&CK technique (e.g. "T1059.001").
            count: Number of events to return.
            snr_ratio: Signal-to-noise ratio. 1.0 = all attack events.
                       0.1 = 10% attack, 90% benign noise.
            force_refresh: Bypass cache and regenerate from Claude.

        Returns:
            dict with keys: events, source_id, technique_id, count,
            cache_hit, benign_count, attack_count.
        """
        schema = self._registry.get(source_id)
        if not schema:
            available = self._registry.list_ids()
            return {
                "error": f"Unknown source_id '{source_id}'. Available: {available}",
                "events": [],
            }

        attack_count = max(1, round(count * snr_ratio))
        benign_count = count - attack_count

        # Generate attack events
        attack_events, attack_cache_hit = await self._get_attack_events(
            schema, technique_id, attack_count, force_refresh
        )

        # Generate benign noise if requested
        benign_events: list[dict[str, Any]] = []
        if benign_count > 0:
            benign_events, _ = await self._get_benign_events(
                schema, benign_count, force_refresh
            )

        # Merge + shuffle
        all_events = attack_events + benign_events
        random.shuffle(all_events)

        return {
            "status": "success",
            "source_id": source_id,
            "technique_id": technique_id,
            "count": len(all_events),
            "attack_count": len(attack_events),
            "benign_count": len(benign_events),
            "snr_ratio": snr_ratio,
            "cache_hit": attack_cache_hit,
            "events": all_events,
        }

    async def generate_benign(
        self,
        source_id: str,
        count: int = 10,
        force_refresh: bool = False,
    ) -> dict[str, Any]:
        """Generate purely benign/noise events for a source."""
        schema = self._registry.get(source_id)
        if not schema:
            return {"error": f"Unknown source_id '{source_id}'", "events": []}

        events, cache_hit = await self._get_benign_events(schema, count, force_refresh)
        return {
            "status": "success",
            "source_id": source_id,
            "count": len(events),
            "cache_hit": cache_hit,
            "events": events,
        }

    async def invalidate_source(self, source_id: str) -> int:
        """Flush all cached templates for a source (call after schema update)."""
        count = await _cache.flush_source(source_id)
        logger.info("Invalidated %d cached templates for '%s'", count, source_id)
        return count

    async def list_sources(self) -> list[dict[str, Any]]:
        """Return all registered sources with metadata."""
        return [
            {
                "source_id": s.source_id,
                "vendor": s.vendor,
                "product": s.product,
                "category": s.category,
                "version": s.version,
                "mitre_techniques": list(s.mitre_mappings.keys()),
                "joti_source_type": s.joti_source_type,
                "format": s.format,
                "update_frequency": s.update_frequency,
            }
            for s in self._registry.list_all()
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _attack_cache_key(
        self, source_id: str, version: str, technique_id: str
    ) -> str:
        return f"log_template:{source_id}:{version}:{technique_id}"

    def _benign_cache_key(self, source_id: str, version: str) -> str:
        return f"log_template:{source_id}:{version}:__benign__"

    async def _get_attack_events(
        self,
        schema: Any,
        technique_id: str,
        count: int,
        force_refresh: bool,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return attack events, using/populating the template cache."""
        cache_key = self._attack_cache_key(
            schema.source_id, schema.version, technique_id
        )
        templates = None
        cache_hit = False

        if not force_refresh:
            templates = await _cache.get(cache_key)
            if templates:
                cache_hit = True
                logger.debug(
                    "Cache hit for %s / %s", schema.source_id, technique_id
                )

        if not templates:
            # Need to fetch from MITRE to get technique name
            technique_name = await _lookup_technique_name(technique_id)
            schema_text = self._registry.get_schema_text(schema.source_id)

            prompt = _GENERATION_PROMPT.format(
                schema_text=schema_text,
                count=self.TEMPLATE_BATCH_SIZE,
                technique_id=technique_id,
                technique_name=technique_name,
            )
            templates = await _call_claude_for_templates(prompt)

            if not templates:
                logger.warning(
                    "Claude returned no templates for %s / %s — using schema samples",
                    schema.source_id, technique_id,
                )
                templates = _fallback_templates(schema, technique_id)

            # Tag all attack templates
            for t in templates:
                t["_purplelab_technique"] = technique_id
                t["_purplelab_source"] = schema.source_id
                t["_purplelab_is_attack"] = True

            await _cache.set(cache_key, templates, ttl=self.TEMPLATE_CACHE_TTL)
            logger.info(
                "Cached %d attack templates for %s / %s",
                len(templates), schema.source_id, technique_id,
            )

        return _render_n(templates, count), cache_hit

    async def _get_benign_events(
        self,
        schema: Any,
        count: int,
        force_refresh: bool,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return benign events, using/populating the noise template cache."""
        cache_key = self._benign_cache_key(schema.source_id, schema.version)
        templates = None
        cache_hit = False

        if not force_refresh:
            templates = await _cache.get(cache_key)
            if templates:
                cache_hit = True

        if not templates:
            schema_text = self._registry.get_schema_text(schema.source_id)
            prompt = _BENIGN_PROMPT.format(
                schema_text=schema_text,
                count=self.TEMPLATE_BATCH_SIZE,
            )
            templates = await _call_claude_for_templates(prompt)

            if not templates:
                templates = _fallback_benign_templates(schema)

            for t in templates:
                t["_purplelab_source"] = schema.source_id
                t["_purplelab_is_attack"] = False

            await _cache.set(cache_key, templates, ttl=self.TEMPLATE_CACHE_TTL)

        return _render_n(templates, count), cache_hit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _render_n(
    templates: list[dict[str, Any]], count: int
) -> list[dict[str, Any]]:
    """Render ``count`` events from a template list (repeating if needed)."""
    if not templates:
        return []
    base_time = datetime.now(timezone.utc)
    events = []
    for i in range(count):
        tpl = templates[i % len(templates)]
        events.append(_render_template(tpl, base_time - timedelta(seconds=i * 3)))
    return events


def _fallback_templates(schema: Any, technique_id: str) -> list[dict[str, Any]]:
    """Return sample events from the schema as emergency fallback templates."""
    events = []
    relevant_event_types = schema.mitre_mappings.get(technique_id, [])
    for et in relevant_event_types:
        samples = schema.sample_events.get(et, [])
        for s in samples:
            e = dict(s)
            e["_purplelab_fallback"] = True
            events.append(e)
    if not events:
        # Grab first available sample
        for samples in schema.sample_events.values():
            if samples:
                e = dict(samples[0])
                e["_purplelab_fallback"] = True
                events.append(e)
                break
    return events or [{"_purplelab_fallback": True, "source": schema.source_id}]


def _fallback_benign_templates(schema: Any) -> list[dict[str, Any]]:
    """Return all sample events as benign fallbacks."""
    events = []
    for samples in schema.sample_events.values():
        for s in samples:
            e = dict(s)
            e["_purplelab_fallback"] = True
            events.append(e)
    return events or [{"_purplelab_fallback": True, "source": schema.source_id}]


# MITRE technique names — small local cache
_TECHNIQUE_NAMES: dict[str, str] = {
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1136": "Create Account",
    "T1543.003": "Windows Service",
    "T1190": "Exploit Public-Facing Application",
    "T1071.001": "Web Protocols",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1566.001": "Spearphishing Attachment",
    "T1087": "Account Discovery",
    "T1098": "Account Manipulation",
    "T1218.011": "Rundll32",
    "T1055": "Process Injection",
    "T1547.001": "Registry Run Keys",
    "T1562.001": "Disable or Modify Tools",
    "T1003.001": "LSASS Memory",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1613": "Container and Resource Discovery",
    "T1552.007": "Container API",
    "T1611": "Escape to Host",
    "T1610": "Deploy Container",
}


async def _lookup_technique_name(technique_id: str) -> str:
    """Return a human-readable technique name (local lookup first)."""
    return _TECHNIQUE_NAMES.get(technique_id, technique_id)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_generator: AgenticLogGenerator | None = None


def get_generator() -> AgenticLogGenerator:
    global _generator
    if _generator is None:
        _generator = AgenticLogGenerator()
    return _generator
