"""Threat research orchestrator — aggregates data from multiple intelligence sources.

Coordinates MITRE ATT&CK lookups, web search, and the knowledge base
to produce comprehensive research reports on threats, actors, and techniques.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from backend.knowledge.store import KnowledgeStore
from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.web_search import WebSearchSource

logger = logging.getLogger(__name__)

_NAMESPACE = "research_notes"


class ThreatResearcher:
    """Orchestrates threat intelligence gathering from multiple sources.

    Typical flow for any research request:
    1. Check knowledge base cache
    2. Query MITRE ATT&CK structured data
    3. Search the web for recent reports
    4. Synthesise findings
    5. Cache results in knowledge base
    """

    def __init__(
        self,
        mitre_source: MITREAttackSource | None = None,
        web_source: WebSearchSource | None = None,
        knowledge: KnowledgeStore | None = None,
    ) -> None:
        self.mitre = mitre_source or MITREAttackSource()
        self.web = web_source or WebSearchSource()
        self.knowledge = knowledge

    # ------------------------------------------------------------------
    # Generic topic research
    # ------------------------------------------------------------------

    async def research_topic(self, query: str) -> dict[str, Any]:
        """Research an arbitrary threat intel topic."""
        cache_key = f"research-topic-{_slug(query)}"

        # 1. Check cache
        if self.knowledge:
            cached = await self.knowledge.get_knowledge(_NAMESPACE, cache_key)
            if cached:
                logger.info("Cache hit for research topic: %s", query)
                return {"query": query, "cached": True, **self._parse_cached(cached)}

        findings: dict[str, Any] = {
            "query": query,
            "cached": False,
            "mitre_techniques": [],
            "mitre_groups": [],
            "web_results": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # 2. Search MITRE techniques
        try:
            all_techniques = await self.mitre.get_all_techniques()
            query_lower = query.lower()
            findings["mitre_techniques"] = [
                {
                    "technique_id": t["technique_id"],
                    "name": t["name"],
                    "tactics": t.get("tactics", []),
                    "description": t.get("description", "")[:300],
                }
                for t in all_techniques
                if query_lower in f"{t['technique_id']} {t['name']} {t.get('description', '')}".lower()
            ][:10]
        except Exception as exc:
            logger.warning("MITRE technique search failed: %s", exc)

        # Search MITRE groups
        try:
            all_groups = await self.mitre.get_groups()
            query_lower = query.lower()
            findings["mitre_groups"] = [
                {
                    "group_id": g["group_id"],
                    "name": g["name"],
                    "aliases": g.get("aliases", []),
                    "description": g.get("description", "")[:300],
                }
                for g in all_groups
                if query_lower in f"{g['name']} {' '.join(g.get('aliases', []))} {g.get('description', '')}".lower()
            ][:5]
        except Exception as exc:
            logger.warning("MITRE group search failed: %s", exc)

        # 3. Web search
        try:
            web_results = await self.web.search(f"{query} threat intelligence", max_results=5)
            findings["web_results"] = web_results
        except Exception as exc:
            logger.warning("Web search failed: %s", exc)

        # 4 & 5. Cache
        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "topic_research", "query": query},
            )

        return findings

    # ------------------------------------------------------------------
    # Actor research
    # ------------------------------------------------------------------

    async def research_actor(self, actor_name: str) -> dict[str, Any]:
        """Deep research on a specific threat actor."""
        cache_key = f"research-actor-{_slug(actor_name)}"

        # 1. Check cache
        if self.knowledge:
            cached = await self.knowledge.get_knowledge(_NAMESPACE, cache_key)
            if cached:
                return {"actor_name": actor_name, "cached": True, **self._parse_cached(cached)}

        findings: dict[str, Any] = {
            "actor_name": actor_name,
            "cached": False,
            "mitre_group": None,
            "techniques": [],
            "web_results": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # 2. MITRE groups
        try:
            all_groups = await self.mitre.get_groups()
            actor_lower = actor_name.lower()
            for g in all_groups:
                names = [g["name"].lower()] + [a.lower() for a in g.get("aliases", [])]
                if actor_lower in names:
                    findings["mitre_group"] = g

                    # Get techniques
                    techniques = await self.mitre.get_techniques_for_group(g["group_id"])
                    findings["techniques"] = [
                        {
                            "technique_id": t["technique_id"],
                            "name": t["name"],
                            "tactics": t.get("tactics", []),
                            "description": t.get("description", "")[:300],
                        }
                        for t in techniques
                    ]
                    break
        except Exception as exc:
            logger.warning("MITRE actor search failed: %s", exc)

        # 3. Web search
        try:
            web_results = await self.web.search(
                f'"{actor_name}" threat actor APT cyber', max_results=5
            )
            findings["web_results"] = web_results
        except Exception as exc:
            logger.warning("Web search failed: %s", exc)

        # 5. Cache
        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "actor_research", "actor_name": actor_name},
            )

        return findings

    # ------------------------------------------------------------------
    # Technique research
    # ------------------------------------------------------------------

    async def research_technique(self, technique_id: str) -> dict[str, Any]:
        """Deep research on a specific MITRE ATT&CK technique."""
        cache_key = f"research-technique-{technique_id}"

        # 1. Check cache
        if self.knowledge:
            cached = await self.knowledge.get_knowledge(_NAMESPACE, cache_key)
            if cached:
                return {"technique_id": technique_id, "cached": True, **self._parse_cached(cached)}

        findings: dict[str, Any] = {
            "technique_id": technique_id,
            "cached": False,
            "technique": None,
            "used_by_groups": [],
            "web_results": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # 2. MITRE technique details
        try:
            all_techniques = await self.mitre.get_all_techniques()
            for t in all_techniques:
                if t["technique_id"].upper() == technique_id.upper():
                    findings["technique"] = t
                    break

            # Find groups that use this technique
            if findings["technique"]:
                stix_id = findings["technique"].get("stix_id", "")
                if stix_id:
                    all_groups = await self.mitre.get_groups()
                    # Check relationships
                    for rel in self.mitre.relationships:
                        if (
                            rel.get("target_ref") == stix_id
                            and rel.get("relationship_type") == "uses"
                        ):
                            source_ref = rel["source_ref"]
                            for g in all_groups:
                                if g.get("stix_id") == source_ref:
                                    findings["used_by_groups"].append({
                                        "group_id": g["group_id"],
                                        "name": g["name"],
                                    })
                                    break
        except Exception as exc:
            logger.warning("MITRE technique lookup failed: %s", exc)

        # 3. Web search
        try:
            tech_name = ""
            if findings["technique"]:
                tech_name = findings["technique"].get("name", "")
            web_results = await self.web.search(
                f"MITRE {technique_id} {tech_name} detection", max_results=5
            )
            findings["web_results"] = web_results
        except Exception as exc:
            logger.warning("Web search failed: %s", exc)

        # 5. Cache
        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "technique_research", "technique_id": technique_id},
            )

        return findings

    # ------------------------------------------------------------------
    # IOC research (stub for future expansion)
    # ------------------------------------------------------------------

    async def research_ioc(self, ioc: str, ioc_type: str = "auto") -> dict[str, Any]:
        """Research an indicator of compromise.

        Currently supports web search only. Future: integrate VirusTotal,
        OTX, and abuse.ch connectors.
        """
        findings: dict[str, Any] = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "web_results": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            web_results = await self.web.search(f'"{ioc}" malware threat', max_results=5)
            findings["web_results"] = web_results
        except Exception as exc:
            logger.warning("IOC web search failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_cached(entry: dict[str, Any]) -> dict[str, Any]:
        """Parse a cached knowledge entry back into a findings dict."""
        import json

        text = entry.get("text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return {"text": text, "metadata": entry.get("metadata", {})}


def _slug(text: str) -> str:
    """Create a cache-key-safe slug."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]
