"""Threat research orchestrator — purple team simulation planning.

Coordinates MITRE ATT&CK lookups, web search, and the knowledge base to
produce research reports on threat actors and techniques, and to suggest
use case scenarios for purple team simulation.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from backend.knowledge.store import KnowledgeStore
from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.web_search import WebSearchSource

logger = logging.getLogger(__name__)

_NAMESPACE = "research_notes"

# Log source IDs known to the platform — used to map MITRE data sources
_KNOWN_LOG_SOURCES = [
    "windows_security",
    "windows_sysmon",
    "linux_auditd",
    "aws_cloudtrail",
    "aws_guardduty",
    "gcp_audit",
    "azure_activity",
    "palo_alto_panos",
    "kubernetes_audit",
    "dns",
    "cloudflare",
    "wiz",
]

# Mapping from MITRE data source names → platform log source IDs
_MITRE_TO_LOG_SOURCE: dict[str, str] = {
    "windows registry": "windows_security",
    "windows event logs": "windows_security",
    "process creation": "windows_sysmon",
    "process monitoring": "windows_sysmon",
    "file monitoring": "windows_sysmon",
    "network traffic": "palo_alto_panos",
    "dns records": "dns",
    "dns resolution": "dns",
    "cloud logs": "aws_cloudtrail",
    "aws cloudtrail": "aws_cloudtrail",
    "gcp audit logs": "gcp_audit",
    "azure activity log": "azure_activity",
    "kubernetes audit logs": "kubernetes_audit",
    "linux audit": "linux_auditd",
    "auditd": "linux_auditd",
}


class ThreatResearcher:
    """Orchestrates threat research for purple team simulation planning.

    Typical flow for any research request:
    1. Check knowledge base cache
    2. Query MITRE ATT&CK structured data
    3. Search the web for recent reports
    4. Synthesise findings with LLM
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

    @classmethod
    def from_settings(
        cls,
        knowledge: KnowledgeStore | None = None,
        mitre_source: MITREAttackSource | None = None,
        web_source: WebSearchSource | None = None,
    ) -> "ThreatResearcher":
        """Construct a ThreatResearcher from application settings."""
        return cls(
            mitre_source=mitre_source,
            web_source=web_source,
            knowledge=knowledge,
        )

    # ------------------------------------------------------------------
    # Threat actor research
    # ------------------------------------------------------------------

    async def research_threat_actor(self, actor_name: str) -> dict[str, Any]:
        """Research a threat actor's TTPs, tools, and techniques for simulation planning.

        Queries MITRE ATT&CK for structured group data, augments with web
        search results, then uses the LLM to produce simulation recommendations.

        Args:
            actor_name: Threat actor name or alias (e.g. "APT29", "Cozy Bear").

        Returns:
            dict with keys: name, aliases, description, techniques, tools,
            targeted_sectors, attack_patterns, simulation_recommendations.
        """
        cache_key = f"threat-actor-{_slug(actor_name)}"

        if self.knowledge:
            cached = await self.knowledge.get_knowledge(_NAMESPACE, cache_key)
            if cached:
                logger.info("Cache hit for threat actor: %s", actor_name)
                return {"name": actor_name, "cached": True, **self._parse_cached(cached)}

        findings: dict[str, Any] = {
            "name": actor_name,
            "cached": False,
            "aliases": [],
            "description": "",
            "techniques": [],
            "tools": [],
            "targeted_sectors": [],
            "attack_patterns": [],
            "simulation_recommendations": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # MITRE ATT&CK group lookup
        mitre_group: dict[str, Any] | None = None
        try:
            all_groups = await self.mitre.get_groups()
            actor_lower = actor_name.lower()
            for g in all_groups:
                names = [g["name"].lower()] + [a.lower() for a in g.get("aliases", [])]
                if actor_lower in names or any(actor_lower in n for n in names):
                    mitre_group = g
                    findings["aliases"] = g.get("aliases", [])
                    findings["description"] = g.get("description", "")

                    techniques_raw = await self.mitre.get_techniques_for_group(g["group_id"])
                    findings["techniques"] = [
                        {
                            "id": t["technique_id"],
                            "name": t["name"],
                            "tactic": t.get("tactics", ["unknown"])[0] if t.get("tactics") else "unknown",
                        }
                        for t in techniques_raw
                    ]

                    # Extract tools from group data if available
                    if g.get("software"):
                        findings["tools"] = [s.get("name", "") for s in g["software"] if s.get("name")]

                    break
        except Exception as exc:
            logger.warning("MITRE actor lookup failed: %s", exc)

        # Web search for additional context
        web_snippets: list[str] = []
        try:
            results = await self.web.search(
                f'"{actor_name}" threat actor APT techniques targeted sectors', max_results=5
            )
            for r in results or []:
                snippet = r.get("snippet") or r.get("body") or r.get("description") or ""
                if snippet:
                    web_snippets.append(snippet[:500])
        except Exception as exc:
            logger.warning("Web search failed for actor %s: %s", actor_name, exc)

        # LLM synthesis for simulation recommendations
        try:
            llm_result = await self._llm_synthesise_actor(
                actor_name, findings, web_snippets
            )
            if llm_result:
                findings["targeted_sectors"] = llm_result.get("targeted_sectors", [])
                findings["attack_patterns"] = llm_result.get("attack_patterns", [])
                findings["simulation_recommendations"] = llm_result.get(
                    "simulation_recommendations", []
                )
        except Exception as exc:
            logger.warning("LLM actor synthesis failed: %s", exc)
            # Derive basic recommendations from techniques without LLM
            findings["simulation_recommendations"] = _derive_basic_recommendations(
                findings["techniques"]
            )

        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "threat_actor_research", "actor_name": actor_name},
            )

        return findings

    async def _llm_synthesise_actor(
        self,
        actor_name: str,
        findings: dict[str, Any],
        web_snippets: list[str],
    ) -> dict[str, Any] | None:
        """Use LLM to produce structured simulation planning output for a threat actor."""
        try:
            from backend.llm.config import LLMFunction
            from backend.llm.router import get_router
        except ImportError:
            return None

        router = get_router()

        techniques_summary = ", ".join(
            f"{t['id']} ({t['name']})" for t in findings["techniques"][:20]
        )
        web_context = "\n".join(f"- {s}" for s in web_snippets[:3])

        prompt = (
            f"Threat actor: {actor_name}\n"
            f"Aliases: {', '.join(findings['aliases']) or 'none known'}\n"
            f"Description: {findings['description'][:400] or 'none available'}\n"
            f"Known MITRE techniques: {techniques_summary or 'none mapped'}\n"
            f"Web intelligence:\n{web_context or '(none)'}\n\n"
            "Produce a JSON object with these keys:\n"
            "  targeted_sectors: list of strings (industries/sectors this actor targets)\n"
            "  attack_patterns: list of strings (characteristic attack patterns/behaviors)\n"
            "  simulation_recommendations: list of strings (specific simulation scenarios "
            "     a purple team should prioritise to test detection for this actor)\n"
            "Be specific and actionable. Output valid JSON only, no markdown fences."
        )

        try:
            raw = await router.complete(
                function=LLMFunction.THREAT_INTEL,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are a senior purple team analyst helping to plan detection validation "
                    "simulations. Respond only with the requested JSON object."
                ),
                max_tokens=1024,
                temperature=0.2,
            )
            if raw:
                import json
                return json.loads(raw.strip())
        except Exception as exc:
            logger.debug("LLM actor synthesis completion failed: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Technique research
    # ------------------------------------------------------------------

    async def research_technique(self, technique_id: str) -> dict[str, Any]:
        """Deep dive on a MITRE technique for simulation planning.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g. "T1059.001").

        Returns:
            dict with keys: id, name, tactic, description, log_sources_needed,
            detection_opportunities, typical_commands, simulation_notes.
        """
        cache_key = f"technique-sim-{technique_id.upper()}"

        if self.knowledge:
            cached = await self.knowledge.get_knowledge(_NAMESPACE, cache_key)
            if cached:
                logger.info("Cache hit for technique: %s", technique_id)
                return {"id": technique_id, "cached": True, **self._parse_cached(cached)}

        findings: dict[str, Any] = {
            "id": technique_id,
            "cached": False,
            "name": "",
            "tactic": "",
            "description": "",
            "log_sources_needed": [],
            "detection_opportunities": [],
            "typical_commands": [],
            "simulation_notes": "",
            "used_by_groups": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # MITRE technique details
        mitre_tech: dict[str, Any] | None = None
        try:
            all_techniques = await self.mitre.get_all_techniques()
            for t in all_techniques:
                if t["technique_id"].upper() == technique_id.upper():
                    mitre_tech = t
                    findings["name"] = t.get("name", "")
                    findings["tactic"] = (
                        t.get("tactics", ["unknown"])[0] if t.get("tactics") else "unknown"
                    )
                    findings["description"] = t.get("description", "")[:600]

                    # Map MITRE data sources → platform log source IDs
                    mitre_sources = t.get("data_sources") or []
                    if isinstance(mitre_sources, list):
                        mapped: list[str] = []
                        for ds in mitre_sources:
                            ds_lower = ds.lower()
                            mapped_id = _MITRE_TO_LOG_SOURCE.get(ds_lower)
                            if mapped_id and mapped_id not in mapped:
                                mapped.append(mapped_id)
                        findings["log_sources_needed"] = mapped or ["windows_sysmon"]
                    break

            # Find groups that use this technique for context
            if mitre_tech:
                stix_id = mitre_tech.get("stix_id", "")
                if stix_id and hasattr(self.mitre, "relationships"):
                    all_groups = await self.mitre.get_groups()
                    for rel in self.mitre.relationships:
                        if (
                            rel.get("target_ref") == stix_id
                            and rel.get("relationship_type") == "uses"
                        ):
                            source_ref = rel["source_ref"]
                            for g in all_groups:
                                if g.get("stix_id") == source_ref:
                                    findings["used_by_groups"].append(g["name"])
                                    break
        except Exception as exc:
            logger.warning("MITRE technique lookup failed for %s: %s", technique_id, exc)

        # Web search for detection guidance
        tech_name = findings.get("name", "")
        web_snippets: list[str] = []
        try:
            results = await self.web.search(
                f"MITRE {technique_id} {tech_name} detection simulation commands",
                max_results=5,
            )
            for r in results or []:
                snippet = r.get("snippet") or r.get("body") or r.get("description") or ""
                if snippet:
                    web_snippets.append(snippet[:500])
        except Exception as exc:
            logger.warning("Web search failed for technique %s: %s", technique_id, exc)

        # LLM synthesis
        try:
            llm_result = await self._llm_synthesise_technique(findings, web_snippets)
            if llm_result:
                findings["detection_opportunities"] = llm_result.get(
                    "detection_opportunities", []
                )
                findings["typical_commands"] = llm_result.get("typical_commands", [])
                findings["simulation_notes"] = llm_result.get("simulation_notes", "")
                if llm_result.get("log_sources_needed") and not findings["log_sources_needed"]:
                    findings["log_sources_needed"] = llm_result["log_sources_needed"]
        except Exception as exc:
            logger.warning("LLM technique synthesis failed: %s", exc)

        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "technique_research", "technique_id": technique_id},
            )

        return findings

    async def _llm_synthesise_technique(
        self,
        findings: dict[str, Any],
        web_snippets: list[str],
    ) -> dict[str, Any] | None:
        """Use LLM to enrich technique research with simulation-focused detail."""
        try:
            from backend.llm.config import LLMFunction
            from backend.llm.router import get_router
        except ImportError:
            return None

        router = get_router()

        web_context = "\n".join(f"- {s}" for s in web_snippets[:3])
        known_sources = ", ".join(findings.get("log_sources_needed", []))
        used_by = ", ".join(findings.get("used_by_groups", [])[:5]) or "unknown"

        prompt = (
            f"MITRE Technique: {findings['id']} — {findings['name']}\n"
            f"Tactic: {findings['tactic']}\n"
            f"Description: {findings['description'][:400]}\n"
            f"Used by threat actors: {used_by}\n"
            f"Known log sources: {known_sources or 'not mapped'}\n"
            f"Web context:\n{web_context or '(none)'}\n\n"
            "Produce a JSON object with these keys:\n"
            "  log_sources_needed: list of platform log source IDs from "
            f"    {_KNOWN_LOG_SOURCES} that would capture this technique\n"
            "  detection_opportunities: list of strings describing specific "
            "     detection logic opportunities (what to look for in logs)\n"
            "  typical_commands: list of example commands/tools an attacker "
            "     would use when executing this technique\n"
            "  simulation_notes: string — notes for a purple teamer simulating "
            "     this technique (setup requirements, prerequisites, expected artifacts)\n"
            "Output valid JSON only, no markdown fences."
        )

        try:
            raw = await router.complete(
                function=LLMFunction.THREAT_INTEL,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are a senior purple team engineer with deep expertise in "
                    "MITRE ATT&CK simulation and detection engineering. "
                    "Respond only with the requested JSON object."
                ),
                max_tokens=1024,
                temperature=0.2,
            )
            if raw:
                import json
                return json.loads(raw.strip())
        except Exception as exc:
            logger.debug("LLM technique synthesis completion failed: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Use case suggestion
    # ------------------------------------------------------------------

    async def suggest_use_cases(self, technique_ids: list[str]) -> list[dict[str, Any]]:
        """Given a list of technique IDs, suggest use case scenarios to simulate.

        Looks up each technique in MITRE ATT&CK, then uses the LLM to generate
        specific, actionable simulation scenarios with expected log sources and
        detection approaches.

        Args:
            technique_ids: List of MITRE ATT&CK technique IDs.

        Returns:
            List of dicts, each with keys: name, technique_id, description,
            expected_logs, detection_approach.
        """
        if not technique_ids:
            return []

        suggestions: list[dict[str, Any]] = []

        # Load MITRE technique details for context
        technique_details: dict[str, dict[str, Any]] = {}
        try:
            all_techniques = await self.mitre.get_all_techniques()
            tech_map = {t["technique_id"].upper(): t for t in all_techniques}
            for tid in technique_ids:
                if tid.upper() in tech_map:
                    technique_details[tid] = tech_map[tid.upper()]
        except Exception as exc:
            logger.warning("MITRE technique bulk lookup failed: %s", exc)

        # LLM-based suggestion generation
        try:
            suggestions = await self._llm_suggest_use_cases(technique_ids, technique_details)
        except Exception as exc:
            logger.warning("LLM use case suggestion failed: %s", exc)

        # Fallback: generate basic suggestions from technique metadata
        if not suggestions:
            for tid in technique_ids:
                tech = technique_details.get(tid, {})
                name = tech.get("name", tid)
                tactics = tech.get("tactics", ["unknown"])
                tactic = tactics[0] if tactics else "unknown"
                suggestions.append({
                    "name": f"Simulate {name}",
                    "technique_id": tid,
                    "description": (
                        tech.get("description", f"Simulation of {tid} — {name}.")[:300]
                    ),
                    "expected_logs": _derive_log_sources(tech),
                    "detection_approach": (
                        f"Monitor for indicators of {name} in {tactic} phase. "
                        "Review process creation, network traffic, and system event logs."
                    ),
                })

        return suggestions

    async def _llm_suggest_use_cases(
        self,
        technique_ids: list[str],
        technique_details: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Use LLM to generate structured use case suggestions."""
        try:
            from backend.llm.config import LLMFunction
            from backend.llm.router import get_router
        except ImportError:
            return []

        router = get_router()

        tech_summaries: list[str] = []
        for tid in technique_ids:
            td = technique_details.get(tid, {})
            name = td.get("name", "Unknown")
            tactics = td.get("tactics", [])
            tactic = tactics[0] if tactics else "unknown"
            tech_summaries.append(f"  - {tid}: {name} (tactic: {tactic})")

        prompt = (
            "Generate simulation use cases for these MITRE ATT&CK techniques:\n"
            + "\n".join(tech_summaries)
            + "\n\nFor each technique, produce a JSON object with:\n"
            "  name: concise use case name (e.g. 'Mimikatz LSASS Dump')\n"
            "  technique_id: the technique ID\n"
            "  description: 1-2 sentence scenario description for a purple teamer\n"
            f"  expected_logs: list of log source IDs from {_KNOWN_LOG_SOURCES} "
            "     that would capture this technique\n"
            "  detection_approach: 1-2 sentences on what detection rule should fire\n"
            "Return a JSON array of these objects. Output valid JSON only, no markdown."
        )

        try:
            raw = await router.complete(
                function=LLMFunction.THREAT_INTEL,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are a senior purple team engineer. Generate practical, "
                    "specific use case scenarios for detection validation testing. "
                    "Respond only with the requested JSON array."
                ),
                max_tokens=2048,
                temperature=0.3,
            )
            if raw:
                import json
                result = json.loads(raw.strip())
                if isinstance(result, list):
                    return result
        except Exception as exc:
            logger.debug("LLM use case suggestion failed: %s", exc)

        return []

    # ------------------------------------------------------------------
    # Generic topic research (retained for agent tool use)
    # ------------------------------------------------------------------

    async def research_topic(self, query: str) -> dict[str, Any]:
        """Research an arbitrary threat intel topic relevant to simulation planning."""
        cache_key = f"research-topic-{_slug(query)}"

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

        try:
            web_results = await self.web.search(f"{query} threat intelligence", max_results=5)
            findings["web_results"] = web_results
        except Exception as exc:
            logger.warning("Web search failed: %s", exc)

        if self.knowledge:
            import json
            content = json.dumps(findings, default=str)
            await self.knowledge.store_knowledge(
                _NAMESPACE, cache_key, content,
                metadata={"type": "topic_research", "query": query},
            )

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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    """Create a cache-key-safe slug."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


def _derive_log_sources(tech: dict[str, Any]) -> list[str]:
    """Derive platform log source IDs from MITRE technique data sources."""
    mitre_sources = tech.get("data_sources") or []
    if not isinstance(mitre_sources, list):
        return ["windows_sysmon"]

    mapped: list[str] = []
    for ds in mitre_sources:
        ds_lower = ds.lower()
        mapped_id = _MITRE_TO_LOG_SOURCE.get(ds_lower)
        if mapped_id and mapped_id not in mapped:
            mapped.append(mapped_id)

    return mapped or ["windows_sysmon"]


def _derive_basic_recommendations(techniques: list[dict[str, Any]]) -> list[str]:
    """Derive basic simulation recommendations from technique list without LLM."""
    tactic_counts: dict[str, int] = {}
    for t in techniques:
        tactic = t.get("tactic", "unknown")
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    recs: list[str] = []
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1])[:5]:
        recs.append(
            f"Simulate {tactic} phase techniques ({count} known TTPs) — "
            "ensure detection rules cover this tactic."
        )

    if not recs:
        recs.append(
            "Research this threat actor further to identify priority simulation scenarios."
        )

    return recs
