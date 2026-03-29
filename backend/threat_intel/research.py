"""Threat research orchestrator — aggregates data from multiple intelligence sources.

Coordinates MITRE ATT&CK lookups, web search, the knowledge base, and external
threat intelligence APIs (VirusTotal, OTX, abuse.ch) to produce comprehensive
research reports on threats, actors, techniques, and IOCs.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any

from backend.knowledge.store import KnowledgeStore
from backend.threat_intel.sources.abusech import AbuseEHSource
from backend.threat_intel.sources.mitre_attack import MITREAttackSource
from backend.threat_intel.sources.otx import OTXSource
from backend.threat_intel.sources.virustotal import VirusTotalSource
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

    For IOC research the flow is extended with parallel queries to
    VirusTotal, OTX, and abuse.ch, followed by LLM-assisted enrichment.
    """

    def __init__(
        self,
        mitre_source: MITREAttackSource | None = None,
        web_source: WebSearchSource | None = None,
        knowledge: KnowledgeStore | None = None,
        virustotal: VirusTotalSource | None = None,
        otx: OTXSource | None = None,
        abusech: AbuseEHSource | None = None,
    ) -> None:
        self.mitre = mitre_source or MITREAttackSource()
        self.web = web_source or WebSearchSource()
        self.knowledge = knowledge
        self.virustotal = virustotal
        self.otx = otx
        self.abusech = abusech or AbuseEHSource()

    @classmethod
    def from_settings(
        cls,
        knowledge: KnowledgeStore | None = None,
        mitre_source: MITREAttackSource | None = None,
        web_source: WebSearchSource | None = None,
    ) -> "ThreatResearcher":
        """Construct a ThreatResearcher from application settings."""
        try:
            from backend.config import settings
            from backend.threat_intel.sources import get_threat_intel_sources
            sources = get_threat_intel_sources(settings)
        except Exception as exc:
            logger.warning("Could not load threat intel sources from settings: %s", exc)
            sources = {}

        return cls(
            mitre_source=mitre_source,
            web_source=web_source,
            knowledge=knowledge,
            virustotal=sources.get("virustotal"),
            otx=sources.get("otx"),
            abusech=sources.get("abusech"),
        )

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
    # IOC research — parallel multi-source enrichment
    # ------------------------------------------------------------------

    async def research_ioc(self, ioc: str, ioc_type: str = "auto") -> dict[str, Any]:
        """Research an indicator of compromise across all available sources.

        Flow:
        1. Auto-detect IOC type if ``ioc_type="auto"``
        2. Parallel query: VirusTotal + OTX + abuse.ch + web search
        3. Aggregate results and compute reputation verdict
        4. LLM-assisted enrichment summary (if LLM router available)
        5. Return structured IOC report

        Returns:
            dict with keys:
                ioc, ioc_type, sources, reputation, threat_actors,
                mitre_techniques, verdict, web_results, researched_at
        """
        if ioc_type == "auto":
            ioc_type = _detect_ioc_type(ioc)

        logger.info("Researching IOC: %s (type=%s)", ioc, ioc_type)

        findings: dict[str, Any] = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "sources": {},
            "reputation": 0,
            "threat_actors": [],
            "mitre_techniques": [],
            "tags": [],
            "verdict": "unknown",
            "web_results": [],
            "researched_at": datetime.now(timezone.utc).isoformat(),
        }

        # -- Parallel queries -----------------------------------------------
        tasks: dict[str, Any] = {}

        # VirusTotal
        if self.virustotal:
            if ioc_type == "ip":
                tasks["virustotal"] = self.virustotal.lookup_ip(ioc)
            elif ioc_type == "domain":
                tasks["virustotal"] = self.virustotal.lookup_domain(ioc)
            elif ioc_type == "hash":
                tasks["virustotal"] = self.virustotal.lookup_hash(ioc)

        # OTX
        if self.otx:
            otx_type = _ioc_type_to_otx(ioc_type, ioc)
            if otx_type:
                tasks["otx"] = self.otx.get_indicator_details(otx_type, ioc)

        # AbuseEH
        if ioc_type == "url":
            tasks["urlhaus"] = self.abusech.lookup_url(ioc)
            tasks["threatfox"] = self.abusech.search_ioc(ioc)
        elif ioc_type in ("ip", "domain"):
            tasks["urlhaus"] = self.abusech.lookup_host(ioc)
            tasks["threatfox"] = self.abusech.search_ioc(ioc)
        elif ioc_type == "hash":
            tasks["malwarebazaar"] = self.abusech.lookup_hash(ioc)
            tasks["threatfox"] = self.abusech.search_ioc(ioc)

        # Web search (low priority, run in parallel)
        tasks["web"] = self.web.search(f'"{ioc}" malware threat indicator', max_results=5)

        # Execute all tasks concurrently
        results = await _gather_dict(tasks)

        # -- Aggregate -------------------------------------------------------
        source_results: dict[str, Any] = {}
        all_tags: set[str] = set()
        all_actors: set[str] = set()
        all_techniques: set[str] = set()
        malicious_signals: list[int] = []  # malicious vote counts per source

        for key, result in results.items():
            if key == "web":
                findings["web_results"] = result or []
                continue

            if not result:
                continue

            source_results[key] = result

            # Tags
            for t in result.get("tags") or []:
                if t:
                    all_tags.add(str(t))

            # Threat actors
            for actor in result.get("threat_actors") or []:
                if actor:
                    all_actors.add(str(actor))

            # MITRE techniques
            for tech in result.get("mitre_techniques") or []:
                if isinstance(tech, str) and tech:
                    all_techniques.add(tech)
                elif isinstance(tech, dict) and tech.get("technique_id"):
                    all_techniques.add(tech["technique_id"])

            # Reputation signals
            malicious_votes = result.get("malicious_votes", result.get("malicious_engine_count", 0))
            if isinstance(malicious_votes, int) and malicious_votes > 0:
                malicious_signals.append(malicious_votes)
            if result.get("confidence", 0) >= 80 and result.get("found"):
                malicious_signals.append(result["confidence"])

        # -- Verdict ---------------------------------------------------------
        verdict = _compute_verdict(source_results, malicious_signals)

        # Aggregate reputation: weighted average scaled to -100..100
        if malicious_signals:
            # More signals → higher confidence in malicious verdict
            avg_signal = sum(malicious_signals) / len(malicious_signals)
            findings["reputation"] = -min(int(avg_signal), 100)
        else:
            # Check if any source explicitly returned found=False (clean)
            all_found = [v.get("found") for v in source_results.values() if isinstance(v, dict)]
            if all_found and not any(all_found):
                findings["reputation"] = 0  # unknown / clean

        findings["sources"] = source_results
        findings["tags"] = sorted(all_tags)
        findings["threat_actors"] = sorted(all_actors)
        findings["mitre_techniques"] = sorted(all_techniques)
        findings["verdict"] = verdict

        # -- LLM enrichment --------------------------------------------------
        try:
            summary = await self._llm_enrich_ioc(findings)
            if summary:
                findings["llm_summary"] = summary
        except Exception as exc:
            logger.debug("LLM IOC enrichment skipped: %s", exc)

        logger.info(
            "IOC research complete: %s → verdict=%s sources=%s",
            ioc, verdict, list(source_results.keys()),
        )
        return findings

    async def _llm_enrich_ioc(self, findings: dict[str, Any]) -> str | None:
        """Use LLM to produce a concise natural-language IOC summary."""
        try:
            from backend.llm.config import LLMFunction
            from backend.llm.router import get_router
        except ImportError:
            return None

        router = get_router()

        ioc = findings["ioc"]
        ioc_type = findings["ioc_type"]
        verdict = findings["verdict"]
        actors = findings.get("threat_actors", [])
        techniques = findings.get("mitre_techniques", [])
        tags = findings.get("tags", [])[:10]

        # Build a concise source summary (avoid dumping entire raw JSON)
        source_snippets: list[str] = []
        for src_name, src_data in (findings.get("sources") or {}).items():
            if not isinstance(src_data, dict) or not src_data.get("found"):
                continue
            malicious = src_data.get("malicious_votes", src_data.get("malicious_engine_count", "n/a"))
            snippet = f"{src_name}: malicious={malicious}, confidence={src_data.get('confidence', 'n/a')}"
            if src_data.get("signature"):
                snippet += f", signature={src_data['signature']}"
            if src_data.get("threat"):
                snippet += f", threat={src_data['threat']}"
            source_snippets.append(snippet)

        prompt = (
            f"IOC: {ioc} (type: {ioc_type})\n"
            f"Verdict: {verdict}\n"
            f"Sources: {'; '.join(source_snippets) or 'none with findings'}\n"
            f"Threat actors: {', '.join(actors) or 'none identified'}\n"
            f"MITRE techniques: {', '.join(techniques) or 'none'}\n"
            f"Tags: {', '.join(tags) or 'none'}\n\n"
            "Write a concise 2-4 sentence threat intelligence summary for a SOC analyst. "
            "Include: what is known about this IOC, associated threat actors or malware families, "
            "and recommended actions. Be factual and cite sources."
        )

        try:
            summary = await router.complete(
                function=LLMFunction.THREAT_INTEL,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are a senior threat intelligence analyst. "
                    "Provide concise, accurate IOC assessments based solely on the data provided. "
                    "Do not speculate beyond the evidence."
                ),
                max_tokens=512,
                temperature=0.1,
            )
            return summary.strip() if summary else None
        except Exception as exc:
            logger.debug("LLM completion failed for IOC enrichment: %s", exc)
            return None

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
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


# ---------------------------------------------------------------------------
# IOC type detection helpers
# ---------------------------------------------------------------------------

_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _detect_ioc_type(ioc: str) -> str:
    """Auto-detect the type of an IOC string.

    Returns one of: 'ip', 'domain', 'url', 'hash', 'cve', 'email', 'unknown'
    """
    ioc = ioc.strip()

    # URL check first (contains scheme)
    if ioc.lower().startswith(("http://", "https://", "ftp://")):
        return "url"

    # CVE
    if _CVE_RE.match(ioc):
        return "cve"

    # Email
    if "@" in ioc and "." in ioc.split("@")[-1]:
        return "email"

    # IP address (v4 or v6)
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # CIDR range
    try:
        ipaddress.ip_network(ioc, strict=False)
        return "ip"
    except ValueError:
        pass

    # File hash
    if _MD5_RE.match(ioc) or _SHA1_RE.match(ioc) or _SHA256_RE.match(ioc):
        return "hash"

    # Domain / hostname (rough heuristic: no slashes, has a dot)
    if "." in ioc and "/" not in ioc and " " not in ioc:
        return "domain"

    return "unknown"


def _ioc_type_to_otx(ioc_type: str, ioc: str) -> str | None:
    """Map a generic IOC type to the OTX indicator type string."""
    mapping = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "URL",
        "hash": "FileHash-SHA256" if _SHA256_RE.match(ioc) else (
            "FileHash-SHA1" if _SHA1_RE.match(ioc) else "FileHash-MD5"
        ),
        "cve": "CVE",
        "email": "email",
    }
    return mapping.get(ioc_type)


def _compute_verdict(
    source_results: dict[str, Any],
    malicious_signals: list[int],
) -> str:
    """Derive a verdict string from aggregated source data.

    Returns: 'malicious', 'suspicious', 'clean', or 'unknown'
    """
    if not source_results:
        return "unknown"

    # Count sources that flagged as malicious/found
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    for src_data in source_results.values():
        if not isinstance(src_data, dict):
            continue

        found = src_data.get("found", False)
        if not found:
            clean_count += 1
            continue

        malicious_votes = src_data.get("malicious_votes", src_data.get("malicious_engine_count", 0))
        confidence = src_data.get("confidence", 0)
        suspicious_votes = src_data.get("suspicious_votes", 0)

        if malicious_votes >= 5 or confidence >= 80:
            malicious_count += 1
        elif malicious_votes >= 1 or suspicious_votes >= 3 or confidence >= 50:
            suspicious_count += 1
        elif found:
            suspicious_count += 1  # Known to any TI source but not flagged = suspicious

    total = malicious_count + suspicious_count + clean_count
    if total == 0:
        return "unknown"

    if malicious_count >= 2:
        return "malicious"
    if malicious_count >= 1 or suspicious_count >= 2:
        return "suspicious"
    if clean_count == total:
        return "clean"
    return "unknown"


async def _gather_dict(tasks: dict[str, Any]) -> dict[str, Any]:
    """Run a dict of {name: coroutine} in parallel, return {name: result}.

    Individual task failures are caught and logged; their result is None.
    """
    if not tasks:
        return {}

    names = list(tasks.keys())
    coros = list(tasks.values())

    async def _safe(name: str, coro: Any) -> tuple[str, Any]:
        try:
            return name, await coro
        except Exception as exc:
            logger.warning("Threat intel task '%s' failed: %s", name, exc)
            return name, None

    pairs = await asyncio.gather(*[_safe(n, c) for n, c in zip(names, coros)])
    return dict(pairs)
