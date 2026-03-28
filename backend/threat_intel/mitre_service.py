"""MITRE ATT&CK service — technique data, tactic mapping, and coverage analysis.

Provides high-level access to MITRE ATT&CK data backed by the knowledge
store for semantic search and the STIX source for structured lookups.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from backend.knowledge.store import KnowledgeStore
from backend.threat_intel.sources.mitre_attack import MITREAttackSource

logger = logging.getLogger(__name__)

# Canonical tactic ordering (Enterprise ATT&CK)
TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


class MITREService:
    """Service for MITRE ATT&CK framework data.

    Lazily loads ATT&CK data on first use and optionally indexes it into
    the knowledge base for semantic search.
    """

    def __init__(
        self,
        knowledge_store: KnowledgeStore | None = None,
        mitre_source: MITREAttackSource | None = None,
    ) -> None:
        self.knowledge = knowledge_store
        self._source = mitre_source or MITREAttackSource()
        self._loaded = False

        # In-memory indices built after loading
        self._techniques_by_id: dict[str, dict[str, Any]] = {}
        self._techniques_by_tactic: dict[str, list[dict[str, Any]]] = {}
        self._groups_by_name: dict[str, dict[str, Any]] = {}
        self._groups_by_id: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    async def load_attack_data(self) -> None:
        """Load MITRE ATT&CK Enterprise data and build indices."""
        if self._loaded:
            return

        data = await asyncio.to_thread(self._source.load_enterprise_attack)

        # Build technique index
        for tech in data.get("techniques", []):
            tid = tech["technique_id"]
            self._techniques_by_id[tid] = tech
            for tactic in tech.get("tactics", []):
                self._techniques_by_tactic.setdefault(tactic, []).append(tech)

        # Build group index
        for group in data.get("groups", []):
            self._groups_by_id[group["group_id"]] = group
            self._groups_by_name[group["name"].lower()] = group
            for alias in group.get("aliases", []):
                self._groups_by_name[alias.lower()] = group

        self._loaded = True
        logger.info(
            "MITREService loaded: %d techniques, %d groups",
            len(self._techniques_by_id),
            len(self._groups_by_id),
        )

        # Optionally index into knowledge base for semantic search
        if self.knowledge:
            await self._index_to_knowledge_base()

    async def _ensure_loaded(self) -> None:
        if not self._loaded:
            await self.load_attack_data()

    async def _index_to_knowledge_base(self) -> None:
        """Index techniques and groups into the knowledge base."""
        if not self.knowledge:
            return

        count = 0
        for tech in self._techniques_by_id.values():
            content = f"{tech['technique_id']} - {tech['name']}\n\n{tech.get('description', '')}"
            await self.knowledge.store_knowledge(
                namespace="detection_rules",
                key=f"mitre-technique-{tech['technique_id']}",
                content=content,
                metadata={
                    "type": "mitre_technique",
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactics": ", ".join(tech.get("tactics", [])),
                },
            )
            count += 1

        for group in self._groups_by_id.values():
            content = f"{group['name']} ({group['group_id']})\n\n{group.get('description', '')}"
            await self.knowledge.store_knowledge(
                namespace="threat_actors",
                key=f"mitre-group-{group['group_id']}",
                content=content,
                metadata={
                    "type": "mitre_group",
                    "group_id": group["group_id"],
                    "name": group["name"],
                    "aliases": ", ".join(group.get("aliases", [])),
                },
            )
            count += 1

        logger.info("Indexed %d MITRE items into knowledge base", count)

    # ------------------------------------------------------------------
    # Technique queries
    # ------------------------------------------------------------------

    async def get_all_techniques(self) -> list[dict[str, Any]]:
        """Get all techniques with tactic mapping."""
        await self._ensure_loaded()
        return list(self._techniques_by_id.values())

    async def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Get a specific technique by ID (e.g., T1059.001)."""
        await self._ensure_loaded()
        return self._techniques_by_id.get(technique_id.upper())

    async def get_techniques_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Get all techniques for a tactic (e.g., 'execution')."""
        await self._ensure_loaded()
        # Normalise: accept both "Execution" and "execution"
        tactic_key = tactic.lower().replace(" ", "-")
        return self._techniques_by_tactic.get(tactic_key, [])

    async def search_techniques(self, query: str) -> list[dict[str, Any]]:
        """Semantic search for techniques.

        Uses the knowledge base if available, otherwise falls back to
        simple substring matching.
        """
        await self._ensure_loaded()

        # Try knowledge base semantic search first
        if self.knowledge:
            results = await self.knowledge.search_knowledge(
                namespace="detection_rules", query=query, top_k=10
            )
            technique_ids = []
            for r in results:
                meta = r.get("metadata", {})
                tid = meta.get("technique_id", "")
                if tid and tid in self._techniques_by_id:
                    technique_ids.append(tid)
            if technique_ids:
                return [self._techniques_by_id[tid] for tid in technique_ids]

        # Fallback: substring search
        query_lower = query.lower()
        matches: list[dict[str, Any]] = []
        for tech in self._techniques_by_id.values():
            text = f"{tech['technique_id']} {tech['name']} {tech.get('description', '')}".lower()
            if query_lower in text:
                matches.append(tech)
        return matches[:20]

    # ------------------------------------------------------------------
    # Backward-compatible aliases (original stub signatures)
    # ------------------------------------------------------------------

    async def list_techniques(
        self, tactic: str = "", platform: str = ""
    ) -> list[dict[str, Any]]:
        """List techniques with optional tactic/platform filtering."""
        await self._ensure_loaded()

        if tactic:
            techniques = await self.get_techniques_by_tactic(tactic)
        else:
            techniques = list(self._techniques_by_id.values())

        if platform:
            platform_lower = platform.lower()
            techniques = [
                t for t in techniques
                if any(p.lower() == platform_lower for p in t.get("platforms", []))
            ]

        return techniques

    # ------------------------------------------------------------------
    # Group / actor queries
    # ------------------------------------------------------------------

    async def get_all_groups(self) -> list[dict[str, Any]]:
        """Get all threat actor groups from ATT&CK."""
        await self._ensure_loaded()
        return list(self._groups_by_id.values())

    async def get_group(self, group_name: str) -> dict[str, Any] | None:
        """Get a specific group by name, alias, or ID."""
        await self._ensure_loaded()
        # Try by ID first
        if group_name.upper().startswith("G"):
            group = self._groups_by_id.get(group_name.upper())
            if group:
                return group
        # Try by name / alias
        return self._groups_by_name.get(group_name.lower())

    async def get_actor_techniques(self, actor_name: str) -> list[dict[str, Any]]:
        """Get techniques used by a specific threat actor/group."""
        await self._ensure_loaded()
        return await self._source.get_techniques_for_group(actor_name)

    async def get_techniques_for_actor(self, actor_name: str) -> list[dict[str, Any]]:
        """Alias for backward compatibility."""
        return await self.get_actor_techniques(actor_name)

    # ------------------------------------------------------------------
    # Coverage matrix
    # ------------------------------------------------------------------

    async def get_coverage_matrix(
        self, technique_ids: list[str] | None = None
    ) -> dict[str, Any]:
        """Generate a coverage matrix showing which tactics/techniques are covered.

        Parameters
        ----------
        technique_ids : list[str] | None
            List of technique IDs that are "covered" (e.g., by detection
            rules).  If *None*, returns the full matrix with nothing covered.

        Returns
        -------
        dict with ``{tactic: [{technique_id, technique_name, covered}]}``
        """
        await self._ensure_loaded()

        covered_set = set(tid.upper() for tid in (technique_ids or []))
        matrix: dict[str, list[dict[str, Any]]] = {}
        total = 0
        covered_count = 0

        for tactic in TACTIC_ORDER:
            entries: list[dict[str, Any]] = []
            for tech in self._techniques_by_tactic.get(tactic, []):
                is_covered = tech["technique_id"] in covered_set
                entries.append({
                    "technique_id": tech["technique_id"],
                    "technique_name": tech["name"],
                    "covered": is_covered,
                })
                total += 1
                if is_covered:
                    covered_count += 1
            matrix[tactic] = entries

        return {
            "matrix": matrix,
            "total_techniques": total,
            "covered": covered_count,
            "coverage_pct": round(covered_count / total * 100, 1) if total > 0 else 0.0,
        }

    # ------------------------------------------------------------------
    # Sync from MITRE (backward-compatible)
    # ------------------------------------------------------------------

    async def sync_from_mitre(self) -> int:
        """Sync technique data from MITRE ATT&CK STIX repository."""
        self._loaded = False
        self._techniques_by_id.clear()
        self._techniques_by_tactic.clear()
        self._groups_by_name.clear()
        self._groups_by_id.clear()

        await self.load_attack_data()
        return len(self._techniques_by_id)
