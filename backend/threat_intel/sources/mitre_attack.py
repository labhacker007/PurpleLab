"""MITRE ATT&CK data source — loads and parses STIX bundles.

Supports two loading strategies:
1. ``mitreattack-python`` library (preferred, auto-downloads latest data)
2. Bundled STIX JSON file at ``data/mitre_attack/enterprise-attack.json``
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default path for the bundled STIX JSON
_DATA_DIR = Path("data/mitre_attack")
_STIX_PATH = _DATA_DIR / "enterprise-attack.json"
_SUMMARY_PATH = _DATA_DIR / "techniques_summary.json"

# Optional dependency
_mitreattack_available = False
try:
    from mitreattack.stix20 import MitreAttackData as _MitreAttackData

    _mitreattack_available = True
except ImportError:
    pass


class MITREAttackSource:
    """Loads and parses MITRE ATT&CK STIX data.

    After calling :meth:`load_enterprise_attack`, the parsed data is
    accessible via the ``techniques``, ``groups``, and ``relationships``
    attributes.
    """

    def __init__(self, stix_path: str | Path | None = None) -> None:
        self.stix_path = Path(stix_path) if stix_path else _STIX_PATH
        self.techniques: list[dict[str, Any]] = []
        self.groups: list[dict[str, Any]] = []
        self.relationships: list[dict[str, Any]] = []
        self._stix_bundle: dict[str, Any] | None = None
        self._loaded = False

    # ------------------------------------------------------------------
    # Main loader
    # ------------------------------------------------------------------

    def load_enterprise_attack(self) -> dict[str, Any]:
        """Load enterprise ATT&CK data.

        Returns a dict with keys ``techniques``, ``groups``, ``relationships``.
        """
        if self._loaded:
            return self._as_dict()

        # Strategy 1: Try mitreattack-python
        if _mitreattack_available:
            try:
                return self._load_via_library()
            except Exception as exc:
                logger.warning("mitreattack-python load failed (%s), trying STIX file", exc)

        # Strategy 2: Bundled STIX JSON
        if self.stix_path.exists():
            return self._load_from_stix_file()

        # Strategy 3: Try the summary file (lighter)
        if _SUMMARY_PATH.exists():
            return self._load_from_summary()

        logger.warning(
            "No MITRE ATT&CK data available. Run scripts/seed_mitre.py to download it."
        )
        self._loaded = True
        return self._as_dict()

    # ------------------------------------------------------------------
    # Loading strategies
    # ------------------------------------------------------------------

    def _load_via_library(self) -> dict[str, Any]:
        """Load using mitreattack-python."""
        logger.info("Loading MITRE ATT&CK data via mitreattack-python ...")

        # If we have the STIX file cached, use it directly (faster)
        if self.stix_path.exists():
            mitre = _MitreAttackData(stix_filepath=str(self.stix_path))
        else:
            # Download fresh (this is slow the first time)
            mitre = _MitreAttackData(stix_filepath=str(self.stix_path))

        # Extract techniques
        for tech in mitre.get_techniques(remove_revoked_deprecated=True):
            parsed = self._parse_stix_technique(tech)
            if parsed:
                self.techniques.append(parsed)

        # Extract groups
        for group in mitre.get_groups(remove_revoked_deprecated=True):
            parsed = self._parse_stix_group(group)
            if parsed:
                self.groups.append(parsed)

        # Extract relationships (group-uses-technique)
        for rel in (mitre.src.query([
            _Filter("type", "=", "relationship"),
            _Filter("relationship_type", "=", "uses"),
        ]) if hasattr(mitre, 'src') else []):
            parsed = self._parse_stix_relationship(rel)
            if parsed:
                self.relationships.append(parsed)

        self._loaded = True
        logger.info(
            "Loaded %d techniques, %d groups, %d relationships",
            len(self.techniques), len(self.groups), len(self.relationships),
        )
        return self._as_dict()

    def _load_from_stix_file(self) -> dict[str, Any]:
        """Load from a local STIX JSON bundle."""
        logger.info("Loading MITRE ATT&CK from %s ...", self.stix_path)
        with open(self.stix_path, "r", encoding="utf-8") as f:
            self._stix_bundle = json.load(f)

        objects = self._stix_bundle.get("objects", [])
        self.techniques = self.parse_techniques(self._stix_bundle)
        self.groups = self.parse_groups(self._stix_bundle)
        self.relationships = self.parse_relationships(self._stix_bundle)

        self._loaded = True
        logger.info(
            "Loaded %d techniques, %d groups, %d relationships from STIX file",
            len(self.techniques), len(self.groups), len(self.relationships),
        )
        return self._as_dict()

    def _load_from_summary(self) -> dict[str, Any]:
        """Load from the lightweight summary JSON."""
        logger.info("Loading MITRE ATT&CK from summary file %s ...", _SUMMARY_PATH)
        with open(_SUMMARY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.techniques = data.get("techniques", [])
        self.groups = data.get("groups", [])
        self.relationships = data.get("relationships", [])
        self._loaded = True
        return self._as_dict()

    # ------------------------------------------------------------------
    # STIX bundle parsers
    # ------------------------------------------------------------------

    def parse_techniques(self, stix_bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract techniques from a STIX bundle."""
        techniques: list[dict[str, Any]] = []
        objects = stix_bundle.get("objects", [])

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            parsed = self._parse_stix_technique(obj)
            if parsed:
                techniques.append(parsed)
        return techniques

    def parse_groups(self, stix_bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract groups/actors from a STIX bundle."""
        groups: list[dict[str, Any]] = []
        objects = stix_bundle.get("objects", [])

        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            parsed = self._parse_stix_group(obj)
            if parsed:
                groups.append(parsed)
        return groups

    def parse_relationships(self, stix_bundle: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract group-uses-technique relationships from a STIX bundle."""
        relationships: list[dict[str, Any]] = []
        objects = stix_bundle.get("objects", [])

        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            parsed = self._parse_stix_relationship(obj)
            if parsed:
                relationships.append(parsed)
        return relationships

    # ------------------------------------------------------------------
    # Individual object parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_stix_technique(obj: Any) -> dict[str, Any] | None:
        """Parse a STIX attack-pattern into a clean technique dict."""
        # Handle both stix2 objects and raw dicts
        get = getattr(obj, "get", None)
        if get is None:
            # stix2 object — convert to dict-like access
            try:
                obj = json.loads(obj.serialize())
            except Exception:
                return None
            get = obj.get

        refs = get("external_references", [])
        technique_id = ""
        url = ""
        for ref in refs:
            src = ref.get("source_name", "") if isinstance(ref, dict) else getattr(ref, "source_name", "")
            if src == "mitre-attack":
                technique_id = ref.get("external_id", "") if isinstance(ref, dict) else getattr(ref, "external_id", "")
                url = ref.get("url", "") if isinstance(ref, dict) else getattr(ref, "url", "")
                break

        if not technique_id:
            return None

        # Extract tactics from kill_chain_phases
        tactics: list[str] = []
        for phase in get("kill_chain_phases", []):
            phase_name = phase.get("phase_name", "") if isinstance(phase, dict) else getattr(phase, "phase_name", "")
            if phase_name:
                tactics.append(phase_name)

        # Extract platforms
        platforms = get("x_mitre_platforms", [])
        if not isinstance(platforms, list):
            platforms = []

        return {
            "technique_id": technique_id,
            "stix_id": get("id", ""),
            "name": get("name", ""),
            "description": get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "url": url,
            "is_subtechnique": "." in technique_id,
            "detection": get("x_mitre_detection", ""),
            "data_sources": get("x_mitre_data_sources", []),
        }

    @staticmethod
    def _parse_stix_group(obj: Any) -> dict[str, Any] | None:
        """Parse a STIX intrusion-set into a clean group dict."""
        get = getattr(obj, "get", None)
        if get is None:
            try:
                obj = json.loads(obj.serialize())
            except Exception:
                return None
            get = obj.get

        refs = get("external_references", [])
        group_id = ""
        url = ""
        for ref in refs:
            src = ref.get("source_name", "") if isinstance(ref, dict) else getattr(ref, "source_name", "")
            if src == "mitre-attack":
                group_id = ref.get("external_id", "") if isinstance(ref, dict) else getattr(ref, "external_id", "")
                url = ref.get("url", "") if isinstance(ref, dict) else getattr(ref, "url", "")
                break

        if not group_id:
            return None

        aliases = get("aliases", [])
        if not isinstance(aliases, list):
            aliases = []

        return {
            "group_id": group_id,
            "stix_id": get("id", ""),
            "name": get("name", ""),
            "description": get("description", ""),
            "aliases": aliases,
            "url": url,
        }

    @staticmethod
    def _parse_stix_relationship(obj: Any) -> dict[str, Any] | None:
        """Parse a STIX relationship object."""
        get = getattr(obj, "get", None)
        if get is None:
            try:
                obj = json.loads(obj.serialize())
            except Exception:
                return None
            get = obj.get

        return {
            "id": get("id", ""),
            "relationship_type": get("relationship_type", ""),
            "source_ref": get("source_ref", ""),
            "target_ref": get("target_ref", ""),
            "description": get("description", ""),
        }

    # ------------------------------------------------------------------
    # Async wrappers (for service layer)
    # ------------------------------------------------------------------

    async def get_groups(self) -> list[dict[str, Any]]:
        """Return all parsed groups (loads data first if needed)."""
        if not self._loaded:
            import asyncio
            await asyncio.to_thread(self.load_enterprise_attack)
        return self.groups

    async def get_techniques_for_group(self, group_id: str) -> list[dict[str, Any]]:
        """Return techniques used by a specific group."""
        if not self._loaded:
            import asyncio
            await asyncio.to_thread(self.load_enterprise_attack)

        # Find the group's STIX ID
        stix_id = ""
        for g in self.groups:
            if g["group_id"] == group_id or g["name"].lower() == group_id.lower():
                stix_id = g["stix_id"]
                break
            if group_id.lower() in [a.lower() for a in g.get("aliases", [])]:
                stix_id = g["stix_id"]
                break

        if not stix_id:
            return []

        # Find technique STIX IDs via relationships
        technique_stix_ids: set[str] = set()
        for rel in self.relationships:
            if rel["source_ref"] == stix_id and rel["relationship_type"] == "uses":
                target = rel["target_ref"]
                if target.startswith("attack-pattern--"):
                    technique_stix_ids.add(target)

        # Map back to technique dicts
        return [t for t in self.techniques if t["stix_id"] in technique_stix_ids]

    async def get_all_techniques(self) -> list[dict[str, Any]]:
        """Return all parsed techniques."""
        if not self._loaded:
            import asyncio
            await asyncio.to_thread(self.load_enterprise_attack)
        return self.techniques

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _as_dict(self) -> dict[str, Any]:
        return {
            "techniques": self.techniques,
            "groups": self.groups,
            "relationships": self.relationships,
        }
