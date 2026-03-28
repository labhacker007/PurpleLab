#!/usr/bin/env python3
"""Seed script — download and parse the MITRE ATT&CK Enterprise STIX bundle.

Usage:
    python scripts/seed_mitre.py [--index]

Options:
    --index     Also load the parsed data into the knowledge base (ChromaDB).

The script:
1. Downloads the latest MITRE ATT&CK Enterprise STIX bundle from GitHub.
2. Saves the full bundle to  data/mitre_attack/enterprise-attack.json
3. Parses it into techniques, groups, and relationships.
4. Creates a lightweight  data/mitre_attack/techniques_summary.json
5. (Optional) Indexes everything into the knowledge base.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path so we can import backend modules
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))
os.chdir(_PROJECT_ROOT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("seed_mitre")

# MITRE ATT&CK STIX bundle URLs (GitHub raw)
ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

DATA_DIR = _PROJECT_ROOT / "data" / "mitre_attack"
STIX_PATH = DATA_DIR / "enterprise-attack.json"
SUMMARY_PATH = DATA_DIR / "techniques_summary.json"


def download_stix_bundle(url: str = ENTERPRISE_ATTACK_URL, dest: Path = STIX_PATH) -> Path:
    """Download the STIX bundle to *dest*."""
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Try httpx first, then urllib
    try:
        import httpx

        logger.info("Downloading STIX bundle via httpx from %s ...", url)
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
    except ImportError:
        import urllib.request

        logger.info("Downloading STIX bundle via urllib from %s ...", url)
        urllib.request.urlretrieve(url, str(dest))

    size_mb = dest.stat().st_size / (1024 * 1024)
    logger.info("Saved STIX bundle to %s (%.1f MB)", dest, size_mb)
    return dest


def parse_and_save_summary(stix_path: Path = STIX_PATH, summary_path: Path = SUMMARY_PATH) -> dict:
    """Parse the STIX bundle and save a lightweight summary."""
    from backend.threat_intel.sources.mitre_attack import MITREAttackSource

    source = MITREAttackSource(stix_path=stix_path)
    data = source.load_enterprise_attack()

    # Build lightweight summary
    summary = {
        "techniques": [
            {
                "technique_id": t["technique_id"],
                "name": t["name"],
                "tactics": t.get("tactics", []),
                "description": t.get("description", "")[:500],
                "is_subtechnique": t.get("is_subtechnique", False),
                "platforms": t.get("platforms", []),
            }
            for t in data["techniques"]
        ],
        "groups": [
            {
                "group_id": g["group_id"],
                "name": g["name"],
                "aliases": g.get("aliases", []),
                "description": g.get("description", "")[:500],
            }
            for g in data["groups"]
        ],
        "relationships": [
            {
                "source_ref": r["source_ref"],
                "target_ref": r["target_ref"],
                "relationship_type": r["relationship_type"],
            }
            for r in data["relationships"]
        ],
        "stats": {
            "total_techniques": len(data["techniques"]),
            "total_groups": len(data["groups"]),
            "total_relationships": len(data["relationships"]),
        },
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info(
        "Saved summary to %s — %d techniques, %d groups, %d relationships",
        summary_path,
        summary["stats"]["total_techniques"],
        summary["stats"]["total_groups"],
        summary["stats"]["total_relationships"],
    )
    return summary


async def index_to_knowledge_base() -> None:
    """Load parsed MITRE data into the knowledge base (ChromaDB)."""
    from backend.knowledge.vector_store import VectorStore
    from backend.knowledge.store import KnowledgeStore
    from backend.threat_intel.mitre_service import MITREService
    from backend.threat_intel.sources.mitre_attack import MITREAttackSource
    from backend.config import settings

    vector_store = VectorStore(persist_dir=settings.CHROMA_PERSIST_DIR)
    knowledge = KnowledgeStore(vector_store=vector_store)
    source = MITREAttackSource(stix_path=STIX_PATH)
    mitre_svc = MITREService(knowledge_store=knowledge, mitre_source=source)

    logger.info("Loading MITRE data into knowledge base ...")
    await mitre_svc.load_attack_data()

    stats = await knowledge.get_stats()
    logger.info("Knowledge base stats after indexing: %s", stats)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed MITRE ATT&CK data")
    parser.add_argument(
        "--index",
        action="store_true",
        help="Also index data into the knowledge base (ChromaDB)",
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip downloading the STIX bundle (use existing file)",
    )
    args = parser.parse_args()

    # Step 1: Download
    if not args.skip_download:
        download_stix_bundle()
    elif not STIX_PATH.exists():
        logger.error("STIX file not found at %s and --skip-download was set", STIX_PATH)
        sys.exit(1)

    # Step 2: Parse and summarise
    parse_and_save_summary()

    # Step 3: Optionally index
    if args.index:
        asyncio.run(index_to_knowledge_base())

    logger.info("Done!")


if __name__ == "__main__":
    main()
