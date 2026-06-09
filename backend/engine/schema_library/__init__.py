"""Vendor-specific log schema libraries for realistic simulation.

Each sub-module defines authentic event templates using real field names from
vendor documentation, allowing PurpleLab to produce logs that are
indistinguishable from actual product telemetry in a SIEM.
"""
from __future__ import annotations

from typing import Any

from backend.engine.schema_library.edr import VENDOR_BENIGN_TEMPLATES as _EDR
from backend.engine.schema_library.identity import VENDOR_BENIGN_TEMPLATES as _IDP
from backend.engine.schema_library.network import VENDOR_BENIGN_TEMPLATES as _NETWORK
from backend.engine.schema_library.cloud import VENDOR_BENIGN_TEMPLATES as _CLOUD
from backend.engine.schema_library.email import VENDOR_BENIGN_TEMPLATES as _EMAIL

# Combined registry: category → vendor → [templates]
VENDOR_TEMPLATES: dict[str, dict[str, list[dict[str, Any]]]] = {
    "edr":      _EDR,
    "idp":      _IDP,
    "firewall": _NETWORK,
    "proxy":    _NETWORK,
    "cloud":    _CLOUD,
    "email":    _EMAIL,
}


def get_vendor_benign_templates(
    category: str,
    vendor: str | None,
) -> list[dict[str, Any]]:
    """Return vendor-specific benign event templates for a product category.

    Falls back to the first available vendor's templates if the requested
    vendor has none defined, then to an empty list.

    Args:
        category: Product category (e.g., "edr", "firewall", "cloud").
        vendor:   Vendor key (e.g., "crowdstrike", "palo_alto", "aws").

    Returns:
        List of benign event template dicts.
    """
    cat_templates = VENDOR_TEMPLATES.get(category, {})
    if vendor and vendor in cat_templates:
        return cat_templates[vendor]
    # Fall back to first available vendor in the category
    for v_templates in cat_templates.values():
        if v_templates:
            return v_templates
    return []
