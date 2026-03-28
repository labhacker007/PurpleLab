"""Splunk Common Information Model (CIM) normalizer.

TODO: Implement field mapping to/from CIM data models:
- Authentication, Change, Endpoint, Malware, Network Traffic, Web
"""
from __future__ import annotations

from typing import Any


class CIMNormalizer:
    """Normalizes events to/from Splunk CIM format.

    TODO: Implement field mapping for each CIM data model.
    """

    def normalize(self, event: dict[str, Any], data_model: str = "Authentication") -> dict[str, Any]:
        raise NotImplementedError

    def denormalize(self, cim_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        raise NotImplementedError
