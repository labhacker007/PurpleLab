"""Microsoft Advanced SIEM Information Model (ASIM) normalizer.

TODO: Implement field mapping to/from ASIM schemas:
- Authentication, AuditEvent, Dns, FileEvent, NetworkSession, ProcessEvent, WebSession
"""
from __future__ import annotations

from typing import Any


class ASIMNormalizer:
    """Normalizes events to/from Microsoft ASIM format.

    TODO: Implement field mapping for each ASIM schema.
    """

    def normalize(self, event: dict[str, Any], schema: str = "Authentication") -> dict[str, Any]:
        raise NotImplementedError

    def denormalize(self, asim_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        raise NotImplementedError
