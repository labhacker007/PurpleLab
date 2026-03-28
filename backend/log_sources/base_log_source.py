"""Abstract base class for log source generators.

All log source implementations inherit from AbstractLogSource and
produce events in the appropriate format for their source type.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AbstractLogSource(ABC):
    """Abstract base for log source generators.

    Subclasses produce synthetic events matching a specific log source
    format (Windows EventLog, Sysmon, Linux audit, etc.).
    """

    source_type: str = ""
    description: str = ""

    @abstractmethod
    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        """Generate a single log event.

        Args:
            malicious: If True, generate an event containing attack indicators.
            technique_id: Optional MITRE technique to simulate.

        Returns:
            A dict representing the log event in the source's native format.
        """
        ...

    @abstractmethod
    def generate_batch(
        self,
        count: int = 10,
        malicious_ratio: float = 0.1,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        """Generate a batch of log events with a mix of benign and malicious.

        Args:
            count: Total number of events.
            malicious_ratio: Fraction of events that should be malicious (0.0-1.0).
            technique_id: Optional MITRE technique for malicious events.

        Returns:
            List of event dicts.
        """
        ...

    def get_schema(self) -> dict[str, Any]:
        """Return the JSON schema for events from this source.

        Default returns empty schema. Subclasses should override.
        """
        return {"source_type": self.source_type, "fields": {}}
