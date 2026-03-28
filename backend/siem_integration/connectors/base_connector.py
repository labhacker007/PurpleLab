"""Abstract base connector for SIEM platforms.

All SIEM connectors inherit from AbstractConnector and implement
platform-specific connect(), pull_rules(), and push_logs() methods.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AbstractConnector(ABC):
    """Abstract base for SIEM platform connectors.

    Subclasses implement the connection and data exchange logic
    for a specific SIEM platform (Splunk, Sentinel, Elastic).
    """

    platform: str = ""

    @abstractmethod
    async def connect(self, base_url: str, credentials: dict[str, str]) -> bool:
        """Establish a connection to the SIEM platform.

        Args:
            base_url: The SIEM platform URL.
            credentials: Decrypted credentials dict.

        Returns:
            True if connection was successful.
        """
        ...

    @abstractmethod
    async def pull_rules(self) -> list[dict[str, Any]]:
        """Pull detection rules from the connected SIEM.

        Returns:
            List of rule dicts with name, query, severity, etc.
        """
        ...

    @abstractmethod
    async def push_logs(self, events: list[dict[str, Any]], index: str = "") -> bool:
        """Push log events to the SIEM for testing.

        Args:
            events: List of log events to push.
            index: Target index/workspace (platform-specific).

        Returns:
            True if push was successful.
        """
        ...

    async def disconnect(self) -> None:
        """Clean up connection resources."""
        pass

    async def health_check(self) -> bool:
        """Check if the connection is still alive."""
        return False
