"""Windows Event Log source generator.

TODO: Generate events for common Event IDs:
- 4624/4625 (Logon Success/Failure)
- 4688 (Process Creation)
- 4672 (Special Privilege Logon)
- 4720/4726 (Account Created/Deleted)
- 4732 (Member Added to Security Group)
- 7045 (Service Installed)
"""
from __future__ import annotations

from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


class WindowsEventLogSource(AbstractLogSource):
    source_type = "windows_eventlog"
    description = "Windows Security/System/Application Event Logs"

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        raise NotImplementedError

    def generate_batch(self, count: int = 10, malicious_ratio: float = 0.1, technique_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError
