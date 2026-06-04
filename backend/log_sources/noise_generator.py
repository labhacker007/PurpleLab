"""Noise generator — produces realistic background log traffic.

Instantiates all available log sources and generates a mixed stream
of benign events with time-of-day volume weighting:
  - Business hours (08:00-18:00): high volume, more auth/process events
  - After hours (18:00-22:00): medium volume
  - Night (22:00-08:00): low volume, mostly scheduled task/sysmon events
"""
from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Any

# Import all available log sources, skipping any that are not yet implemented.
_available_sources: list[Any] = []

try:
    from backend.log_sources.sources.windows_eventlog import WindowsEventLogSource
    _available_sources.append(WindowsEventLogSource)
except ImportError:
    WindowsEventLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.sysmon import SysmonLogSource
    _available_sources.append(SysmonLogSource)
except ImportError:
    SysmonLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.linux_audit import LinuxAuditLogSource
    _available_sources.append(LinuxAuditLogSource)
except ImportError:
    LinuxAuditLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.proxy import ProxyLogSource
    _available_sources.append(ProxyLogSource)
except ImportError:
    ProxyLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.firewall import FirewallLogSource
    _available_sources.append(FirewallLogSource)
except ImportError:
    FirewallLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.dns import DNSLogSource
    _available_sources.append(DNSLogSource)
except ImportError:
    DNSLogSource = None  # type: ignore[assignment,misc]

try:
    from backend.log_sources.sources.cloud_trail import CloudTrailLogSource
    _available_sources.append(CloudTrailLogSource)
except ImportError:
    CloudTrailLogSource = None  # type: ignore[assignment,misc]


def _classify_hour(hour: int) -> str:
    """Return a time-of-day band name for the given UTC hour (0-23)."""
    if 8 <= hour < 18:
        return "business"
    if 18 <= hour < 22:
        return "afterhours"
    return "night"


class NoiseGenerator:
    """Generates realistic background log traffic from all available sources.

    Time-of-day weighting table (source_type → relative weight per band):

    +-----------------------+----------+------------+-------+
    | source_type           | business | afterhours | night |
    +-----------------------+----------+------------+-------+
    | windows_eventlog      |    4     |     2      |   1   |
    | sysmon                |    3     |     1      |   2   |
    | linux_audit           |    2     |     2      |   3   |
    | proxy                 |    3     |     3      |   1   |
    | firewall              |    2     |     3      |   2   |
    | dns                   |    2     |     1      |   3   |
    | cloudtrail            |    3     |     2      |   1   |
    +-----------------------+----------+------------+-------+
    """

    # (source_type → {band: weight})
    _WEIGHTS: dict[str, dict[str, int]] = {
        "windows_eventlog": {"business": 4, "afterhours": 2, "night": 1},
        "sysmon":           {"business": 3, "afterhours": 1, "night": 2},
        "linux_audit":      {"business": 2, "afterhours": 2, "night": 3},
        "proxy":            {"business": 3, "afterhours": 3, "night": 1},
        "firewall":         {"business": 2, "afterhours": 3, "night": 2},
        "dns":              {"business": 2, "afterhours": 1, "night": 3},
        "cloudtrail":       {"business": 3, "afterhours": 2, "night": 1},
    }

    def __init__(self, session_id: str = "", seed: int | None = None) -> None:
        """Initialise the noise generator.

        Args:
            session_id: Optional identifier stamped onto every emitted event.
            seed: Optional RNG seed for reproducible output.
        """
        if seed is not None:
            random.seed(seed)

        self.session_id = session_id

        # Instantiate one instance of each available source class.
        self._sources: dict[str, Any] = {}
        for cls in _available_sources:
            try:
                instance = cls()
                self._sources[instance.source_type] = instance
            except Exception:
                # Skip sources whose constructors fail (missing dependencies, etc.)
                pass

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _weighted_source(self, band: str) -> Any | None:
        """Pick a random source instance weighted by the time-of-day band."""
        if not self._sources:
            return None

        population = []
        weights = []
        for source_type, instance in self._sources.items():
            band_weights = self._WEIGHTS.get(source_type, {})
            w = band_weights.get(band, 1)
            population.append(instance)
            weights.append(w)

        return random.choices(population, weights=weights, k=1)[0]

    def _stamp(self, event: dict[str, Any], source_type: str) -> dict[str, Any]:
        """Add source_type and optional session_id to an event dict."""
        event["source_type"] = source_type
        if self.session_id:
            event["session_id"] = self.session_id
        return event

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_noise(self, count: int = 100, hour: int | None = None) -> list[dict[str, Any]]:
        """Generate benign background log events with time-of-day weighting.

        Args:
            count: Number of events to generate.
            hour: UTC hour (0-23) to use for weighting. Defaults to current UTC hour.

        Returns:
            List of benign event dicts, each stamped with source_type (and
            session_id if provided at construction time).
        """
        if hour is None:
            hour = datetime.now(timezone.utc).hour

        band = _classify_hour(hour)
        events: list[dict[str, Any]] = []

        for _ in range(count):
            source = self._weighted_source(band)
            if source is None:
                continue
            ev = source.generate(malicious=False)
            events.append(self._stamp(ev, source.source_type))

        return events

    def generate_mixed(
        self,
        count: int = 100,
        malicious_ratio: float = 0.05,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        """Generate a mixed batch of benign and attack events.

        Malicious events are distributed across a random subset of the
        available sources so they blend naturally into the noise stream.

        Args:
            count: Total number of events.
            malicious_ratio: Fraction of events that should be malicious (0.0-1.0).
            technique_id: Optional MITRE technique ID to use for malicious events.
                          If empty, each source picks a random attack pattern.

        Returns:
            Shuffled list of event dicts, each stamped with source_type (and
            session_id if provided at construction time).
        """
        if not self._sources:
            return []

        n_malicious = max(0, min(count, round(count * malicious_ratio)))
        n_benign = count - n_malicious

        events: list[dict[str, Any]] = []

        # Benign events — use time-of-day weighting
        hour = datetime.now(timezone.utc).hour
        band = _classify_hour(hour)
        for _ in range(n_benign):
            source = self._weighted_source(band)
            if source is None:
                continue
            ev = source.generate(malicious=False)
            events.append(self._stamp(ev, source.source_type))

        # Malicious events — spread across a random subset of sources
        source_list = list(self._sources.values())
        malicious_sources = random.choices(source_list, k=n_malicious) if source_list else []
        for source in malicious_sources:
            try:
                ev = source.generate(malicious=True, technique_id=technique_id)
            except Exception:
                ev = source.generate(malicious=False)
            events.append(self._stamp(ev, source.source_type))

        random.shuffle(events)
        return events

    def available_sources(self) -> list[str]:
        """Return the source_type strings for all successfully instantiated sources.

        Returns:
            Sorted list of source_type strings (e.g. ["cloudtrail", "dns", ...]).
        """
        return sorted(self._sources.keys())
