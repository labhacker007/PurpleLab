"""Background noise generator for realistic log data.

Generates benign/normal activity events to mix with malicious events,
creating a realistic signal-to-noise ratio for detection testing.

TODO: Implement noise profiles for different organization types.
TODO: Support time-based patterns (business hours, weekends).
TODO: Generate correlated noise (user sessions, service activity).
"""
from __future__ import annotations

from typing import Any


class NoiseGenerator:
    """Generates realistic background noise events.

    TODO: Implement noise generation with configurable profiles.
    """

    async def generate_noise(
        self,
        source_type: str,
        count: int = 100,
        profile: str = "corporate",
    ) -> list[dict[str, Any]]:
        """Generate background noise events.

        TODO: Implement with realistic patterns per source type.
        """
        raise NotImplementedError
