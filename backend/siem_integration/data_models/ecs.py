"""Elastic Common Schema (ECS) normalizer.

TODO: Implement field mapping to/from ECS fields:
- event, host, source, destination, process, file, network, user, threat
"""
from __future__ import annotations

from typing import Any


class ECSNormalizer:
    """Normalizes events to/from Elastic ECS format.

    TODO: Implement field mapping for each ECS field set.
    """

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def denormalize(self, ecs_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        raise NotImplementedError
