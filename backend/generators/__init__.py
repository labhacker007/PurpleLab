"""Security product event generators — backward compatibility re-exports.

The canonical location is now backend.engine.generators.
This module re-exports everything for backward compatibility with
existing imports (e.g., from backend.generators import GENERATOR_REGISTRY).
"""
from backend.engine.generators import (
    GENERATOR_REGISTRY,
    BaseGenerator,
    GeneratorConfig,
    SplunkGenerator,
    CrowdStrikeGenerator,
    SentinelGenerator,
    OktaGenerator,
    ProofpointGenerator,
    ServiceNowGenerator,
    CarbonBlackGenerator,
    DefenderEndpointGenerator,
    EntraIDGenerator,
    QRadarGenerator,
    ElasticGenerator,
    GuardDutyGenerator,
)

__all__ = ["GENERATOR_REGISTRY", "BaseGenerator", "GeneratorConfig"]
