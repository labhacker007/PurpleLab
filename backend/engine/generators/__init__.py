"""Security product event generators.

Each generator produces events matching the real vendor's API/webhook format.
This is the canonical location; backend/generators/ re-exports for backward compat.
"""
from backend.engine.generators.base import BaseGenerator, GeneratorConfig
from backend.engine.generators.splunk import SplunkGenerator
from backend.engine.generators.crowdstrike import CrowdStrikeGenerator
from backend.engine.generators.sentinel import SentinelGenerator
from backend.engine.generators.okta import OktaGenerator
from backend.engine.generators.proofpoint import ProofpointGenerator
from backend.engine.generators.servicenow import ServiceNowGenerator
from backend.engine.generators.carbon_black import CarbonBlackGenerator
from backend.engine.generators.defender_endpoint import DefenderEndpointGenerator
from backend.engine.generators.entra_id import EntraIDGenerator
from backend.engine.generators.qradar import QRadarGenerator
from backend.engine.generators.elastic import ElasticGenerator
from backend.engine.generators.guardduty import GuardDutyGenerator

GENERATOR_REGISTRY: dict[str, type[BaseGenerator]] = {
    "splunk": SplunkGenerator,
    "crowdstrike": CrowdStrikeGenerator,
    "sentinel": SentinelGenerator,
    "okta": OktaGenerator,
    "proofpoint": ProofpointGenerator,
    "servicenow": ServiceNowGenerator,
    "carbon_black": CarbonBlackGenerator,
    "defender_endpoint": DefenderEndpointGenerator,
    "entra_id": EntraIDGenerator,
    "qradar": QRadarGenerator,
    "elastic": ElasticGenerator,
    "guardduty": GuardDutyGenerator,
}

__all__ = ["GENERATOR_REGISTRY", "BaseGenerator", "GeneratorConfig"]
