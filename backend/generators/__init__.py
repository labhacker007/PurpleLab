"""Security product event generators.

Each generator produces events matching the real vendor's API/webhook format.
"""
from backend.generators.base import BaseGenerator, GeneratorConfig
from backend.generators.splunk import SplunkGenerator
from backend.generators.crowdstrike import CrowdStrikeGenerator
from backend.generators.sentinel import SentinelGenerator
from backend.generators.okta import OktaGenerator
from backend.generators.proofpoint import ProofpointGenerator
from backend.generators.servicenow import ServiceNowGenerator
from backend.generators.carbon_black import CarbonBlackGenerator
from backend.generators.defender_endpoint import DefenderEndpointGenerator
from backend.generators.entra_id import EntraIDGenerator
from backend.generators.qradar import QRadarGenerator
from backend.generators.elastic import ElasticGenerator
from backend.generators.guardduty import GuardDutyGenerator

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
