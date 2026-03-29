"""HITL data models and default action configurations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class HITLLevel(IntEnum):
    """Approval level for a platform action."""
    L0_AUTO = 0          # Always auto-approve
    L1_SOFT = 1          # Ask in-chat; proceed if no objection within timeout
    L2_EXPLICIT = 2      # Block until human clicks Magic Link / Slack button
    L3_MULTI_PARTY = 3   # Require N≥2 approvals from different reviewers


class HITLStatus(str):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


@dataclass
class NotificationChannels:
    slack_channel: str = ""          # e.g. "#purple-team-approvals"
    slack_user_ids: list[str] = field(default_factory=list)  # DM these users
    email_addresses: list[str] = field(default_factory=list)
    pagerduty_routing_key: str = ""
    webhook_url: str = ""            # Generic webhook (Teams, custom)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slack_channel": self.slack_channel,
            "slack_user_ids": self.slack_user_ids,
            "email_addresses": self.email_addresses,
            "pagerduty_routing_key": self.pagerduty_routing_key,
            "webhook_url": self.webhook_url,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NotificationChannels":
        return cls(
            slack_channel=d.get("slack_channel", ""),
            slack_user_ids=d.get("slack_user_ids", []),
            email_addresses=d.get("email_addresses", []),
            pagerduty_routing_key=d.get("pagerduty_routing_key", ""),
            webhook_url=d.get("webhook_url", ""),
        )


@dataclass
class ActionConfig:
    """Admin-configured HITL rules for one action type."""
    action_type: str
    level: HITLLevel
    description: str = ""
    notifications: NotificationChannels = field(default_factory=NotificationChannels)
    auto_approve_after_seconds: int | None = None   # L0/L1 grace period
    required_approvals: int = 1                      # L3: how many approvers needed
    timeout_seconds: int = 3600                      # Max wait before expiry

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "level": int(self.level),
            "description": self.description,
            "notifications": self.notifications.to_dict(),
            "auto_approve_after_seconds": self.auto_approve_after_seconds,
            "required_approvals": self.required_approvals,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class HITLRequest:
    """A pending or resolved approval request."""
    id: str
    action_type: str
    action_payload: dict[str, Any]
    level: HITLLevel
    status: str
    requested_by: str
    magic_link_token: str | None
    magic_link_url: str | None
    created_at: datetime
    resolved_at: datetime | None = None
    reviewed_by: str | None = None
    review_note: str = ""
    approvals_received: int = 0
    approvals_required: int = 1
    expires_at: datetime | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status in (HITLStatus.APPROVED, HITLStatus.REJECTED,
                               HITLStatus.EXPIRED, HITLStatus.AUTO_APPROVED)

    @property
    def is_approved(self) -> bool:
        return self.status in (HITLStatus.APPROVED, HITLStatus.AUTO_APPROVED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_type": self.action_type,
            "action_payload": self.action_payload,
            "level": int(self.level),
            "level_name": self.level.name,
            "status": self.status,
            "requested_by": self.requested_by,
            "magic_link_url": self.magic_link_url,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "reviewed_by": self.reviewed_by,
            "review_note": self.review_note,
            "approvals_received": self.approvals_received,
            "approvals_required": self.approvals_required,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


# ---------------------------------------------------------------------------
# Default action configs — sensible security defaults
# ---------------------------------------------------------------------------

DEFAULT_ACTION_CONFIGS: dict[str, ActionConfig] = {
    # Simulation / log generation — low risk
    "generate_attack_logs": ActionConfig(
        action_type="generate_attack_logs",
        level=HITLLevel.L0_AUTO,
        description="Generate synthetic attack log events",
    ),
    "run_attack_chain": ActionConfig(
        action_type="run_attack_chain",
        level=HITLLevel.L1_SOFT,
        description="Execute a multi-stage attack chain simulation",
        auto_approve_after_seconds=30,
    ),
    # SIEM operations — medium risk
    "push_logs_to_siem": ActionConfig(
        action_type="push_logs_to_siem",
        level=HITLLevel.L2_EXPLICIT,
        description="Send simulated events to a connected SIEM",
        timeout_seconds=1800,
    ),
    "push_rule_to_siem": ActionConfig(
        action_type="push_rule_to_siem",
        level=HITLLevel.L2_EXPLICIT,
        description="Deploy a detection rule to production SIEM",
        timeout_seconds=3600,
    ),
    "sync_rules_from_siem": ActionConfig(
        action_type="sync_rules_from_siem",
        level=HITLLevel.L1_SOFT,
        description="Import detection rules from a SIEM connection",
        auto_approve_after_seconds=15,
    ),
    # Threat intel — low risk
    "research_threat_actor": ActionConfig(
        action_type="research_threat_actor",
        level=HITLLevel.L0_AUTO,
        description="Research a threat actor using external sources",
    ),
    # Detection rule changes — medium risk
    "import_detection_rules": ActionConfig(
        action_type="import_detection_rules",
        level=HITLLevel.L1_SOFT,
        description="Import new detection rules into the platform",
        auto_approve_after_seconds=20,
    ),
    "delete_detection_rules": ActionConfig(
        action_type="delete_detection_rules",
        level=HITLLevel.L2_EXPLICIT,
        description="Permanently delete detection rules",
        timeout_seconds=1800,
    ),
    # Environment changes — high risk
    "create_environment": ActionConfig(
        action_type="create_environment",
        level=HITLLevel.L1_SOFT,
        description="Create a new simulation environment",
        auto_approve_after_seconds=10,
    ),
    "delete_environment": ActionConfig(
        action_type="delete_environment",
        level=HITLLevel.L3_MULTI_PARTY,
        description="Delete a simulation environment and all data",
        required_approvals=2,
        timeout_seconds=7200,
    ),
    # Knowledge base
    "save_to_knowledge_base": ActionConfig(
        action_type="save_to_knowledge_base",
        level=HITLLevel.L0_AUTO,
        description="Store information in the knowledge base",
    ),
}
