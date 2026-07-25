"""Enterprise security intelligence: software inventory, SSPM, ASPM, risk register.

Tables:
  software_packages      — npm/pip/apt/brew/gem/go package inventory per asset
  package_vulnerabilities — CVE ↔ package version linkage (enriched from OSV/NVD)
  sspm_findings          — SaaS Security Posture (Okta/GitHub/Slack/Salesforce/M365)
  aspm_scans             — Application security scan runs per product
  aspm_findings          — Individual SAST/SCA/DAST/secrets/container findings
  risk_register          — Central risk registry aggregating all security tool outputs

Revision ID: 013_enterprise_security_intelligence
Revises: 012_joti_audit_events
Create Date: 2026-07-24
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "013_sec_intel"
down_revision: Union[str, Sequence[str], None] = "012_joti_audit_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── software_packages ────────────────────────────────────────────────────
    op.create_table(
        "software_packages",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("hardware_asset_id", UUID(as_uuid=True), sa.ForeignKey("cmdb_hardware_assets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("simulated_endpoint_id", UUID(as_uuid=True), sa.ForeignKey("simulated_endpoints.id", ondelete="CASCADE"), nullable=True),
        sa.Column("package_name", sa.String(200), nullable=False),
        sa.Column("package_version", sa.String(100), nullable=False),
        sa.Column("package_manager", sa.String(30), nullable=False),  # npm/pip/apt/brew/gem/go/maven/cargo/nuget
        sa.Column("ecosystem", sa.String(30), nullable=True),  # node/python/linux/macos/java/rust/dotnet
        sa.Column("install_path", sa.String(500), nullable=True),
        sa.Column("is_direct", sa.Boolean, server_default="true"),  # vs transitive dependency
        sa.Column("is_dev_dependency", sa.Boolean, server_default="false"),
        sa.Column("license", sa.String(100), nullable=True),
        sa.Column("publisher", sa.String(200), nullable=True),
        sa.Column("source_file", sa.String(500), nullable=True),  # package.json / requirements.txt / pom.xml
        sa.Column("last_seen_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("discovered_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()")),
    )
    op.create_index("ix_swpkg_asset", "software_packages", ["hardware_asset_id"])
    op.create_index("ix_swpkg_endpoint", "software_packages", ["simulated_endpoint_id"])
    op.create_index("ix_swpkg_name_ver", "software_packages", ["package_name", "package_version"])
    op.create_index("ix_swpkg_ecosystem", "software_packages", ["ecosystem"])
    op.create_index("ix_swpkg_mgr", "software_packages", ["package_manager"])

    # ── package_vulnerabilities ──────────────────────────────────────────────
    op.create_table(
        "package_vulnerabilities",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("vuln_id", UUID(as_uuid=True), sa.ForeignKey("vm_vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_name", sa.String(200), nullable=False),
        sa.Column("ecosystem", sa.String(30), nullable=False),  # npm/pypi/maven/cargo/nuget/gem/go
        sa.Column("affected_version_range", sa.String(200), nullable=True),  # ">= 1.0.0, < 2.1.3"
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Column("introduced_version", sa.String(100), nullable=True),
        sa.Column("advisory_url", sa.String(500), nullable=True),
        sa.Column("advisory_id", sa.String(100), nullable=True),  # GHSA-xxxx-xxxx, npm advisory, etc.
        sa.Column("source", sa.String(50), nullable=True),  # osv/nvd/github-advisory/npm-advisory/snyk
        sa.Column("severity_override", sa.String(15), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()")),
        sa.UniqueConstraint("vuln_id", "package_name", "ecosystem", name="uq_pkgvuln_vuln_pkg_eco"),
    )
    op.create_index("ix_pkgvuln_name_eco", "package_vulnerabilities", ["package_name", "ecosystem"])
    op.create_index("ix_pkgvuln_vuln", "package_vulnerabilities", ["vuln_id"])

    # ── sspm_findings ────────────────────────────────────────────────────────
    op.create_table(
        "sspm_findings",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("saas_app", sa.String(50), nullable=False),  # okta/github/slack/salesforce/m365/gsuite/zoom/jira/confluence
        sa.Column("cloud_account_id", UUID(as_uuid=True), sa.ForeignKey("product_registry_cloud_accounts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("control_id", sa.String(100), nullable=False),  # e.g. OKTA-MFA-001, GH-SEC-003
        sa.Column("control_name", sa.String(300), nullable=False),
        sa.Column("control_framework", sa.String(100), nullable=True),  # CIS/NIST/SCF/CSA
        sa.Column("category", sa.String(100), nullable=True),  # identity/access/data/config/network
        sa.Column("severity", sa.String(15), nullable=False),  # critical/high/medium/low/info
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),  # open/resolved/accepted_risk/in_remediation
        sa.Column("affected_entity_type", sa.String(50), nullable=True),  # user/group/app/setting/repo/policy
        sa.Column("affected_entity_id", sa.String(500), nullable=True),  # the actual entity name/id
        sa.Column("finding_details", JSONB, nullable=True),  # scanner-specific detail blob
        sa.Column("remediation_steps", sa.Text, nullable=True),
        sa.Column("first_detected_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("scanner", sa.String(100), nullable=True),  # wing/obsidian/adaptive-shield/orca/manual
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()")),
    )
    op.create_index("ix_sspm_app", "sspm_findings", ["saas_app"])
    op.create_index("ix_sspm_severity", "sspm_findings", ["severity"])
    op.create_index("ix_sspm_status", "sspm_findings", ["status"])
    op.create_index("ix_sspm_control", "sspm_findings", ["control_id"])

    # ── aspm_scans ───────────────────────────────────────────────────────────
    op.create_table(
        "aspm_scans",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("product_id", UUID(as_uuid=True), sa.ForeignKey("product_registry_products.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_type", sa.String(30), nullable=False),  # sast/sca/dast/secrets/container/iac
        sa.Column("scanner", sa.String(100), nullable=False),  # snyk/sonarqube/semgrep/trivy/ghas/checkov/grype
        sa.Column("branch", sa.String(200), nullable=True),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("pipeline_run_id", sa.String(200), nullable=True),
        sa.Column("scan_duration_seconds", sa.Integer, nullable=True),
        sa.Column("files_scanned", sa.Integer, nullable=True),
        sa.Column("findings_critical", sa.Integer, server_default="0"),
        sa.Column("findings_high", sa.Integer, server_default="0"),
        sa.Column("findings_medium", sa.Integer, server_default="0"),
        sa.Column("findings_low", sa.Integer, server_default="0"),
        sa.Column("findings_info", sa.Integer, server_default="0"),
        sa.Column("quality_gate_passed", sa.Boolean, nullable=True),
        sa.Column("scan_metadata", JSONB, nullable=True),
        sa.Column("scanned_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
    )
    op.create_index("ix_aspm_scan_product", "aspm_scans", ["product_id"])
    op.create_index("ix_aspm_scan_type", "aspm_scans", ["scan_type"])
    op.create_index("ix_aspm_scan_date", "aspm_scans", ["scanned_at"])

    # ── aspm_findings ────────────────────────────────────────────────────────
    op.create_table(
        "aspm_findings",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("aspm_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("product_id", UUID(as_uuid=True), sa.ForeignKey("product_registry_products.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=True),
        sa.Column("advisory_id", sa.String(100), nullable=True),  # GHSA-xxxx / npm advisory
        sa.Column("rule_id", sa.String(200), nullable=True),  # scanner rule/pattern ID
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(15), nullable=False),
        sa.Column("scan_type", sa.String(30), nullable=False),
        sa.Column("category", sa.String(100), nullable=True),  # sql-injection/xss/hardcoded-secret/outdated-dep/misconfig
        sa.Column("cwe_id", sa.String(30), nullable=True),
        sa.Column("owasp_category", sa.String(50), nullable=True),  # A01-A10
        sa.Column("file_path", sa.String(1000), nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("package_name", sa.String(200), nullable=True),  # for SCA findings
        sa.Column("package_version", sa.String(100), nullable=True),
        sa.Column("fixed_in_version", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),  # open/in_remediation/resolved/accepted_risk/false_positive
        sa.Column("suppressed", sa.Boolean, server_default="false"),
        sa.Column("first_seen_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("remediation_pr", sa.String(500), nullable=True),  # PR URL
        sa.Column("finding_metadata", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()")),
    )
    op.create_index("ix_aspm_finding_product", "aspm_findings", ["product_id"])
    op.create_index("ix_aspm_finding_severity", "aspm_findings", ["severity"])
    op.create_index("ix_aspm_finding_status", "aspm_findings", ["status"])
    op.create_index("ix_aspm_finding_cve", "aspm_findings", ["cve_id"])
    op.create_index("ix_aspm_finding_scan", "aspm_findings", ["scan_id"])

    # ── risk_register ────────────────────────────────────────────────────────
    op.create_table(
        "risk_register",
        sa.Column("id", UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("risk_ref", sa.String(30), nullable=True),  # RR-2026-0001
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("source", sa.String(30), nullable=False),  # cspm/sspm/aspm/vm/pen_test/threat_intel/manual
        sa.Column("source_finding_id", sa.String(200), nullable=True),  # external reference
        sa.Column("risk_category", sa.String(50), nullable=False),  # infrastructure/application/identity/data/supply_chain/vendor/compliance
        sa.Column("threat_vector", sa.String(200), nullable=True),  # e.g. "external/internet/ransomware"
        sa.Column("affected_asset_id", UUID(as_uuid=True), sa.ForeignKey("cmdb_hardware_assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("affected_product_id", UUID(as_uuid=True), sa.ForeignKey("product_registry_products.id", ondelete="SET NULL"), nullable=True),
        sa.Column("affected_cloud_account_id", UUID(as_uuid=True), sa.ForeignKey("product_registry_cloud_accounts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("likelihood", sa.Integer, nullable=False),  # 1-5
        sa.Column("impact", sa.Integer, nullable=False),  # 1-5
        sa.Column("risk_score", sa.Integer, nullable=False),  # likelihood × impact (1-25)
        sa.Column("inherent_risk_score", sa.Integer, nullable=True),  # before controls
        sa.Column("residual_risk_score", sa.Integer, nullable=True),  # after controls
        sa.Column("risk_treatment", sa.String(20), nullable=True),  # accept/mitigate/transfer/avoid
        sa.Column("treatment_notes", sa.Text, nullable=True),
        sa.Column("control_ids", JSONB, nullable=True),  # list of control references
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),  # open/in_treatment/accepted/closed/transferred
        sa.Column("priority", sa.String(10), nullable=True),  # P1/P2/P3/P4
        sa.Column("owner_id", UUID(as_uuid=True), sa.ForeignKey("cmdb_people.id", ondelete="SET NULL"), nullable=True),
        sa.Column("review_date", sa.DateTime, nullable=True),
        sa.Column("target_remediation_date", sa.DateTime, nullable=True),
        sa.Column("compliance_frameworks", JSONB, nullable=True),  # ["SOC2","ISO27001","PCI-DSS"]
        sa.Column("tags", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime, server_default=sa.text("now()")),
    )
    op.create_index("ix_rr_status", "risk_register", ["status"])
    op.create_index("ix_rr_score", "risk_register", ["risk_score"])
    op.create_index("ix_rr_source", "risk_register", ["source"])
    op.create_index("ix_rr_category", "risk_register", ["risk_category"])
    op.create_index("ix_rr_product", "risk_register", ["affected_product_id"])
    op.create_index("ix_rr_cloud", "risk_register", ["affected_cloud_account_id"])
    op.create_index("ix_rr_owner", "risk_register", ["owner_id"])


def downgrade() -> None:
    op.drop_table("risk_register")
    op.drop_table("aspm_findings")
    op.drop_table("aspm_scans")
    op.drop_table("sspm_findings")
    op.drop_table("package_vulnerabilities")
    op.drop_table("software_packages")
