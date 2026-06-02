"""Enterprise CMDB, Product Registry, Vulnerability Management, CSPM

Revision ID: 004_enterprise_cmdb_vm_cspm
Revises: 003_security_simulation_api
Create Date: 2026-06-02

Creates 8 tables:
  cmdb_people               — HR directory (employees + contractors)
  cmdb_hardware_assets      — Laptops, Macs, phones, tablets, servers
  product_registry_cloud_accounts — AWS/Azure/GCP account inventory
  product_registry_products — All products (vendor + internal custom)
  vm_vulnerabilities        — CVE library with CVSS/EPSS/KEV enrichment
  vm_asset_vulnerabilities  — Many-to-many: vuln -> hardware asset or product
  cspm_checks               — Check catalog (CIS, NIST, SOC2, PCI-DSS)
  cspm_findings             — Per-resource misconfiguration findings
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade():
    # ── cmdb_people ─────────────────────────────────────────────────────────
    op.create_table('cmdb_people',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('employee_id', sa.String(20), nullable=False, unique=True),
        sa.Column('first_name', sa.String(100), nullable=False),
        sa.Column('last_name', sa.String(100), nullable=False),
        sa.Column('email', sa.String(200), nullable=False, unique=True),
        sa.Column('phone', sa.String(50)),
        sa.Column('department', sa.String(100)),
        sa.Column('title', sa.String(150)),
        sa.Column('employment_type', sa.String(20), default='employee'),  # employee|contractor|intern
        sa.Column('manager_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('location', sa.String(100)),
        sa.Column('status', sa.String(20), default='active'),  # active|on_leave|terminated
        sa.Column('hire_date', sa.Date),
        sa.Column('slack_handle', sa.String(100)),
        sa.Column('avatar_initials', sa.String(4)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_cmdb_people_department', 'cmdb_people', ['department'])
    op.create_index('ix_cmdb_people_status', 'cmdb_people', ['status'])
    op.create_index('ix_cmdb_people_manager_id', 'cmdb_people', ['manager_id'])

    # ── cmdb_hardware_assets ─────────────────────────────────────────────────
    op.create_table('cmdb_hardware_assets',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('asset_tag', sa.String(50), nullable=False, unique=True),
        sa.Column('asset_type', sa.String(30), nullable=False),  # laptop|mac|windows_laptop|phone|tablet|server|workstation
        sa.Column('make', sa.String(80)),   # Apple|Dell|Lenovo|HP|Microsoft|Samsung
        sa.Column('model', sa.String(150)),
        sa.Column('serial_number', sa.String(100)),
        sa.Column('purchase_date', sa.Date),
        sa.Column('warranty_expires', sa.Date),
        sa.Column('os_type', sa.String(30)),    # macOS|Windows|iOS|Android|Linux
        sa.Column('os_version', sa.String(50)),
        sa.Column('status', sa.String(20), default='assigned'),  # assigned|in_stock|in_repair|retired|lost
        sa.Column('assigned_to_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('assigned_date', sa.Date),
        sa.Column('location', sa.String(100)),
        sa.Column('specs', JSONB, default=dict),   # {cpu, ram_gb, storage_gb, screen_size}
        sa.Column('tags', JSONB, default=dict),
        sa.Column('notes', sa.Text),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_cmdb_hardware_asset_type', 'cmdb_hardware_assets', ['asset_type'])
    op.create_index('ix_cmdb_hardware_status', 'cmdb_hardware_assets', ['status'])
    op.create_index('ix_cmdb_hardware_assigned_to', 'cmdb_hardware_assets', ['assigned_to_id'])

    # ── product_registry_cloud_accounts ─────────────────────────────────────
    op.create_table('product_registry_cloud_accounts',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('cloud_provider', sa.String(10), nullable=False),  # aws|azure|gcp
        sa.Column('account_id', sa.String(50), nullable=False),       # 123456789012 (AWS), subscription-id (Azure), project-id (GCP)
        sa.Column('account_name', sa.String(150), nullable=False),
        sa.Column('account_type', sa.String(30), default='production'),  # production|staging|development|shared_services|security|sandbox
        sa.Column('environment', sa.String(20), default='prod'),         # prod|staging|dev|sandbox
        sa.Column('region_primary', sa.String(50)),
        sa.Column('regions', JSONB, default=list),
        sa.Column('owner_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('technical_lead_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('billing_email', sa.String(200)),
        sa.Column('monthly_cost_usd', sa.Float, default=0.0),
        sa.Column('tags', JSONB, default=dict),
        sa.Column('mfa_enabled', sa.Boolean, default=True),
        sa.Column('cloudtrail_enabled', sa.Boolean, default=True),   # CloudTrail / Activity Log / Audit Log
        sa.Column('security_hub_enabled', sa.Boolean, default=False),
        sa.Column('status', sa.String(20), default='active'),  # active|suspended|closed
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_cloud_accounts_provider', 'product_registry_cloud_accounts', ['cloud_provider'])
    op.create_index('ix_cloud_accounts_type', 'product_registry_cloud_accounts', ['account_type'])

    # ── product_registry_products ────────────────────────────────────────────
    op.create_table('product_registry_products',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),
        sa.Column('product_type', sa.String(30), default='internal'),    # internal|vendor_saas|vendor_on_prem|open_source
        sa.Column('category', sa.String(50)),                             # security|infrastructure|business|developer_tool|data|communication
        sa.Column('tier', sa.String(20), default='tier2_important'),      # tier1_critical|tier2_important|tier3_standard|tier4_low
        sa.Column('description', sa.Text),
        sa.Column('owner_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('tech_lead_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('team', sa.String(100)),
        sa.Column('url_production', sa.String(500)),
        sa.Column('url_staging', sa.String(500)),
        sa.Column('url_docs', sa.String(500)),
        sa.Column('url_repo', sa.String(500)),
        sa.Column('status', sa.String(20), default='active'),             # active|deprecated|sunset|planned
        sa.Column('data_classification', sa.String(20), default='internal'),  # public|internal|confidential|secret
        sa.Column('pii_data', sa.Boolean, default=False),
        sa.Column('phi_data', sa.Boolean, default=False),   # Protected Health Information
        sa.Column('pci_data', sa.Boolean, default=False),   # Payment Card data
        sa.Column('compliance_frameworks', JSONB, default=list),  # [SOC2, HIPAA, PCI-DSS, GDPR, ISO27001]
        sa.Column('tech_stack', JSONB, default=list),              # [Python, FastAPI, PostgreSQL, Redis, Docker]
        sa.Column('deployment_model', sa.String(20), default='cloud'),    # cloud|on_prem|hybrid|saas
        sa.Column('cloud_account_id', UUID(as_uuid=True), sa.ForeignKey('product_registry_cloud_accounts.id'), nullable=True),
        sa.Column('server_names', JSONB, default=list),
        sa.Column('container_names', JSONB, default=list),
        sa.Column('k8s_namespace', sa.String(100)),
        sa.Column('database_types', JSONB, default=list),
        sa.Column('annual_cost_usd', sa.Float, default=0.0),
        sa.Column('vendor_name', sa.String(150)),
        sa.Column('vendor_contract_expires', sa.Date),
        sa.Column('sla_uptime_target', sa.Float, default=99.9),
        sa.Column('on_call_slack_channel', sa.String(100)),
        sa.Column('incident_runbook_url', sa.String(500)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_products_category', 'product_registry_products', ['category'])
    op.create_index('ix_products_tier', 'product_registry_products', ['tier'])
    op.create_index('ix_products_type', 'product_registry_products', ['product_type'])
    op.create_index('ix_products_status', 'product_registry_products', ['status'])
    op.create_index('ix_products_cloud_account', 'product_registry_products', ['cloud_account_id'])

    # ── vm_vulnerabilities ───────────────────────────────────────────────────
    op.create_table('vm_vulnerabilities',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('cve_id', sa.String(30), unique=True),       # CVE-2024-1234 (nullable for non-CVE findings)
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('cvss_score', sa.Float),
        sa.Column('cvss_vector', sa.String(200)),
        sa.Column('severity', sa.String(15), nullable=False),  # critical|high|medium|low|informational
        sa.Column('cwe_id', sa.String(30)),                    # CWE-79, CWE-89, etc.
        sa.Column('affected_component', sa.String(200)),       # OpenSSL 3.x, Apache Log4j 2.x
        sa.Column('affected_versions', JSONB, default=list),
        sa.Column('fixed_version', sa.String(100)),
        sa.Column('epss_score', sa.Float, default=0.0),        # 0.0 to 1.0, probability of exploitation
        sa.Column('cisa_kev', sa.Boolean, default=False),      # In CISA Known Exploited Vulnerabilities list
        sa.Column('exploit_public', sa.Boolean, default=False),
        sa.Column('exploit_type', sa.String(100)),             # remote_code_execution|privilege_escalation|info_disclosure|dos
        sa.Column('attack_vector', sa.String(20)),             # network|adjacent|local|physical
        sa.Column('attack_complexity', sa.String(10)),         # low|high
        sa.Column('references', JSONB, default=list),          # NVD URLs, vendor advisories
        sa.Column('nvd_published_at', sa.DateTime),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_vulns_severity', 'vm_vulnerabilities', ['severity'])
    op.create_index('ix_vulns_cisa_kev', 'vm_vulnerabilities', ['cisa_kev'])
    op.create_index('ix_vulns_epss', 'vm_vulnerabilities', ['epss_score'])

    # ── vm_asset_vulnerabilities ─────────────────────────────────────────────
    op.create_table('vm_asset_vulnerabilities',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('vuln_id', UUID(as_uuid=True), sa.ForeignKey('vm_vulnerabilities.id'), nullable=False),
        sa.Column('asset_type', sa.String(20), nullable=False),   # hardware|product
        sa.Column('hardware_asset_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_hardware_assets.id'), nullable=True),
        sa.Column('product_id', UUID(as_uuid=True), sa.ForeignKey('product_registry_products.id'), nullable=True),
        sa.Column('status', sa.String(20), default='open'),       # open|in_remediation|resolved|accepted_risk|false_positive
        sa.Column('severity_override', sa.String(15), nullable=True),
        sa.Column('risk_score', sa.Float, default=0.0),           # 0-100, computed
        sa.Column('assigned_to_id', UUID(as_uuid=True), sa.ForeignKey('cmdb_people.id'), nullable=True),
        sa.Column('discovered_at', sa.DateTime, nullable=False),
        sa.Column('remediation_due_date', sa.DateTime),
        sa.Column('resolved_at', sa.DateTime, nullable=True),
        sa.Column('scan_source', sa.String(50)),    # tenable|qualys|wiz|snyk|manual|crowdstrike
        sa.Column('notes', sa.Text),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_asset_vulns_vuln_id', 'vm_asset_vulnerabilities', ['vuln_id'])
    op.create_index('ix_asset_vulns_hardware', 'vm_asset_vulnerabilities', ['hardware_asset_id'])
    op.create_index('ix_asset_vulns_product', 'vm_asset_vulnerabilities', ['product_id'])
    op.create_index('ix_asset_vulns_status', 'vm_asset_vulnerabilities', ['status'])
    op.create_index('ix_asset_vulns_assigned', 'vm_asset_vulnerabilities', ['assigned_to_id'])

    # ── cspm_checks ──────────────────────────────────────────────────────────
    op.create_table('cspm_checks',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('check_id', sa.String(50), nullable=False, unique=True),  # CIS-AWS-1.1, SOC2-CC6.1, etc.
        sa.Column('framework', sa.String(30), nullable=False),   # CIS_AWS_v3|CIS_AZURE_v2|CIS_GCP_v2|SOC2|NIST_CSF|PCI_DSS_v4|GDPR|ISO27001
        sa.Column('cloud_provider', sa.String(10)),               # aws|azure|gcp|all
        sa.Column('section', sa.String(50)),                      # IAM|Network|Logging|Storage|Encryption|Compute|Container|Database|Data
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('remediation_steps', sa.Text),
        sa.Column('severity', sa.String(15), nullable=False),     # critical|high|medium|low
        sa.Column('automated', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_cspm_checks_framework', 'cspm_checks', ['framework'])
    op.create_index('ix_cspm_checks_section', 'cspm_checks', ['section'])
    op.create_index('ix_cspm_checks_provider', 'cspm_checks', ['cloud_provider'])

    # ── cspm_findings ────────────────────────────────────────────────────────
    op.create_table('cspm_findings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('check_id', sa.Integer, sa.ForeignKey('cspm_checks.id'), nullable=False),
        sa.Column('cloud_account_id', UUID(as_uuid=True), sa.ForeignKey('product_registry_cloud_accounts.id'), nullable=False),
        sa.Column('product_id', UUID(as_uuid=True), sa.ForeignKey('product_registry_products.id'), nullable=True),
        sa.Column('resource_id', sa.String(500), nullable=False),   # ARN, resource path, or unique ID
        sa.Column('resource_type', sa.String(100)),                  # aws_s3_bucket|azurerm_security_group|google_compute_instance
        sa.Column('resource_name', sa.String(300)),
        sa.Column('region', sa.String(50)),
        sa.Column('status', sa.String(20), default='open'),          # open|resolved|suppressed|in_remediation
        sa.Column('severity', sa.String(15), nullable=False),
        sa.Column('title', sa.String(300)),
        sa.Column('description', sa.Text),
        sa.Column('evidence', JSONB, default=dict),                  # raw API response, config snapshot
        sa.Column('remediation_effort', sa.String(10), default='low'),  # low|medium|high
        sa.Column('first_seen_at', sa.DateTime, nullable=False),
        sa.Column('last_seen_at', sa.DateTime, nullable=False),
        sa.Column('resolved_at', sa.DateTime, nullable=True),
        sa.Column('suppressed_reason', sa.String(300)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('ix_cspm_findings_account', 'cspm_findings', ['cloud_account_id'])
    op.create_index('ix_cspm_findings_product', 'cspm_findings', ['product_id'])
    op.create_index('ix_cspm_findings_status', 'cspm_findings', ['status'])
    op.create_index('ix_cspm_findings_severity', 'cspm_findings', ['severity'])
    op.create_index('ix_cspm_findings_check', 'cspm_findings', ['check_id'])


def downgrade():
    op.drop_table('cspm_findings')
    op.drop_table('cspm_checks')
    op.drop_table('vm_asset_vulnerabilities')
    op.drop_table('vm_vulnerabilities')
    op.drop_table('product_registry_products')
    op.drop_table('product_registry_cloud_accounts')
    op.drop_table('cmdb_hardware_assets')
    op.drop_table('cmdb_people')
