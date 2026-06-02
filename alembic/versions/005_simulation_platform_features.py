"""Simulation platform features — environment templates, threat profiles, sigma library, normalization schemas

Revision ID: 005
Revises: 004
Create Date: 2026-06-02
"""
import json
import uuid as _uuid_mod
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── environment_templates ──────────────────────────────────────────────────
    op.create_table(
        "environment_templates",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("topology", JSONB, nullable=False, server_default="{}"),
        sa.Column("default_log_sources", JSONB, nullable=False, server_default="[]"),
        sa.Column("default_settings", JSONB, nullable=False, server_default="{}"),
        sa.Column("icon", sa.String(50), nullable=True),
        sa.Column("is_builtin", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ── environment_threat_profiles ────────────────────────────────────────────
    op.create_table(
        "environment_threat_profiles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", UUID(as_uuid=True), sa.ForeignKey("environments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("profile_type", sa.String(30), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("data", JSONB, nullable=False, server_default="{}"),
        sa.Column("source", sa.String(50), nullable=False, server_default="manual"),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_env_threat_profiles_env_id", "environment_threat_profiles", ["environment_id"])

    # ── sigma_rule_sources ─────────────────────────────────────────────────────
    op.create_table(
        "sigma_rule_sources",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("github_url", sa.String(500), nullable=False),
        sa.Column("github_api_path", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_synced_at", sa.DateTime, nullable=True),
        sa.Column("rule_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ── sigma_library_rules ────────────────────────────────────────────────────
    op.create_table(
        "sigma_library_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source_id", sa.Integer, sa.ForeignKey("sigma_rule_sources.id"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("rule_yaml", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="stable"),
        sa.Column("level", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("product", sa.String(100), nullable=True),
        sa.Column("service", sa.String(100), nullable=True),
        sa.Column("technique_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("tags", JSONB, nullable=False, server_default="[]"),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("added_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sigma_library_rules_sha256", "sigma_library_rules", ["sha256"])
    op.create_index("ix_sigma_library_rules_level", "sigma_library_rules", ["level"])
    op.create_index("ix_sigma_library_rules_source_id", "sigma_library_rules", ["source_id"])

    # ── session_sigma_rules ────────────────────────────────────────────────────
    op.create_table(
        "session_sigma_rules",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("simulation_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sigma_rule_id", UUID(as_uuid=True), sa.ForeignKey("sigma_library_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("deployed_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("deployed_by", sa.String(255), nullable=True),
    )
    op.create_unique_constraint("uq_session_sigma_rules", "session_sigma_rules", ["session_id", "sigma_rule_id"])

    # ── normalization_schemas ──────────────────────────────────────────────────
    op.create_table(
        "normalization_schemas",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version_label", sa.String(100), nullable=False),
        sa.Column("siem_platform", sa.String(50), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("fields", JSONB, nullable=False, server_default="[]"),
        sa.Column("datasets", JSONB, nullable=False, server_default="[]"),
        sa.Column("data_models", JSONB, nullable=False, server_default="[]"),
        sa.Column("ai_parsed", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("ai_parse_notes", sa.Text, nullable=True),
        sa.Column("source_file_name", sa.String(255), nullable=True),
        sa.Column("source_format", sa.String(20), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # ── normalization_schema_versions ──────────────────────────────────────────
    op.create_table(
        "normalization_schema_versions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("schema_id", UUID(as_uuid=True), sa.ForeignKey("normalization_schemas.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version_num", sa.Integer, nullable=False, server_default="1"),
        sa.Column("version_label", sa.String(100), nullable=False),
        sa.Column("fields_snapshot", JSONB, nullable=False, server_default="[]"),
        sa.Column("datasets_snapshot", JSONB, nullable=False, server_default="[]"),
        sa.Column("data_models_snapshot", JSONB, nullable=False, server_default="[]"),
        sa.Column("change_summary", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_norm_schema_versions_schema_id", "normalization_schema_versions", ["schema_id"])

    # ── seed built-in sigma sources ────────────────────────────────────────────
    conn = op.get_bind()
    sigma_sources = [
        ("SigmaHQ Core Rules", "https://github.com/SigmaHQ/sigma", "SigmaHQ/sigma/rules", "Official SigmaHQ detection rule repository — the gold standard", True),
        ("SOCPRIME Detection as Code", "https://github.com/socprime/the-prime-hunt", "socprime/the-prime-hunt", "SOC Prime community detection rules", True),
        ("Elastic Detection Rules", "https://github.com/elastic/detection-rules", "elastic/detection-rules/rules", "Elastic Security detection rules in EQL/KQL/Sigma", True),
        ("Splunk Security Content", "https://github.com/splunk/security_content", "splunk/security_content/detections", "Splunk ESCU — Enterprise Security Content Update detections", True),
        ("Microsoft Sentinel Rules", "https://github.com/Azure/Azure-Sentinel", "Azure/Azure-Sentinel/Detections", "Microsoft Sentinel community analytic rules", True),
        ("Florian Roth Sigma Rules", "https://github.com/Neo23x0/sigma", "Neo23x0/sigma/rules", "Florian Roth original sigma rules — pioneering collection", True),
        ("Chronicle Detection Rules", "https://github.com/chronicle/detection-rules", "chronicle/detection-rules", "Google Chronicle YARA-L and Sigma rules", True),
        ("MITRE Cyber Analytics Repository", "https://github.com/mitre-attack/car", "mitre-attack/car/analytics", "MITRE CAR analytics mapped to ATT&CK framework", True),
        ("Hayabusa Rules", "https://github.com/Yamato-Security/hayabusa-rules", "Yamato-Security/hayabusa-rules/sigma", "Hayabusa fast forensics and threat hunting rules for Windows", True),
        ("Valhalla Community Rules", "https://github.com/NextronSystems/valhalla-rules", "NextronSystems/valhalla-rules/sigma", "Nextron Systems Valhalla community Sigma rules", False),
    ]
    conn.execute(
        sa.text("INSERT INTO sigma_rule_sources (name, github_url, github_api_path, description, enabled) VALUES (:n, :u, :a, :d, :e)"),
        [{"n": n, "u": u, "a": a, "d": d, "e": e} for n, u, a, d, e in sigma_sources],
    )

    # ── seed built-in environment templates ────────────────────────────────────
    templates = [
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Enterprise Windows Domain",
            "slug": "windows-domain",
            "category": "endpoint",
            "description": "Active Directory domain with Windows endpoints, domain controller, and Sysmon telemetry.",
            "topology": json.dumps({"nodes": [{"id": "dc1", "type": "server", "position": {"x": 300, "y": 100}, "data": {"label": "Domain Controller", "nodeType": "domain_controller", "os": "Windows Server 2022"}}, {"id": "ws1", "type": "server", "position": {"x": 100, "y": 280}, "data": {"label": "Workstation 1", "nodeType": "workstation", "os": "Windows 11", "sysmon": True}}, {"id": "ws2", "type": "server", "position": {"x": 300, "y": 280}, "data": {"label": "Workstation 2", "nodeType": "workstation", "os": "Windows 10", "sysmon": True}}, {"id": "fs1", "type": "server", "position": {"x": 500, "y": 280}, "data": {"label": "File Server", "nodeType": "file_server", "os": "Windows Server 2019"}}], "edges": [{"id": "e1", "source": "dc1", "target": "ws1"}, {"id": "e2", "source": "dc1", "target": "ws2"}, {"id": "e3", "source": "dc1", "target": "fs1"}]}),
            "default_log_sources": json.dumps(["windows_security", "windows_system", "sysmon", "powershell"]),
            "default_settings": json.dumps({"siem_platform": "splunk", "log_volume": "medium"}),
            "icon": "Monitor",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Kubernetes Cluster",
            "slug": "kubernetes-cluster",
            "category": "k8s",
            "description": "Multi-node Kubernetes cluster with API server, worker nodes, etcd, and container runtime logs.",
            "topology": json.dumps({"nodes": [{"id": "api", "type": "server", "position": {"x": 300, "y": 80}, "data": {"label": "API Server", "nodeType": "k8s_apiserver", "version": "1.29"}}, {"id": "etcd", "type": "server", "position": {"x": 150, "y": 80}, "data": {"label": "etcd", "nodeType": "k8s_etcd"}}, {"id": "node1", "type": "server", "position": {"x": 100, "y": 260}, "data": {"label": "Worker Node 1", "nodeType": "k8s_node", "runtime": "containerd"}}, {"id": "node2", "type": "server", "position": {"x": 300, "y": 260}, "data": {"label": "Worker Node 2", "nodeType": "k8s_node", "runtime": "containerd"}}, {"id": "node3", "type": "server", "position": {"x": 500, "y": 260}, "data": {"label": "Worker Node 3", "nodeType": "k8s_node", "runtime": "containerd"}}], "edges": [{"id": "e1", "source": "api", "target": "etcd"}, {"id": "e2", "source": "api", "target": "node1"}, {"id": "e3", "source": "api", "target": "node2"}, {"id": "e4", "source": "api", "target": "node3"}]}),
            "default_log_sources": json.dumps(["kubernetes_audit", "container_runtime", "falco", "kube_apiserver"]),
            "default_settings": json.dumps({"siem_platform": "elastic", "log_volume": "high"}),
            "icon": "Cloud",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Cloud Infrastructure (AWS)",
            "slug": "aws-cloud",
            "category": "cspm",
            "description": "AWS cloud environment with VPC, EC2 instances, S3 buckets, IAM, and CloudTrail.",
            "topology": json.dumps({"nodes": [{"id": "vpc", "type": "server", "position": {"x": 300, "y": 80}, "data": {"label": "VPC", "nodeType": "aws_vpc", "cidr": "10.0.0.0/16"}}, {"id": "ec2_1", "type": "server", "position": {"x": 150, "y": 240}, "data": {"label": "Web Server (EC2)", "nodeType": "aws_ec2", "instance_type": "t3.medium"}}, {"id": "ec2_2", "type": "server", "position": {"x": 350, "y": 240}, "data": {"label": "App Server (EC2)", "nodeType": "aws_ec2", "instance_type": "t3.large"}}, {"id": "rds", "type": "server", "position": {"x": 550, "y": 240}, "data": {"label": "RDS PostgreSQL", "nodeType": "aws_rds"}}, {"id": "s3", "type": "server", "position": {"x": 50, "y": 400}, "data": {"label": "S3 Data Bucket", "nodeType": "aws_s3"}}, {"id": "iam", "type": "server", "position": {"x": 500, "y": 80}, "data": {"label": "IAM", "nodeType": "aws_iam"}}], "edges": [{"id": "e1", "source": "vpc", "target": "ec2_1"}, {"id": "e2", "source": "vpc", "target": "ec2_2"}, {"id": "e3", "source": "vpc", "target": "rds"}, {"id": "e4", "source": "ec2_1", "target": "s3"}, {"id": "e5", "source": "iam", "target": "ec2_1"}]}),
            "default_log_sources": json.dumps(["cloudtrail", "vpc_flow_logs", "guardduty", "config_rules", "s3_access_logs"]),
            "default_settings": json.dumps({"siem_platform": "splunk", "cloud_provider": "aws", "log_volume": "high"}),
            "icon": "Database",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Vulnerability Management",
            "slug": "vuln-management",
            "category": "vm",
            "description": "Enterprise vulnerability management environment with scanners, asset inventory, and patch management.",
            "topology": json.dumps({"nodes": [{"id": "scanner", "type": "server", "position": {"x": 300, "y": 80}, "data": {"label": "Vuln Scanner", "nodeType": "scanner", "product": "Tenable Nessus"}}, {"id": "asset1", "type": "server", "position": {"x": 100, "y": 260}, "data": {"label": "Webserver Fleet", "nodeType": "asset_group", "count": 45}}, {"id": "asset2", "type": "server", "position": {"x": 300, "y": 260}, "data": {"label": "Windows Servers", "nodeType": "asset_group", "count": 30}}, {"id": "asset3", "type": "server", "position": {"x": 500, "y": 260}, "data": {"label": "Network Devices", "nodeType": "asset_group", "count": 20}}], "edges": [{"id": "e1", "source": "scanner", "target": "asset1"}, {"id": "e2", "source": "scanner", "target": "asset2"}, {"id": "e3", "source": "scanner", "target": "asset3"}]}),
            "default_log_sources": json.dumps(["vulnerability_scanner", "patch_management", "asset_inventory"]),
            "default_settings": json.dumps({"siem_platform": "splunk", "scan_frequency": "weekly"}),
            "icon": "Shield",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "CMDB & HR Environment",
            "slug": "cmdb-hr",
            "category": "cmdb",
            "description": "Corporate CMDB with hardware asset inventory, HR system, and identity management.",
            "topology": json.dumps({"nodes": [{"id": "cmdb", "type": "server", "position": {"x": 300, "y": 80}, "data": {"label": "CMDB", "nodeType": "cmdb", "product": "ServiceNow"}}, {"id": "hr", "type": "server", "position": {"x": 100, "y": 240}, "data": {"label": "HR System", "nodeType": "hr_system", "product": "Workday"}}, {"id": "ad", "type": "server", "position": {"x": 300, "y": 240}, "data": {"label": "Active Directory", "nodeType": "domain_controller"}}, {"id": "idp", "type": "server", "position": {"x": 500, "y": 240}, "data": {"label": "Identity Provider", "nodeType": "idp", "product": "Okta"}}], "edges": [{"id": "e1", "source": "cmdb", "target": "hr"}, {"id": "e2", "source": "cmdb", "target": "ad"}, {"id": "e3", "source": "ad", "target": "idp"}]}),
            "default_log_sources": json.dumps(["servicenow_cmdb", "hr_audit_logs", "ad_events", "okta_logs"]),
            "default_settings": json.dumps({"siem_platform": "sentinel", "log_volume": "low"}),
            "icon": "Users",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Attack Surface Management",
            "slug": "attack-surface",
            "category": "asm",
            "description": "External attack surface with internet-facing assets, subdomains, and exposed services.",
            "topology": json.dumps({"nodes": [{"id": "domain", "type": "server", "position": {"x": 300, "y": 80}, "data": {"label": "Primary Domain", "nodeType": "domain", "fqdn": "corp.example.com"}}, {"id": "web", "type": "server", "position": {"x": 100, "y": 240}, "data": {"label": "Web App (DMZ)", "nodeType": "web_app", "waf": True}}, {"id": "vpn", "type": "server", "position": {"x": 300, "y": 240}, "data": {"label": "VPN Gateway", "nodeType": "vpn", "product": "Palo Alto GlobalProtect"}}, {"id": "mail", "type": "server", "position": {"x": 500, "y": 240}, "data": {"label": "Mail Gateway", "nodeType": "mail_relay", "product": "Proofpoint"}}, {"id": "cdn", "type": "server", "position": {"x": 200, "y": 400}, "data": {"label": "CDN Edge", "nodeType": "cdn", "provider": "Cloudflare"}}], "edges": [{"id": "e1", "source": "domain", "target": "web"}, {"id": "e2", "source": "domain", "target": "vpn"}, {"id": "e3", "source": "domain", "target": "mail"}, {"id": "e4", "source": "web", "target": "cdn"}]}),
            "default_log_sources": json.dumps(["waf_logs", "dns_logs", "network_flow", "ssl_inspection"]),
            "default_settings": json.dumps({"siem_platform": "splunk", "scan_frequency": "daily"}),
            "icon": "Globe",
            "is_builtin": True,
        },
        {
            "id": str(_uuid_mod.uuid4()),
            "name": "Product & Cloud Registry",
            "slug": "product-registry",
            "category": "product",
            "description": "SaaS product registry with cloud accounts, microservices, and SLA monitoring.",
            "topology": json.dumps({"nodes": [{"id": "prod1", "type": "server", "position": {"x": 150, "y": 80}, "data": {"label": "Product: Platform API", "nodeType": "product", "category": "api", "sla": "99.9%"}}, {"id": "prod2", "type": "server", "position": {"x": 400, "y": 80}, "data": {"label": "Product: Web App", "nodeType": "product", "category": "frontend", "sla": "99.5%"}}, {"id": "cloud1", "type": "server", "position": {"x": 100, "y": 260}, "data": {"label": "AWS Prod Account", "nodeType": "aws_account"}}, {"id": "cloud2", "type": "server", "position": {"x": 350, "y": 260}, "data": {"label": "GCP Analytics", "nodeType": "gcp_account"}}, {"id": "cloud3", "type": "server", "position": {"x": 580, "y": 180}, "data": {"label": "Azure AD Tenant", "nodeType": "azure_account"}}], "edges": [{"id": "e1", "source": "prod1", "target": "cloud1"}, {"id": "e2", "source": "prod2", "target": "cloud1"}, {"id": "e3", "source": "prod1", "target": "cloud2"}, {"id": "e4", "source": "prod2", "target": "cloud3"}]}),
            "default_log_sources": json.dumps(["api_gateway_logs", "cloudtrail", "gcp_audit", "azure_ad"]),
            "default_settings": json.dumps({"siem_platform": "elastic", "log_volume": "high"}),
            "icon": "Package",
            "is_builtin": True,
        },
    ]
    for t in templates:
        conn.execute(
            sa.text("""INSERT INTO environment_templates
                (id, name, slug, category, description, topology, default_log_sources, default_settings, icon, is_builtin)
                VALUES (:id, :name, :slug, :category, :description, cast(:topology as jsonb), cast(:dls as jsonb), cast(:ds as jsonb), :icon, :is_builtin)"""),
            {"id": t["id"], "name": t["name"], "slug": t["slug"], "category": t["category"],
             "description": t["description"], "topology": t["topology"], "dls": t["default_log_sources"],
             "ds": t["default_settings"], "icon": t["icon"], "is_builtin": t["is_builtin"]},
        )


def downgrade() -> None:
    op.drop_table("normalization_schema_versions")
    op.drop_table("normalization_schemas")
    op.drop_table("session_sigma_rules")
    op.drop_table("sigma_library_rules")
    op.drop_table("sigma_rule_sources")
    op.drop_table("environment_threat_profiles")
    op.drop_table("environment_templates")
