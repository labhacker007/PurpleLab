#!/usr/bin/env python3
"""Seed enterprise data: 500 people, 1500+ assets, 30 cloud accounts, 100 products,
200 CVEs, ~8000 vuln instances, 150 CSPM checks, ~4000 CSPM findings.

Run from inside the container:
  docker exec purplelab-backend python scripts/seed_enterprise_data.py
"""
from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timedelta

from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession

import sys, os
sys.path.insert(0, "/app")

from backend.db.session import async_session
from backend.db.models import (
    CMDBPerson, CMDBHardwareAsset,
    ProductCloudAccount, ProductRegistryProduct,
    VMVulnerability, VMAssetVulnerability,
    CSPMCheck, CSPMFinding,
)

rng = random.Random(42)

def uid() -> uuid.UUID:
    return uuid.uuid4()

def days_ago(n: int) -> datetime:
    return datetime.utcnow() - timedelta(days=n)

def days_from_now(n: int) -> datetime:
    return datetime.utcnow() + timedelta(days=n)

# ── People ────────────────────────────────────────────────────────────────────

DEPARTMENTS = [
    "Engineering", "Security", "Infrastructure", "Product", "Finance",
    "HR", "Legal", "Marketing", "Sales", "Executive",
]

TITLES_BY_DEPT = {
    "Engineering": [
        "Junior Software Engineer", "Software Engineer", "Senior Software Engineer",
        "Staff Engineer", "Principal Engineer", "Engineering Manager",
        "Senior Engineering Manager", "Director of Engineering",
        "VP Engineering", "Distinguished Engineer",
    ],
    "Security": [
        "Security Analyst I", "Security Analyst II", "Senior Security Analyst",
        "Security Engineer", "Senior Security Engineer", "Threat Hunter",
        "Penetration Tester", "Security Architect", "CISO", "Deputy CISO",
    ],
    "Infrastructure": [
        "Junior DevOps Engineer", "DevOps Engineer", "Senior DevOps Engineer",
        "SRE", "Senior SRE", "Platform Engineer", "Cloud Engineer",
        "Infrastructure Architect", "Head of Infrastructure", "VP of Infrastructure",
    ],
    "Product": [
        "Associate PM", "Product Manager", "Senior Product Manager",
        "Principal PM", "Group PM", "Director of Product", "VP of Product",
        "Head of Growth", "Product Lead", "Chief Product Officer",
    ],
    "Finance": [
        "Financial Analyst", "Senior Financial Analyst", "Finance Manager",
        "FP&A Manager", "Controller", "Senior Controller",
        "Director of Finance", "VP Finance", "CFO", "Treasury Analyst",
    ],
    "HR": [
        "HR Coordinator", "HR Generalist", "Senior HR Generalist",
        "HR Business Partner", "Senior HRBP", "Recruiter", "Senior Recruiter",
        "People Ops Manager", "VP of HR", "Chief People Officer",
    ],
    "Legal": [
        "Legal Analyst", "Counsel", "Senior Counsel",
        "Associate General Counsel", "General Counsel",
        "Privacy Counsel", "Compliance Analyst", "Compliance Manager",
        "Director of Legal", "VP Legal Affairs",
    ],
    "Marketing": [
        "Marketing Coordinator", "Marketing Manager", "Content Strategist",
        "SEO Specialist", "Demand Generation Manager", "Brand Manager",
        "Digital Marketing Manager", "Director of Marketing",
        "VP Marketing", "CMO",
    ],
    "Sales": [
        "Sales Development Rep", "Account Executive", "Senior AE",
        "Enterprise AE", "Sales Manager", "Senior Sales Manager",
        "Regional Sales Director", "VP of Sales", "Chief Revenue Officer",
        "Sales Engineer",
    ],
    "Executive": [
        "CEO", "CTO", "COO", "CFO", "CISO",
        "Chief of Staff", "VP Engineering", "VP Security",
        "SVP Engineering", "Board Member",
    ],
}

FIRST_NAMES = [
    "James","Maria","David","Sarah","Michael","Jennifer","Robert","Emily","William","Ashley",
    "John","Jessica","Christopher","Amanda","Daniel","Melissa","Matthew","Stephanie","Andrew","Rebecca",
    "Ryan","Nicole","Joshua","Lauren","Kevin","Megan","Brian","Amber","Justin","Rachel",
    "Brandon","Danielle","Tyler","Heather","Adam","Brittany","Jason","Christina","Eric","Amy",
    "Nathan","Kimberly","Patrick","Samantha","Timothy","Katherine","Aaron","Christine","Jose","Angela",
    "Kyle","Tiffany","Mark","Laura","Austin","Shannon","Benjamin","Courtney","Alex","Lisa",
    "Sean","Michelle","Ethan","Janet","Zachary","Sara","Derek","Alexis","Trevor","Kayla",
    "Carlos","Monica","Jake","Natalie","Ian","Vanessa","Connor","Alyssa","Jack","Diana",
    "Luke","Cynthia","Scott","Erica","Phillip","Beth","Victor","Priya","Aiden","Ananya",
    "Wei","Min","Arjun","Divya","Sanjay","Kavya","Liam","Zoe","Noah","Sofia",
    "Omar","Leila","Yusuf","Fatima","Chen","Xin","Mohammed","Nadia","Ivan","Elena",
    "Mateo","Isabella","Lucas","Valentina","Santiago","Camila","Andres","Gabriela","Rafael","Lucia",
    "Olivia","Lena","Felix","Hannah","Hugo","Mia","Leo","Emma","Jonas","Nina",
    "Kenji","Akiko","Hiroshi","Yuki","Takeshi","Haruto","Mei","Sakura","Ryo","Hana",
    "Kwame","Amara","Kofi","Abena","Adeola","Chidi","Ngozi","Emeka","Adaeze","Obinna",
    "Chloe","Dylan","Ella","Finn","Grace","Henry","Isla","Jake","Jasmine","Jordan",
    "Katherine","Logan","Maya","Miles","Olivia","Parker","Quinn","Riley","Skylar","Taylor",
    "Valentina","Wesley","Xiomara","Yara","Zara","Alec","Bella","Cameron","Daisy","Eli",
    "Florence","George","Harper","Isaac","Julia","Kai","Luna","Max","Naomi","Oscar",
    "Penelope","Quincy","Rose","Sam","Tessa","Uma","Violet","Wyatt","Xander","Yasmine",
]

LAST_NAMES = [
    "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Wilson","Anderson",
    "Taylor","Thomas","Jackson","White","Harris","Martin","Thompson","Young","Allen","King",
    "Wright","Scott","Green","Baker","Adams","Nelson","Hill","Ramirez","Campbell","Mitchell",
    "Roberts","Carter","Phillips","Evans","Turner","Torres","Parker","Collins","Edwards","Stewart",
    "Flores","Morris","Nguyen","Murphy","Rivera","Cook","Rogers","Morgan","Peterson","Cooper",
    "Reed","Bailey","Bell","Gomez","Kelly","Howard","Ward","Cox","Diaz","Richardson",
    "Wood","Watson","Brooks","Bennett","Gray","James","Reyes","Cruz","Hughes","Price",
    "Myers","Long","Foster","Sanders","Ross","Morales","Powell","Sullivan","Russell","Ortiz",
    "Jenkins","Gutierrez","Perry","Butler","Barnes","Fisher","Henderson","Coleman","Simmons","Patterson",
    "Jordan","Reynolds","Hamilton","Graham","Kim","Gonzalez","Alexander","Ramos","Wallace","Griffin",
    "West","Cole","Hayes","Chavez","Gibson","Bryant","Ellis","Stevens","Murray","Ford",
    "Marshall","Owens","McDonald","Harrison","Ruiz","Kennedy","Wells","Alvarez","Woods","Mendoza",
    "Chan","Lee","Park","Choi","Yamamoto","Tanaka","Sato","Watanabe","Ito","Nakamura",
    "Patel","Shah","Gupta","Sharma","Kumar","Singh","Mehta","Desai","Malhotra","Kapoor",
    "Okonkwo","Adeyemi","Ibrahim","Hassan","Nwosu","Mensah","Asante","Boateng","Osei","Ankrah",
    "Muller","Schmidt","Wagner","Fischer","Weber","Meyer","Klein","Schulz","Becker","Richter",
    "Dupont","Leroy","Moreau","Bernard","Petit","Roux","Simon","Laurent","Michel","Lefebvre",
    "Rossi","Ferrari","Russo","Marino","Romano","Conti","Esposito","Bianchi","Costa","Gentile",
    "Silva","Santos","Oliveira","Souza","Lima","Costa","Ferreira","Carvalho","Alves","Rodrigues",
    "Hernandez","Lopez","Martinez","Sanchez","Perez","Romero","Jimenez","Vargas","Castillo","Moreno",
]

LOCATIONS = [
    "New York", "San Francisco", "London", "Berlin", "Singapore",
    "Austin", "Seattle", "Boston", "Chicago", "Toronto",
    "Amsterdam", "Dublin", "Tokyo", "Sydney", "Paris",
    "Denver", "Atlanta", "Miami", "Los Angeles", "Washington DC",
]


def make_people(n: int = 500) -> list[dict]:
    people = []
    dept_counts = {d: 0 for d in DEPARTMENTS}
    for i in range(n):
        dept = DEPARTMENTS[i % len(DEPARTMENTS)]
        dept_counts[dept] += 1
        fn = FIRST_NAMES[i % len(FIRST_NAMES)]
        ln = LAST_NAMES[(i * 7 + 3) % len(LAST_NAMES)]
        title = TITLES_BY_DEPT[dept][dept_counts[dept] % len(TITLES_BY_DEPT[dept])]
        people.append({
            "id": uid(),
            "employee_id": f"EMP{1000 + i:04d}",
            "first_name": fn,
            "last_name": ln,
            "email": f"{fn.lower()}.{ln.lower()}{i}@corp.example.com",
            "title": title,
            "department": dept,
            "employment_type": rng.choice(["employee", "employee", "employee", "contractor"]),
            "status": "active" if i < 470 else "inactive",
            "location": LOCATIONS[i % len(LOCATIONS)],
            "phone": f"+1-{rng.randint(200,999)}-{rng.randint(100,999)}-{rng.randint(1000,9999)}",
            "manager_id": None,
            "hire_date": days_ago(rng.randint(30, 3000)),
            "created_at": days_ago(rng.randint(30, 3000)),
            "updated_at": days_ago(rng.randint(0, 60)),
        })

    dept_first = {}
    for p in people:
        if p["department"] not in dept_first:
            dept_first[p["department"]] = p["id"]
    for p in people:
        mgr = dept_first.get(p["department"])
        if mgr != p["id"]:
            p["manager_id"] = mgr
    return people


# ── Hardware Assets ───────────────────────────────────────────────────────────

ASSET_MODELS = {
    "laptop": [
        ("Apple",     "MacBook Pro 16 M3",              {"ram_gb": 32,  "storage_gb": 1024, "cpu": "Apple M3 Pro"}),
        ("Apple",     "MacBook Pro 14 M3",              {"ram_gb": 16,  "storage_gb": 512,  "cpu": "Apple M3"}),
        ("Apple",     "MacBook Air 15 M2",              {"ram_gb": 16,  "storage_gb": 512,  "cpu": "Apple M2"}),
        ("Apple",     "MacBook Air 13 M3",              {"ram_gb": 8,   "storage_gb": 256,  "cpu": "Apple M3"}),
        ("Dell",      "XPS 15 9530",                    {"ram_gb": 32,  "storage_gb": 512,  "cpu": "Intel Core i9-13900H"}),
        ("Dell",      "Latitude 5540",                  {"ram_gb": 16,  "storage_gb": 256,  "cpu": "Intel Core i5-1345U"}),
        ("Lenovo",    "ThinkPad X1 Carbon Gen 11",      {"ram_gb": 16,  "storage_gb": 512,  "cpu": "Intel Core i7-1365U"}),
        ("Lenovo",    "ThinkPad T14s Gen 4",            {"ram_gb": 16,  "storage_gb": 256,  "cpu": "AMD Ryzen 7 PRO 7840U"}),
        ("HP",        "EliteBook 840 G10",              {"ram_gb": 16,  "storage_gb": 256,  "cpu": "Intel Core i5-1335U"}),
        ("HP",        "ZBook Firefly G10",              {"ram_gb": 32,  "storage_gb": 512,  "cpu": "Intel Core i7-1355U"}),
        ("Microsoft", "Surface Laptop 5 15\"",          {"ram_gb": 16,  "storage_gb": 512,  "cpu": "Intel Core i7-1265U"}),
        ("ASUS",      "ProArt Studiobook 16",           {"ram_gb": 32,  "storage_gb": 1024, "cpu": "AMD Ryzen 9 7945HX"}),
    ],
    "desktop": [
        ("Apple",  "Mac Studio M2 Ultra",       {"ram_gb": 64,  "storage_gb": 2048, "cpu": "Apple M2 Ultra"}),
        ("Apple",  "Mac Mini M2 Pro",           {"ram_gb": 32,  "storage_gb": 512,  "cpu": "Apple M2 Pro"}),
        ("Dell",   "OptiPlex 7010 Tower",       {"ram_gb": 32,  "storage_gb": 512,  "cpu": "Intel Core i7-13700"}),
        ("Dell",   "Precision 3680 Tower",      {"ram_gb": 64,  "storage_gb": 1024, "cpu": "Intel Core i9-14900K"}),
        ("HP",     "EliteDesk 800 G9 Tower",    {"ram_gb": 16,  "storage_gb": 256,  "cpu": "Intel Core i5-12500"}),
        ("HP",     "Z6 G5 Workstation",         {"ram_gb": 128, "storage_gb": 2048, "cpu": "Intel Xeon W5-2465X"}),
        ("Lenovo", "ThinkCentre M70q Gen 4",    {"ram_gb": 16,  "storage_gb": 512,  "cpu": "Intel Core i5-13400T"}),
        ("Lenovo", "ThinkStation P360 Ultra",   {"ram_gb": 64,  "storage_gb": 1024, "cpu": "Intel Core i9-12900K"}),
    ],
    "server": [
        ("Dell",        "PowerEdge R750xs",            {"ram_gb": 256,  "storage_gb": 8192,  "cpu": "Intel Xeon Gold 6330",     "cores": 28}),
        ("Dell",        "PowerEdge R650xs",            {"ram_gb": 128,  "storage_gb": 4096,  "cpu": "Intel Xeon Silver 4310",   "cores": 12}),
        ("Dell",        "PowerEdge MX760c",            {"ram_gb": 512,  "storage_gb": 16384, "cpu": "Intel Xeon Platinum 8480+","cores": 60}),
        ("HPE",         "ProLiant DL380 Gen10 Plus",   {"ram_gb": 128,  "storage_gb": 4096,  "cpu": "Intel Xeon Silver 4314",   "cores": 16}),
        ("HPE",         "ProLiant DL360 Gen11",        {"ram_gb": 64,   "storage_gb": 2048,  "cpu": "Intel Xeon Silver 4410Y",  "cores": 12}),
        ("Supermicro",  "SYS-221H-TNR",                {"ram_gb": 512,  "storage_gb": 16384, "cpu": "Intel Xeon Platinum 8462Y","cores": 32}),
        ("Supermicro",  "SYS-120U-TNR",                {"ram_gb": 256,  "storage_gb": 8192,  "cpu": "Intel Xeon Gold 6448Y",    "cores": 32}),
        ("Lenovo",      "ThinkSystem SR650 V3",        {"ram_gb": 256,  "storage_gb": 8192,  "cpu": "Intel Xeon Gold 6438N",    "cores": 32}),
        ("Lenovo",      "ThinkSystem SR630 V3",        {"ram_gb": 128,  "storage_gb": 4096,  "cpu": "Intel Xeon Silver 4416+",  "cores": 20}),
        ("Cisco",       "UCS C240 M7",                 {"ram_gb": 256,  "storage_gb": 8192,  "cpu": "Intel Xeon Gold 6448Y",    "cores": 32}),
    ],
    "mobile": [
        ("Apple",   "iPhone 15 Pro Max",    {"storage_gb": 512, "os": "iOS 17"}),
        ("Apple",   "iPhone 15 Pro",        {"storage_gb": 256, "os": "iOS 17"}),
        ("Apple",   "iPhone 14",            {"storage_gb": 128, "os": "iOS 17"}),
        ("Apple",   "iPhone 14 Pro",        {"storage_gb": 256, "os": "iOS 17"}),
        ("Samsung", "Galaxy S24 Ultra",     {"storage_gb": 256, "os": "Android 14"}),
        ("Samsung", "Galaxy S24+",          {"storage_gb": 256, "os": "Android 14"}),
        ("Google",  "Pixel 8 Pro",          {"storage_gb": 128, "os": "Android 14"}),
        ("Google",  "Pixel 8",              {"storage_gb": 128, "os": "Android 14"}),
    ],
    "tablet": [
        ("Apple",     "iPad Pro M4 13\"",       {"storage_gb": 512, "os": "iPadOS 17"}),
        ("Apple",     "iPad Pro M2 11\"",        {"storage_gb": 256, "os": "iPadOS 17"}),
        ("Apple",     "iPad Air M2",             {"storage_gb": 128, "os": "iPadOS 17"}),
        ("Apple",     "iPad mini 6",             {"storage_gb": 64,  "os": "iPadOS 17"}),
        ("Microsoft", "Surface Pro 10",          {"ram_gb": 16, "storage_gb": 256, "cpu": "Intel Core Ultra 5 135U"}),
        ("Microsoft", "Surface Pro 9 5G",        {"ram_gb": 16, "storage_gb": 256, "cpu": "Microsoft SQ3"}),
        ("Samsung",   "Galaxy Tab S9 Ultra",     {"storage_gb": 256, "os": "Android 14"}),
        ("Samsung",   "Galaxy Tab S9+",          {"storage_gb": 128, "os": "Android 14"}),
    ],
    "network": [
        ("Cisco",       "Catalyst 9300-48P Switch",   {"ports": 48, "uplink": "10G", "poe": True}),
        ("Cisco",       "Catalyst 9500-32C Switch",   {"ports": 32, "uplink": "100G"}),
        ("Cisco",       "ASR 1001-X Router",          {"throughput_gbps": 20}),
        ("Palo Alto",   "PA-5430 NGFW",               {"throughput_gbps": 80}),
        ("Palo Alto",   "PA-3440 NGFW",               {"throughput_gbps": 24}),
        ("Palo Alto",   "PA-450 NGFW",                {"throughput_gbps": 3.8}),
        ("Juniper",     "EX4300-48P Switch",          {"ports": 48, "poe": True}),
        ("Juniper",     "SRX300 Services Gateway",    {"throughput_gbps": 1}),
        ("Fortinet",    "FortiGate 601F",             {"throughput_gbps": 36}),
        ("Fortinet",    "FortiGate 200F",             {"throughput_gbps": 18}),
        ("Aruba",       "CX 6300F Switch",            {"ports": 48, "uplink": "25G"}),
        ("F5",          "BIG-IP i5800 LTM",           {"throughput_gbps": 40}),
    ],
}

OS_BY_ASSET = {
    "laptop":  ["macOS 14 Sonoma", "macOS 13 Ventura", "Windows 11 Pro", "Windows 10 Pro", "Ubuntu 22.04 LTS"],
    "desktop": ["macOS 14 Sonoma", "Windows 11 Pro", "Ubuntu 22.04 LTS", "Windows 10 Pro"],
    "server":  ["RHEL 9.3", "RHEL 8.9", "Ubuntu 22.04 LTS", "Ubuntu 20.04 LTS", "Rocky Linux 9.3", "Windows Server 2022", "Windows Server 2019"],
    "mobile":  ["iOS 17.4", "iOS 16.7", "Android 14", "Android 13"],
    "tablet":  ["iPadOS 17.4", "iPadOS 16.7", "Windows 11 Pro", "Android 14"],
    "network": ["Cisco IOS XE 17.12", "PAN-OS 11.1", "PAN-OS 10.2", "Junos OS 23.2", "FortiOS 7.4", "ArubaOS-CX 10.12"],
}

NETWORK_ZONES = ["corporate", "dmz", "production", "staging", "management", "guest", "iot"]
COMPLIANCE_TAGS_POOL = [
    ["pci-dss"], ["hipaa"], ["sox"], ["gdpr"], ["pci-dss","sox"],
    ["gdpr","hipaa"], ["sox","gdpr"], ["pci-dss","gdpr","hipaa"],
    ["soc2"], ["iso27001"], ["soc2","iso27001"], [],
]


def make_assets(people: list[dict], n: int = 1500) -> list[dict]:
    assets = []
    person_ids = [p["id"] for p in people if p["status"] == "active"]

    # Distribution: ~600 laptops, ~450 mobiles, ~120 desktops, ~180 servers, ~90 tablets, ~60 network
    type_dist = (
        ["laptop"] * 600 +
        ["mobile"] * 450 +
        ["desktop"] * 120 +
        ["server"] * 180 +
        ["tablet"] * 90 +
        ["network"] * 60
    )
    rng.shuffle(type_dist)
    type_dist = type_dist[:n]

    assigned_idx = 0
    for i, atype in enumerate(type_dist):
        make, model, specs = rng.choice(ASSET_MODELS[atype])
        os_ver = rng.choice(OS_BY_ASSET[atype])
        sn = f"SN-{atype[:3].upper()}-{rng.randint(100000, 999999)}"
        purchase = days_ago(rng.randint(90, 2500))
        warranty = purchase + timedelta(days=rng.choice([365, 730, 1095, 1460]))
        tag_options = ["managed", "corporate", "critical", "dev", "ci-cd", "contractor"]

        assigned_to = None
        if atype not in ("server", "network") and assigned_idx < len(person_ids):
            assigned_to = person_ids[assigned_idx % len(person_ids)]
            assigned_idx += 1

        assets.append({
            "asset_tag": f"CORP-{atype[:3].upper()}-{10000 + i}",
            "asset_type": atype,
            "make": make,
            "model": model,
            "serial_number": sn,
            "os_version": os_ver,
            "specs": specs,
            "status": rng.choice(["active", "active", "active", "active", "maintenance", "decommissioned"]),
            "assigned_to_id": assigned_to,
            "location": rng.choice(LOCATIONS),
            "purchase_date": purchase,
            "warranty_expires": warranty,
            "tags": rng.choice(COMPLIANCE_TAGS_POOL),
            "created_at": days_ago(rng.randint(30, 2500)),
            "updated_at": days_ago(rng.randint(0, 60)),
        })
    return assets


# ── Cloud Accounts ────────────────────────────────────────────────────────────

CLOUD_REGIONS = {
    "aws":   ["us-east-1","us-west-2","eu-west-1","eu-central-1","ap-southeast-1","ap-northeast-1","us-east-2","eu-west-2","ap-south-1","ca-central-1"],
    "azure": ["eastus","westus2","westeurope","northeurope","southeastasia","japaneast","uksouth","canadacentral","australiaeast","brazilsouth"],
    "gcp":   ["us-central1","us-east1","europe-west1","europe-west4","asia-southeast1","asia-northeast1","us-west1","europe-west3","asia-east1","northamerica-northeast1"],
}

CLOUD_ACCOUNT_NAMES = {
    "aws": [
        "aws-prod-us-east","aws-prod-eu-west","aws-staging-us","aws-dev-shared",
        "aws-security-logging","aws-data-lake","aws-ci-cd-pipelines","aws-ml-platform",
        "aws-dr-backup","aws-network-transit","aws-sandbox-engineering","aws-finance-workloads",
    ],
    "azure": [
        "azure-prod-primary","azure-prod-europe","azure-dev-test","azure-identity-mgmt",
        "azure-backup-recovery","azure-analytics-platform","azure-devops-shared",
        "azure-compliance-audit","azure-iot-hub","azure-partner-integration",
    ],
    "gcp": [
        "gcp-data-engineering","gcp-ml-training","gcp-prod-apis",
        "gcp-logging-monitoring","gcp-ci-artifacts","gcp-sandbox-research",
        "gcp-europe-expansion","gcp-apac-delivery",
    ],
}


def make_cloud_accounts() -> list[dict]:
    accounts = []
    for provider, names in CLOUD_ACCOUNT_NAMES.items():
        for i, name in enumerate(names):
            env = "production" if "prod" in name else ("staging" if "staging" in name else ("dev" if "dev" in name or "sandbox" in name else "production"))
            accounts.append({
                "cloud_provider": provider,
                "account_id": f"{provider[:3].upper()}-{rng.randint(100000000000, 999999999999)}",
                "account_name": name,
                "account_type": "aws_account" if provider == "aws" else ("azure_subscription" if provider == "azure" else "gcp_project"),
                "environment": env,
                "region_primary": rng.choice(CLOUD_REGIONS[provider]),
                "regions": [rng.choice(CLOUD_REGIONS[provider]) for _ in range(rng.randint(1, 4))],
                "billing_email": f"infra-{provider}@corp.example.com",
                "monthly_cost_usd": round(rng.uniform(500, 45000), 2) if env == "production" else round(rng.uniform(200, 8000), 2),
                "tags": {"team": rng.choice(["platform","security","data","devops","ml"]), "cost-center": f"CC-{rng.randint(1000,9999)}"},
                "mfa_enabled": rng.random() < 0.75,
                "cloudtrail_enabled": rng.random() < 0.80 if provider == "aws" else True,
                "security_hub_enabled": rng.random() < 0.60,
                "status": "active",
                "created_at": days_ago(rng.randint(180, 1500)),
                "updated_at": days_ago(rng.randint(0, 30)),
            })
    return accounts


# ── Products ──────────────────────────────────────────────────────────────────

INTERNAL_PRODUCTS = [
    # Core Platform
    ("AuthService",          "Core authentication & SSO gateway",         "platform",  "Engineering",  "tier1_critical"),
    ("APIGateway",           "Unified API gateway + rate limiting",        "platform",  "Engineering",  "tier1_critical"),
    ("UserDirectory",        "Employee LDAP/AD sync & identity store",     "internal",  "Security",     "tier1_critical"),
    ("SecretVault",          "HashiCorp Vault secret management",          "platform",  "Security",     "tier1_critical"),
    ("CertManager",          "PKI & TLS certificate lifecycle",            "platform",  "Security",     "tier1_critical"),
    # Data Platform
    ("DataLakehouse",        "Iceberg-based data lakehouse",               "platform",  "Engineering",  "tier1_critical"),
    ("StreamProcessor",      "Kafka + Flink real-time event processing",   "platform",  "Engineering",  "tier1_critical"),
    ("DataCatalog",          "Atlan data catalog & lineage tracker",       "internal",  "Engineering",  "tier2_important"),
    ("ETLOrchestrator",      "Apache Airflow DAG orchestration",           "internal",  "Engineering",  "tier2_important"),
    ("AnalyticsDW",          "Snowflake enterprise data warehouse",        "saas",      "Engineering",  "tier2_important"),
    # Product Apps
    ("CustomerPortal",       "B2B self-service customer web portal",       "internal",  "Product",      "tier1_critical"),
    ("MobileApp",            "iOS & Android consumer app",                 "internal",  "Product",      "tier1_critical"),
    ("AdminConsole",         "Internal admin & ops dashboard",             "internal",  "Engineering",  "tier2_important"),
    ("BillingEngine",        "Stripe-based subscription billing",          "internal",  "Finance",      "tier1_critical"),
    ("NotificationHub",      "Email/SMS/Push notification service",        "internal",  "Engineering",  "tier2_important"),
    ("ReportingService",     "Scheduled PDF/Excel report generation",      "internal",  "Product",      "tier2_important"),
    ("SearchService",        "Elasticsearch-powered full-text search",     "internal",  "Engineering",  "tier2_important"),
    ("ContentDelivery",      "CDN origin + asset optimization pipeline",   "internal",  "Engineering",  "tier2_important"),
    ("FeatureFlags",         "LaunchDarkly feature flag management",       "saas",      "Engineering",  "tier3_standard"),
    ("MonitoringPlatform",   "Datadog APM + infrastructure monitoring",    "saas",      "Infrastructure","tier2_important"),
    # DevOps & Security
    ("CISystem",             "GitHub Actions CI + artifact registry",      "saas",      "Engineering",  "tier2_important"),
    ("ContainerPlatform",    "EKS + ArgoCD GitOps platform",               "internal",  "Infrastructure","tier1_critical"),
    ("VulnScanner",          "Tenable.io vulnerability scanner",           "saas",      "Security",     "tier2_important"),
    ("SIEMPlatform",         "Splunk Enterprise SIEM",                     "saas",      "Security",     "tier1_critical"),
    ("EDRPlatform",          "CrowdStrike Falcon EDR",                     "saas",      "Security",     "tier1_critical"),
    ("PAMSolution",          "CyberArk Privileged Access Management",      "saas",      "Security",     "tier1_critical"),
    ("EmailSecurity",        "Proofpoint email gateway + sandbox",         "saas",      "Security",     "tier2_important"),
    ("WebProxy",             "Zscaler ZIA secure web gateway",             "saas",      "Security",     "tier2_important"),
    ("IdentityGovernance",   "SailPoint IdentityNow IGA",                  "saas",      "Security",     "tier2_important"),
    ("ThreatIntelPlatform",  "Recorded Future threat intelligence",        "saas",      "Security",     "tier2_important"),
    # Business SaaS
    ("HRMS",                 "Workday HR information system",              "saas",      "HR",           "tier2_important"),
    ("ERP",                  "SAP S/4HANA enterprise resource planning",   "saas",      "Finance",      "tier1_critical"),
    ("CRM",                  "Salesforce CRM",                             "saas",      "Sales",        "tier1_critical"),
    ("ProjectMgmt",          "Jira + Confluence project management",       "saas",      "Engineering",  "tier3_standard"),
    ("DocManagement",        "SharePoint + OneDrive document management",  "saas",      "Legal",        "tier2_important"),
    ("VideoConference",      "Zoom enterprise video conferencing",         "saas",      "HR",           "tier3_standard"),
    ("CollabPlatform",       "Slack enterprise messaging",                 "saas",      "Engineering",  "tier2_important"),
    ("ContractMgmt",         "DocuSign contract lifecycle management",     "saas",      "Legal",        "tier2_important"),
    ("MarketingAutomation",  "HubSpot marketing automation",               "saas",      "Marketing",    "tier3_standard"),
    ("SupportPlatform",      "Zendesk customer support platform",          "saas",      "Product",      "tier2_important"),
    # AI / ML
    ("MLTrainingPlatform",   "Kubeflow MLOps training platform",           "internal",  "Engineering",  "tier2_important"),
    ("ModelRegistry",        "MLflow model registry & versioning",         "internal",  "Engineering",  "tier2_important"),
    ("AIInferenceGateway",   "NVIDIA Triton inference serving gateway",    "internal",  "Engineering",  "tier2_important"),
    ("DataLabeling",         "Scale AI data labeling integration",         "saas",      "Engineering",  "tier3_standard"),
    # More internal services
    ("ServiceMesh",          "Istio service mesh + mTLS encryption",       "internal",  "Infrastructure","tier2_important"),
    ("LogAggregator",        "Fluent Bit + OpenSearch log aggregation",    "internal",  "Infrastructure","tier2_important"),
    ("BackupService",        "Veeam enterprise backup & recovery",         "saas",      "Infrastructure","tier2_important"),
    ("DNS_DHCP",             "Infoblox DDI DNS/DHCP/IPAM",                 "saas",      "Infrastructure","tier2_important"),
    ("ConfigMgmt",           "Ansible + Terraform IaC config management",  "internal",  "Infrastructure","tier2_important"),
    ("IncidentManagement",   "PagerDuty incident management & oncall",     "saas",      "Infrastructure","tier2_important"),
    ("AssetMgmt",            "ServiceNow ITAM asset lifecycle",            "saas",      "IT",           "tier3_standard"),
    ("KnowledgeBase",        "Notion enterprise knowledge management",     "saas",      "HR",           "tier3_standard"),
    ("PasswordManager",      "1Password Teams credential management",      "saas",      "Security",     "tier2_important"),
    ("MFASolution",          "Duo Security MFA platform",                  "saas",      "Security",     "tier1_critical"),
    ("NetworkMonitor",       "SolarWinds Orion network performance mon",   "saas",      "Infrastructure","tier2_important"),
]

DATA_CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"]
TECH_STACKS = [
    {"language": "Python", "framework": "FastAPI", "db": "PostgreSQL", "infra": "Kubernetes"},
    {"language": "TypeScript", "framework": "Next.js", "db": "PostgreSQL", "infra": "Vercel"},
    {"language": "Go", "framework": "Gin", "db": "MySQL", "infra": "Kubernetes"},
    {"language": "Java", "framework": "Spring Boot", "db": "Oracle", "infra": "EKS"},
    {"language": "Node.js", "framework": "Express", "db": "MongoDB", "infra": "ECS"},
    {"language": "Rust", "framework": "Actix", "db": "CockroachDB", "infra": "Kubernetes"},
    {"language": "Ruby", "framework": "Rails", "db": "PostgreSQL", "infra": "Heroku"},
    {"language": "Kotlin", "framework": "Ktor", "db": "PostgreSQL", "infra": "GKE"},
]
SLA_TIERS = {
    "tier1_critical": {"uptime_sla": "99.99%", "rto_hours": 1, "rpo_hours": 0.25},
    "tier2_important": {"uptime_sla": "99.9%", "rto_hours": 4, "rpo_hours": 1},
    "tier3_standard": {"uptime_sla": "99.5%", "rto_hours": 24, "rpo_hours": 4},
}


def make_products(cloud_accounts: list[dict]) -> list[dict]:
    products = []
    # Use real DB IDs populated after cloud_accounts insert
    cloud_ids = [a.get("_id") for a in cloud_accounts if a.get("_id")]

    for i, (name, desc, ptype, owner_dept, tier) in enumerate(INTERNAL_PRODUCTS):
        sla = SLA_TIERS[tier]
        slug = name.lower().replace(" ", "-").replace("_", "-").replace("/", "-")
        products.append({
            "name": name,
            "slug": slug,
            "description": desc,
            "product_type": ptype,
            "category": owner_dept.lower(),
            "tier": tier,
            "team": owner_dept,
            "status": "active",
            "data_classification": rng.choice(DATA_CLASSIFICATIONS),
            "tech_stack": rng.choice(TECH_STACKS) if ptype in ("internal", "platform") else {},
            "cloud_account_id": rng.choice(cloud_ids) if cloud_ids else None,
            "sla_uptime_target": float(sla["uptime_sla"].rstrip("%")) if "%" in sla["uptime_sla"] else 99.9,
            "pii_data": rng.choice([True, False, False]),
            "phi_data": False,
            "pci_data": "billing" in name.lower() or "payment" in name.lower(),
            "compliance_frameworks": rng.sample(["soc2", "pci-dss", "hipaa", "gdpr", "iso27001", "nist"], k=rng.randint(0, 3)),
            "deployment_model": "kubernetes" if ptype in ("internal", "platform") else "saas",
            "annual_cost_usd": round(rng.uniform(5000, 500000), 2) if ptype == "saas" else None,
            "vendor_name": name if ptype == "saas" else None,
            "created_at": days_ago(rng.randint(180, 3000)),
            "updated_at": days_ago(rng.randint(0, 60)),
        })
    return products


# ── Vulnerabilities ───────────────────────────────────────────────────────────

VULN_DATA = [
    # Critical — Remote Code Execution
    ("CVE-2024-21413", "critical", 9.8, 0.94, True,  "Microsoft Outlook RCE via MIME attachment parsing — allows code exec via preview",          "patch", ["windows","office365","outlook"]),
    ("CVE-2024-3400",  "critical", 10.0,0.97, True,  "Palo Alto PAN-OS command injection via GlobalProtect — full device compromise",              "patch", ["network","firewall","paloalto"]),
    ("CVE-2024-4947",  "critical", 9.6, 0.82, True,  "Google Chrome V8 type confusion — sandbox escape via crafted HTML page",                     "patch", ["browser","chromium","electron"]),
    ("CVE-2023-46747", "critical", 9.8, 0.97, True,  "F5 BIG-IP iControl REST auth bypass — unauthenticated RCE on management plane",             "patch", ["network","loadbalancer","f5"]),
    ("CVE-2024-1709",  "critical", 10.0,0.97, True,  "ConnectWise ScreenConnect auth bypass — full filesystem and code execution",                 "patch", ["remote-access","screenconnect"]),
    ("CVE-2023-4966",  "critical", 9.4, 0.97, True,  "Citrix Bleed — session token leak from NetScaler ADC/Gateway memory disclosure",            "patch", ["network","citrix","vpn"]),
    ("CVE-2024-27198", "critical", 9.8, 0.88, True,  "JetBrains TeamCity auth bypass — unauthenticated admin account creation",                   "patch", ["devops","cicd","teamcity"]),
    ("CVE-2024-6387",  "critical", 8.1, 0.95, True,  "regreSSHion — OpenSSH race condition in signal handler allowing unauthenticated RCE",       "patch", ["server","linux","ssh"]),
    ("CVE-2022-0847",  "critical", 7.8, 0.97, True,  "Dirty Pipe — Linux kernel privilege escalation via pipe write to read-only files",          "patch", ["server","linux","kernel"]),
    ("CVE-2023-44487", "high",     7.5, 0.89, True,  "HTTP/2 Rapid Reset — DoS via multiplexed stream cancellation (major web servers)",          "patch", ["server","web","http2"]),
    # High — Privilege Escalation / LPE
    ("CVE-2024-30090", "high",     7.8, 0.67, False, "Windows Kernel privilege escalation via Kernel Streaming Service driver",                   "patch", ["windows","kernel"]),
    ("CVE-2023-36884", "high",     8.3, 0.91, True,  "Office and Windows HTML RCE — crafted Office document triggers code exec",                  "patch", ["windows","office365"]),
    ("CVE-2024-23897", "critical", 9.8, 0.95, True,  "Jenkins arbitrary file read via CLI — leads to RCE via serialized classloader",             "patch", ["devops","cicd","jenkins"]),
    ("CVE-2024-21626", "high",     8.6, 0.78, True,  "Leaky Vessels — runc container escape via /proc/self/cwd file descriptor leak",             "patch", ["containers","docker","kubernetes"]),
    ("CVE-2023-29360", "high",     8.4, 0.62, False, "Windows TPM Device Driver elevation of privilege",                                          "patch", ["windows","tpm"]),
    # SQL Injection / Web
    ("CVE-2023-22527", "critical", 10.0,0.97, True,  "Atlassian Confluence OGNL injection — unauthenticated RCE via template injection",          "patch", ["devops","confluence","atlassian"]),
    ("CVE-2024-22024", "critical", 8.3, 0.79, True,  "Ivanti Connect Secure XXE — authentication bypass via SAML XML parsing",                   "patch", ["vpn","ivanti","remote-access"]),
    ("CVE-2024-21887", "critical", 9.1, 0.97, True,  "Ivanti Connect Secure command injection — authenticated RCE via /api/v1/totp/user-backup-code", "patch", ["vpn","ivanti"]),
    ("CVE-2023-40044", "critical", 9.8, 0.90, True,  "WS_FTP Server deserialization RCE — unauthenticated via Ad Hoc Transfer module",           "patch", ["server","ftp","mft"]),
    ("CVE-2024-20767", "critical", 9.1, 0.76, True,  "Adobe ColdFusion auth bypass + file read via CFFile/CFHTTP endpoint",                      "patch", ["server","coldfusion","adobe"]),
    # Cloud / Container
    ("CVE-2024-21893", "high",     8.2, 0.80, True,  "Ivanti SSRF via SAML component — can reach internal services from public endpoint",        "patch", ["vpn","saml","ssrf"]),
    ("CVE-2023-5528",  "high",     8.8, 0.71, False, "Kubernetes LPE via hostPath mount in CSI driver plugins with privileged PSP",              "patch", ["containers","kubernetes","csi"]),
    ("CVE-2024-37085", "high",     6.8, 0.69, False, "VMware ESXi AD integration auth bypass — join domain admin group without credentials",     "patch", ["virtualization","vmware","esxi"]),
    ("CVE-2023-20593", "medium",   5.5, 0.41, False, "Zenbleed — AMD Zen2 YMM register cross-process data leak via vzeroupper instruction",     "patch", ["hardware","amd","cloud"]),
    ("CVE-2024-28987", "critical", 9.1, 0.87, True,  "SolarWinds WHD hard-coded credentials — unauthenticated API access via embedded creds",    "patch", ["itom","solarwinds","monitoring"]),
    # Application / Framework
    ("CVE-2022-22965", "critical", 9.8, 0.97, True,  "Spring4Shell — Spring MVC ClassLoader manipulation via data binding RCE",                  "patch", ["java","spring","framework"]),
    ("CVE-2021-44228", "critical", 10.0,0.97, True,  "Log4Shell — Log4j2 JNDI injection enabling unauthenticated RCE",                          "patch", ["java","logging","log4j"]),
    ("CVE-2023-20198", "critical", 10.0,0.97, True,  "Cisco IOS XE web UI privilege escalation — remote account creation with level 15 privs",  "patch", ["network","cisco","router"]),
    ("CVE-2023-34362", "critical", 9.8, 0.97, True,  "MOVEit Transfer SQL injection — authentication bypass + data exfiltration",               "patch", ["mft","moveit","file-transfer"]),
    ("CVE-2024-28995", "high",     8.6, 0.81, True,  "SolarWinds Serv-U path traversal — read sensitive files without authentication",          "patch", ["mft","solarwinds","file-transfer"]),
    # Identity / Auth
    ("CVE-2023-47246", "critical", 9.8, 0.91, True,  "SysAid path traversal — unauthenticated file upload + RCE via server-side template injection", "patch", ["itsm","sysaid"]),
    ("CVE-2024-23692", "critical", 9.8, 0.83, True,  "Rejetto HFS template injection — unauthenticated RCE via HTTP File Server search param", "patch", ["server","file-server","hfs"]),
    ("CVE-2024-38112", "high",     7.5, 0.88, True,  "Windows MSHTML Platform spoofing — .url shortcut opens IE browser via mhtml: handler",    "patch", ["windows","mshtml","browser"]),
    ("CVE-2024-30051", "high",     7.8, 0.80, True,  "Windows DWM Core Library LPE — heap-based buffer overflow in window management",         "patch", ["windows","kernel","dwm"]),
    ("CVE-2023-42793", "critical", 9.8, 0.97, True,  "JetBrains TeamCity CI auth bypass — create admin token without authentication",          "patch", ["devops","cicd","teamcity"]),
    # Zero-days / High Exploitability
    ("CVE-2024-49039", "high",     8.8, 0.84, True,  "Windows Task Scheduler LPE — low-priv user elevates to SYSTEM via RPC endpoint",        "patch", ["windows","scheduler","kernel"]),
    ("CVE-2024-43461", "high",     8.8, 0.82, True,  "Windows MSHTML Platform spoofing via braille whitespace in .url file",                  "patch", ["windows","mshtml"]),
    ("CVE-2024-38080", "high",     7.8, 0.77, False, "Windows Hyper-V privilege escalation — guest-to-host escape via IOCTL abuse",           "patch", ["windows","hyperv","virtualization"]),
    ("CVE-2024-26169", "high",     7.8, 0.72, True,  "Windows Error Reporting LPE — DLL hijacking via WER service file write",               "patch", ["windows","wer","dll-hijack"]),
    ("CVE-2024-20356", "high",     8.7, 0.69, False, "Cisco IMC command injection — authenticated but low-priv user gets root on BMC",       "patch", ["network","cisco","bmc"]),
    # Misconfigs / Weaknesses
    ("CVE-2023-28252", "high",     7.8, 0.87, True,  "Windows CLFS driver LPE — heap overflow in log file parsing used by multiple ransomware families", "patch", ["windows","clfs","kernel"]),
    ("CVE-2024-1086",  "high",     7.8, 0.94, True,  "Linux nf_tables use-after-free — LPE to root via netfilter double-free in packet filter", "patch", ["server","linux","kernel","netfilter"]),
    ("CVE-2022-3786",  "high",     7.5, 0.38, False, "OpenSSL punycode buffer overflow in X.509 certificate — crash via malformed email addr", "patch", ["crypto","openssl","tls"]),
    ("CVE-2022-3602",  "high",     7.5, 0.35, False, "OpenSSL X.509 stack buffer overflow via punycode — potential code exec on certificate parse", "patch", ["crypto","openssl","tls"]),
    ("CVE-2024-27316", "medium",   7.5, 0.47, False, "Apache httpd HTTP/2 CONTINUATION flood — DoS via unlimited CONTINUATION frames per stream", "patch", ["server","apache","http2"]),
    # Medium
    ("CVE-2024-22019", "medium",   7.5, 0.56, False, "Node.js HTTP/1.1 request smuggling — malformed Transfer-Encoding bypasses upstream proxy", "patch", ["nodejs","web","proxy"]),
    ("CVE-2023-45857", "medium",   6.5, 0.31, False, "Axios CSRF — X-XSRF-TOKEN header sent to third-party servers via redirect in axios",   "patch", ["nodejs","axios","frontend"]),
    ("CVE-2024-21501", "medium",   5.9, 0.22, False, "sanitize-html ReDoS — exponential backtracking on malformed HTML via regex in parser", "patch", ["nodejs","sanitize","frontend"]),
    ("CVE-2023-44270", "medium",   5.3, 0.18, False, "PostCSS line return parsing error — CSS linter bypass via crafted CSS comment chars",   "patch", ["nodejs","css","build-tools"]),
    ("CVE-2024-37890", "medium",   7.5, 0.54, False, "ws WebSocket library DoS — unlimited memory via crafted header fragments in HTTP upgrade", "patch", ["nodejs","websocket","realtime"]),
    ("CVE-2022-21449", "critical", 7.5, 0.55, False, "Psychic Signatures — Java ECDSA signature validation bypass (blank r/s values accepted)", "patch", ["java","crypto","ecdsa"]),
    # Infrastructure
    ("CVE-2024-20272", "high",     7.2, 0.61, False, "Cisco Unity Connection unauth file upload — code exec without auth via message upload",  "patch", ["network","cisco","voip"]),
    ("CVE-2023-20269", "high",     9.1, 0.78, True,  "Cisco ASA/FTD SSL VPN brute-force — no rate limiting on DAP client auth endpoint",     "patch", ["network","cisco","vpn"]),
    ("CVE-2024-23113", "critical", 9.8, 0.93, True,  "Fortinet FortiOS fgfm daemon RCE — unauthenticated code exec via crafted request to HA sync port", "patch", ["network","fortinet","firewall"]),
    ("CVE-2024-47575", "critical", 9.8, 0.92, True,  "Fortinet FortiManager missing auth — remote management plane compromise via fgfm protocol", "patch", ["network","fortinet","management"]),
    ("CVE-2024-8190",  "high",     7.2, 0.80, True,  "Ivanti CSA command injection — authenticated OS command injection in admin panel",      "patch", ["vpn","ivanti","remote-access"]),
    # Supply Chain
    ("CVE-2024-3661",  "medium",   7.6, 0.48, False, "TunnelVision — DHCP option 121 route injection bypasses VPN encapsulation on Linux/Windows", "patch", ["vpn","dhcp","network"]),
    ("CVE-2023-51385", "medium",   6.5, 0.40, False, "OpenSSH ProxyCommand shell metacharacter injection via hostname in ssh_config",        "patch", ["server","ssh","linux"]),
    ("CVE-2024-32002", "critical", 9.0, 0.74, True,  "Git RCE — recursive clone with crafted submodule path allows hook execution on Windows/Mac", "patch", ["devops","git","scm"]),
    ("CVE-2023-51074", "medium",   5.9, 0.19, False, "json-path ReDoS — stack overflow via deeply-nested filter query in JSON path eval",    "patch", ["java","json","library"]),
    ("CVE-2024-26130", "high",     7.5, 0.36, False, "cryptography.hazmat NULL pointer dereference on PKCS12 parse — crash in Python cert handling", "patch", ["python","crypto","library"]),
    ("CVE-2024-6242",  "high",     7.4, 0.51, False, "Apache HTTP Server mod_rewrite bypass — path traversal via crafted URL bypasses security filters", "patch", ["server","apache","web"]),
    # More critical cloud
    ("CVE-2024-20401", "critical", 9.8, 0.76, True,  "Cisco Secure Email arbitrary file write — code exec via attachment filename in MIME header", "patch", ["email","cisco","security"]),
    ("CVE-2024-21762", "critical", 9.6, 0.94, True,  "Fortinet FortiOS SSL VPN out-of-bounds write — unauthenticated RCE via crafted HTTP request", "patch", ["network","fortinet","vpn"]),
    ("CVE-2023-27997", "critical", 9.8, 0.97, True,  "FortiGate SSL-VPN heap overflow — unauthenticated RCE via pre-auth payload in ssl_vpnd", "patch", ["network","fortinet","vpn"]),
    ("CVE-2024-29824", "critical", 9.6, 0.88, True,  "Ivanti EPM SQL injection — unauthenticated RCE via core server SQLite record id handling", "patch", ["endpoint","ivanti","epm"]),
    ("CVE-2024-9463",  "critical", 9.9, 0.96, True,  "Palo Alto Expedition OS command injection — unauthenticated command exec via migration tool API", "patch", ["network","paloalto","firewall"]),
    ("CVE-2024-9465",  "critical", 9.2, 0.88, True,  "Palo Alto Expedition SQL injection — unauthenticated data disclosure in migration DB", "patch", ["network","paloalto","firewall"]),
    ("CVE-2024-40766", "critical", 9.3, 0.83, True,  "SonicWall SonicOS improper access control — unauthenticated resource access + credential exposure", "patch", ["network","sonicwall","firewall"]),
    ("CVE-2024-24919", "high",     8.6, 0.88, True,  "Check Point VPN info disclosure — unauthenticated arbitrary file read on security gateway", "patch", ["network","checkpoint","vpn"]),
    ("CVE-2024-38193", "high",     7.8, 0.82, True,  "Windows AFD.sys LPE — use-after-free in Ancillary Function Driver leads to SYSTEM",   "patch", ["windows","afd","kernel"]),
    ("CVE-2024-43491", "critical", 9.8, 0.89, True,  "Windows Update Downgrade attack — force older vulnerable version via WinSxS servicing", "patch", ["windows","update","downgrade"]),
    # Mobile
    ("CVE-2023-41064", "critical", 7.8, 0.91, True,  "Apple iOS/macOS WebP zero-click RCE — heap buffer overflow via malicious image in iMessage", "patch", ["mobile","apple","ios"]),
    ("CVE-2023-4863",  "critical", 8.8, 0.91, True,  "libwebp heap buffer overflow — RCE via maliciously crafted WebP in Chrome/Firefox/Electron", "patch", ["browser","chromium","libwebp"]),
    ("CVE-2024-23296", "high",     7.8, 0.86, True,  "Apple RTKit memory corruption — PAC bypass allows code exec with kernel privileges", "patch", ["mobile","apple","ios"]),
    ("CVE-2023-38606", "high",     7.8, 0.89, True,  "Apple XPC services state management issue — leads to kernel code execution",         "patch", ["mobile","apple","ios","kernel"]),
    # Database
    ("CVE-2022-21500", "high",     7.5, 0.43, False, "Oracle MySQL NULL pointer dereference in InnoDB — crash via crafted SELECT statement", "patch", ["database","mysql","oracle"]),
    ("CVE-2022-21425", "high",     7.2, 0.40, False, "Oracle MySQL privilege escalation — component: Server: DDL allows authenticated high-priv user RCE", "patch", ["database","mysql","oracle"]),
    ("CVE-2023-5679",  "medium",   6.5, 0.34, False, "BIND 9 DNS server assertion failure — crash via specific NSEC or NSEC3 responses in dnssec zone", "patch", ["dns","bind","server"]),
    ("CVE-2024-3727",  "high",     8.3, 0.58, False, "containers/image digest validation bypass — pull attacker-controlled image via manifest spoofing", "patch", ["containers","docker","oci"]),
    # End of 200 CVEs
    ("CVE-2024-37079", "critical", 9.8, 0.87, True,  "VMware vCenter RCE — heap overflow in DCERPC protocol allows code exec as root without creds", "patch", ["virtualization","vmware","vcenter"]),
    ("CVE-2024-22245", "critical", 9.6, 0.82, True,  "VMware EAP auth relay — attacker in AitM relays NTLM auth from EAP client to arbitrary service", "patch", ["virtualization","vmware"]),
    ("CVE-2021-21985", "critical", 9.8, 0.97, True,  "VMware vCenter RCE — Virtual SAN Health Check plugin RCE without authentication",    "patch", ["virtualization","vmware","vcenter"]),
    ("CVE-2024-6222",  "high",     7.7, 0.68, False, "Docker Desktop priv esc — extensions feature allows low-priv code to reach host via sockets", "patch", ["containers","docker","desktop"]),
    ("CVE-2023-32154", "critical", 8.2, 0.75, True,  "Windows NFS server RCE — hash collision triggers integer overflow + heap corruption", "patch", ["windows","nfs","server"]),
    ("CVE-2023-28303", "medium",   5.7, 0.23, False, "Windows Snipping Tool info disclosure — deleted areas recoverable from saved PNG metadata", "patch", ["windows","sniptool"]),
    ("CVE-2024-20698", "high",     7.8, 0.66, False, "Windows Kernel LPE — Windows Kernel memory corruption via crafted IOCTL",           "patch", ["windows","kernel"]),
    ("CVE-2024-21338", "high",     7.8, 0.80, True,  "Windows AppLocker driver bypass — userspace IOCTL allows kernel arbitrary R/W",     "patch", ["windows","applocker","kernel"]),
    ("CVE-2023-35628", "critical", 8.1, 0.73, False, "Windows MSHTML Platform RCE — heap overflow via crafted URI in Windows MSHTML component", "patch", ["windows","mshtml"]),
    ("CVE-2024-30103", "high",     8.8, 0.79, True,  "Microsoft Outlook RCE — registry value exploitation during preview allows code exec", "patch", ["windows","outlook","office365"]),
]

def make_vulnerabilities() -> list[dict]:
    vulns = []
    for cve, sev, cvss, epss, cisa_kev, desc, rem, tags in VULN_DATA:
        vulns.append({
            "cve_id": cve,
            "title": f"{cve} — {desc[:80]}",
            "description": desc,
            "severity": sev,
            "cvss_score": cvss,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if cvss >= 9.0 else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": epss,
            "cisa_kev": cisa_kev,
            "exploit_public": cisa_kev or epss > 0.5,
            "exploit_type": rng.choice(["poc", "weaponized", "itw"]) if cisa_kev else ("poc" if epss > 0.4 else None),
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW" if cvss >= 8.0 else "HIGH",
            "affected_component": ", ".join(tags[:3]),
            "nvd_published_at": days_ago(rng.randint(30, 730)),
            "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{cve}", "source": "NVD"}],
            "created_at": days_ago(rng.randint(30, 730)),
            "updated_at": days_ago(rng.randint(0, 30)),
        })
    return vulns


def make_asset_vulnerabilities(assets: list[dict], vuln_ids: list, target: int = 8000) -> list[dict]:
    """Create ~target asset-vulnerability linking rows."""
    avs = []
    seen = set()

    eligible = [a for a in assets if a.get("_id") and a["asset_type"] in ("laptop","desktop","server","mobile","tablet")]

    while len(avs) < target:
        asset = rng.choice(eligible)
        asset_id = asset["_id"]
        vuln_id = rng.choice(vuln_ids)
        key = (asset_id, vuln_id)
        if key in seen:
            continue
        seen.add(key)
        discovered = days_ago(rng.randint(1, 180))
        sla_days = rng.choice([7, 14, 30, 60, 90])
        due = discovered + timedelta(days=sla_days)
        status_choice = rng.choices(
            ["open","in_remediation","resolved","accepted_risk","false_positive"],
            weights=[40, 15, 25, 10, 10]
        )[0]
        avs.append({
            "vuln_id": vuln_id,
            "hardware_asset_id": asset_id,
            "asset_type": asset["asset_type"],
            "status": status_choice,
            "discovered_at": discovered,
            "resolved_at": days_ago(rng.randint(0, 30)) if status_choice == "resolved" else None,
            "remediation_due_date": due,
            "risk_score": round(rng.uniform(3.0, 10.0), 1),
            "scan_source": rng.choice(["tenable","qualys","crowdstrike","defender","manual"]),
            "notes": rng.choice([
                None, None, None,
                "Patch scheduled for next maintenance window",
                "Awaiting vendor patch release",
                "Risk accepted — compensating controls in place",
                "False positive confirmed via package manager",
                "Remediation in progress — estimated 2 weeks",
            ]),
            "created_at": discovered,
            "updated_at": days_ago(rng.randint(0, 10)),
        })

    return avs


# ── CSPM Checks ───────────────────────────────────────────────────────────────

CSPM_CHECKS_DATA = [
    # ── AWS CIS Benchmark 2.0 ──────────────────────────────────────────────────
    ("CIS-AWS-1.1",  "aws", "Avoid the use of root account",           "identity",  "critical", "CIS AWS Benchmark v2.0 §1.1"),
    ("CIS-AWS-1.2",  "aws", "Ensure MFA is enabled for root account",  "identity",  "critical", "CIS AWS Benchmark v2.0 §1.2"),
    ("CIS-AWS-1.3",  "aws", "Ensure root account hardware MFA enabled","identity",  "critical", "CIS AWS Benchmark v2.0 §1.3"),
    ("CIS-AWS-1.4",  "aws", "Ensure no access keys for root account",  "identity",  "high",     "CIS AWS Benchmark v2.0 §1.4"),
    ("CIS-AWS-1.5",  "aws", "Ensure IAM password policy requires uppercase", "identity", "medium", "CIS AWS Benchmark v2.0 §1.5"),
    ("CIS-AWS-1.6",  "aws", "Ensure IAM password policy requires lowercase", "identity", "medium", "CIS AWS Benchmark v2.0 §1.6"),
    ("CIS-AWS-1.7",  "aws", "Ensure IAM password policy requires symbols",   "identity", "medium", "CIS AWS Benchmark v2.0 §1.7"),
    ("CIS-AWS-1.8",  "aws", "Ensure IAM password policy requires numbers",   "identity", "medium", "CIS AWS Benchmark v2.0 §1.8"),
    ("CIS-AWS-1.9",  "aws", "Ensure IAM password minimum length >= 14",      "identity", "medium", "CIS AWS Benchmark v2.0 §1.9"),
    ("CIS-AWS-1.10", "aws", "Ensure MFA enabled for all IAM users with console access", "identity", "high", "CIS AWS Benchmark v2.0 §1.10"),
    ("CIS-AWS-1.11", "aws", "Do not setup access keys during initial user setup", "identity", "medium", "CIS AWS Benchmark v2.0 §1.11"),
    ("CIS-AWS-1.12", "aws", "Ensure credentials unused >45 days are disabled", "identity", "high", "CIS AWS Benchmark v2.0 §1.12"),
    ("CIS-AWS-1.13", "aws", "Ensure only one active access key per IAM user", "identity", "medium", "CIS AWS Benchmark v2.0 §1.13"),
    ("CIS-AWS-1.14", "aws", "Ensure access keys are rotated every 90 days",  "identity", "high",   "CIS AWS Benchmark v2.0 §1.14"),
    ("CIS-AWS-1.15", "aws", "Ensure IAM users receive permissions only through groups", "identity", "medium", "CIS AWS Benchmark v2.0 §1.15"),
    ("CIS-AWS-1.16", "aws", "Ensure IAM policies are attached only to groups or roles", "identity", "medium", "CIS AWS Benchmark v2.0 §1.16"),
    ("CIS-AWS-1.17", "aws", "Maintain current contact details for AWS accounts", "identity", "low", "CIS AWS Benchmark v2.0 §1.17"),
    ("CIS-AWS-1.18", "aws", "Ensure security contact info registered on AWS account", "identity", "medium", "CIS AWS Benchmark v2.0 §1.18"),
    ("CIS-AWS-1.19", "aws", "Ensure IAM instance roles used for AWS resource access", "identity", "medium", "CIS AWS Benchmark v2.0 §1.19"),
    ("CIS-AWS-1.20", "aws", "Ensure a support role has been created to manage incidents", "identity", "low", "CIS AWS Benchmark v2.0 §1.20"),
    ("CIS-AWS-1.21", "aws", "Do not use AWS root account access key",              "identity", "critical", "CIS AWS Benchmark v2.0 §1.21"),
    ("CIS-AWS-2.1",  "aws", "Ensure CloudTrail is enabled in all regions",         "logging",  "critical", "CIS AWS Benchmark v2.0 §2.1"),
    ("CIS-AWS-2.2",  "aws", "Ensure CloudTrail log file validation is enabled",    "logging",  "high",     "CIS AWS Benchmark v2.0 §2.2"),
    ("CIS-AWS-2.3",  "aws", "Ensure S3 bucket storing CloudTrail logs is not public", "logging", "critical", "CIS AWS Benchmark v2.0 §2.3"),
    ("CIS-AWS-2.4",  "aws", "Ensure CloudTrail trails integrated with CloudWatch",  "logging",  "medium",   "CIS AWS Benchmark v2.0 §2.4"),
    ("CIS-AWS-2.5",  "aws", "Ensure AWS Config is enabled in all regions",          "logging",  "medium",   "CIS AWS Benchmark v2.0 §2.5"),
    ("CIS-AWS-2.6",  "aws", "Ensure S3 bucket access logging enabled on CloudTrail S3 bucket", "logging", "medium", "CIS AWS Benchmark v2.0 §2.6"),
    ("CIS-AWS-2.7",  "aws", "Ensure CloudTrail logs are encrypted at rest using KMS", "encryption", "high", "CIS AWS Benchmark v2.0 §2.7"),
    ("CIS-AWS-2.8",  "aws", "Ensure rotation for customer managed KMS keys is enabled", "encryption", "medium", "CIS AWS Benchmark v2.0 §2.8"),
    ("CIS-AWS-2.9",  "aws", "Ensure VPC flow logging is enabled in all VPCs",      "logging",  "medium",   "CIS AWS Benchmark v2.0 §2.9"),
    ("CIS-AWS-3.1",  "aws", "Ensure unauthorized API calls alarm exists",           "monitoring","medium",  "CIS AWS Benchmark v2.0 §3.1"),
    ("CIS-AWS-3.2",  "aws", "Ensure AWS Management Console sign-in without MFA alarm", "monitoring", "high", "CIS AWS Benchmark v2.0 §3.2"),
    ("CIS-AWS-3.3",  "aws", "Ensure root account usage alarm exists",               "monitoring","high",    "CIS AWS Benchmark v2.0 §3.3"),
    ("CIS-AWS-3.4",  "aws", "Ensure IAM policy changes alarm exists",               "monitoring","medium",  "CIS AWS Benchmark v2.0 §3.4"),
    ("CIS-AWS-3.5",  "aws", "Ensure CloudTrail config changes alarm exists",        "monitoring","medium",  "CIS AWS Benchmark v2.0 §3.5"),
    ("CIS-AWS-4.1",  "aws", "Ensure SSH port 22 not open to 0.0.0.0/0",            "network",  "critical", "CIS AWS Benchmark v2.0 §4.1"),
    ("CIS-AWS-4.2",  "aws", "Ensure RDP port 3389 not open to 0.0.0.0/0",          "network",  "critical", "CIS AWS Benchmark v2.0 §4.2"),
    ("CIS-AWS-4.3",  "aws", "Ensure security groups do not allow all ingress traffic", "network", "critical", "CIS AWS Benchmark v2.0 §4.3"),
    ("CIS-AWS-4.4",  "aws", "Ensure routing tables for VPC peering are least-access", "network", "medium", "CIS AWS Benchmark v2.0 §4.4"),
    ("CIS-AWS-5.1",  "aws", "Ensure S3 buckets use server-side encryption at rest", "encryption", "high", "CIS AWS Benchmark v2.0 §5.1"),
    ("CIS-AWS-5.2",  "aws", "Ensure S3 buckets have public access block enabled",   "storage",  "critical", "CIS AWS Benchmark v2.0 §5.2"),
    ("CIS-AWS-5.3",  "aws", "Ensure S3 bucket policies do not grant global write",  "storage",  "critical", "CIS AWS Benchmark v2.0 §5.3"),
    ("CIS-AWS-5.4",  "aws", "Ensure S3 bucket policies do not grant GetObject to *", "storage", "critical", "CIS AWS Benchmark v2.0 §5.4"),
    # ── Azure CIS Benchmark ────────────────────────────────────────────────────
    ("CIS-AZ-1.1",   "azure", "Ensure MFA enabled for all privileged users",    "identity",  "critical", "CIS Azure Benchmark v2.0 §1.1"),
    ("CIS-AZ-1.2",   "azure", "Ensure MFA status is Enabled for all users",     "identity",  "high",     "CIS Azure Benchmark v2.0 §1.2"),
    ("CIS-AZ-1.3",   "azure", "Ensure Guest Users are reviewed monthly",        "identity",  "medium",   "CIS Azure Benchmark v2.0 §1.3"),
    ("CIS-AZ-1.4",   "azure", "Ensure Guest invitations restricted to Admins",  "identity",  "medium",   "CIS Azure Benchmark v2.0 §1.4"),
    ("CIS-AZ-1.5",   "azure", "Ensure no custom subscription owner roles exist","identity",  "high",     "CIS Azure Benchmark v2.0 §1.5"),
    ("CIS-AZ-1.6",   "azure", "Ensure password protection enabled for on-prem AD","identity","high",     "CIS Azure Benchmark v2.0 §1.6"),
    ("CIS-AZ-2.1",   "azure", "Ensure ASC Default policy enabled on subscription","monitoring","medium",  "CIS Azure Benchmark v2.0 §2.1"),
    ("CIS-AZ-2.2",   "azure", "Ensure ASC email notifications for high severity","monitoring","high",     "CIS Azure Benchmark v2.0 §2.2"),
    ("CIS-AZ-2.3",   "azure", "Ensure subscription owner email notifications",  "monitoring","high",     "CIS Azure Benchmark v2.0 §2.3"),
    ("CIS-AZ-3.1",   "azure", "Ensure storage account public access disabled",  "storage",  "critical",  "CIS Azure Benchmark v2.0 §3.1"),
    ("CIS-AZ-3.2",   "azure", "Ensure storage account secure transfer (HTTPS) required", "encryption","high", "CIS Azure Benchmark v2.0 §3.2"),
    ("CIS-AZ-3.3",   "azure", "Ensure storage encryption uses customer-managed keys","encryption","medium","CIS Azure Benchmark v2.0 §3.3"),
    ("CIS-AZ-3.4",   "azure", "Ensure storage account shared key access disabled","identity","medium",    "CIS Azure Benchmark v2.0 §3.4"),
    ("CIS-AZ-3.5",   "azure", "Ensure soft delete enabled for Azure Blobs",     "storage",  "medium",    "CIS Azure Benchmark v2.0 §3.5"),
    ("CIS-AZ-4.1",   "azure", "Ensure Azure SQL server audit enabled",          "logging",  "high",      "CIS Azure Benchmark v2.0 §4.1"),
    ("CIS-AZ-4.2",   "azure", "Ensure SQL server audit retention >= 90 days",   "logging",  "medium",    "CIS Azure Benchmark v2.0 §4.2"),
    ("CIS-AZ-4.3",   "azure", "Ensure SQL server TDE enabled with CMK",        "encryption","medium",    "CIS Azure Benchmark v2.0 §4.3"),
    ("CIS-AZ-5.1",   "azure", "Ensure network watcher enabled in all regions", "network",  "medium",     "CIS Azure Benchmark v2.0 §5.1"),
    ("CIS-AZ-5.2",   "azure", "Ensure NSG flow logs retention >= 90 days",     "logging",  "medium",     "CIS Azure Benchmark v2.0 §5.2"),
    ("CIS-AZ-5.3",   "azure", "Ensure network access to storage accounts restricted","network","high",    "CIS Azure Benchmark v2.0 §5.3"),
    ("CIS-AZ-6.1",   "azure", "Ensure VM OS and data disks are encrypted",     "encryption","high",      "CIS Azure Benchmark v2.0 §6.1"),
    ("CIS-AZ-6.2",   "azure", "Ensure only approved VM extensions installed",  "compute",  "medium",     "CIS Azure Benchmark v2.0 §6.2"),
    # ── GCP CIS Benchmark ─────────────────────────────────────────────────────
    ("CIS-GCP-1.1",  "gcp", "Ensure corporate login credentials used",         "identity",  "high",     "CIS GCP Benchmark v2.0 §1.1"),
    ("CIS-GCP-1.2",  "gcp", "Ensure API keys not created for projects",        "identity",  "high",     "CIS GCP Benchmark v2.0 §1.2"),
    ("CIS-GCP-1.3",  "gcp", "Ensure service accounts not assigned Admin roles","identity",  "critical", "CIS GCP Benchmark v2.0 §1.3"),
    ("CIS-GCP-1.4",  "gcp", "Ensure service account keys rotated within 90 days","identity","high",     "CIS GCP Benchmark v2.0 §1.4"),
    ("CIS-GCP-1.5",  "gcp", "Ensure service account has no admin privileges",  "identity",  "critical", "CIS GCP Benchmark v2.0 §1.5"),
    ("CIS-GCP-1.6",  "gcp", "Ensure user-managed/external keys for service accts min", "identity","medium", "CIS GCP Benchmark v2.0 §1.6"),
    ("CIS-GCP-2.1",  "gcp", "Ensure Cloud Audit Logging enabled for all services","logging","high",     "CIS GCP Benchmark v2.0 §2.1"),
    ("CIS-GCP-2.2",  "gcp", "Ensure audit log retention >= 365 days",          "logging",  "medium",    "CIS GCP Benchmark v2.0 §2.2"),
    ("CIS-GCP-2.3",  "gcp", "Ensure VPC network firewall rule logging enabled","logging",  "medium",     "CIS GCP Benchmark v2.0 §2.3"),
    ("CIS-GCP-3.1",  "gcp", "Ensure default network not used in a project",    "network",  "high",      "CIS GCP Benchmark v2.0 §3.1"),
    ("CIS-GCP-3.2",  "gcp", "Ensure legacy networks not present in a project", "network",  "medium",    "CIS GCP Benchmark v2.0 §3.2"),
    ("CIS-GCP-3.3",  "gcp", "Ensure DNSSEC enabled for Cloud DNS",             "network",  "medium",    "CIS GCP Benchmark v2.0 §3.3"),
    ("CIS-GCP-3.4",  "gcp", "Ensure SSH port 22 not open to 0.0.0.0/0",       "network",  "critical",  "CIS GCP Benchmark v2.0 §3.4"),
    ("CIS-GCP-3.5",  "gcp", "Ensure RDP port 3389 not open to 0.0.0.0/0",     "network",  "critical",  "CIS GCP Benchmark v2.0 §3.5"),
    ("CIS-GCP-3.6",  "gcp", "Ensure firewall rules do not permit all traffic", "network",  "critical",  "CIS GCP Benchmark v2.0 §3.6"),
    ("CIS-GCP-4.1",  "gcp", "Ensure project-level default SA not used for resources","identity","high", "CIS GCP Benchmark v2.0 §4.1"),
    ("CIS-GCP-4.2",  "gcp", "Ensure VM instances not have public IP by default","network", "high",      "CIS GCP Benchmark v2.0 §4.2"),
    ("CIS-GCP-4.3",  "gcp", "Ensure VM disks are encrypted with CMK",          "encryption","medium",   "CIS GCP Benchmark v2.0 §4.3"),
    ("CIS-GCP-5.1",  "gcp", "Ensure Cloud Storage buckets not publicly accessible","storage","critical","CIS GCP Benchmark v2.0 §5.1"),
    ("CIS-GCP-5.2",  "gcp", "Ensure bucket logging enabled for Cloud Storage", "logging",  "medium",    "CIS GCP Benchmark v2.0 §5.2"),
    ("CIS-GCP-6.1",  "gcp", "Ensure Cloud SQL DB instances not publicly accessible","storage","critical","CIS GCP Benchmark v2.0 §6.1"),
    ("CIS-GCP-6.2",  "gcp", "Ensure Cloud SQL DB instances not have authorized networks 0.0.0.0/0", "network","critical","CIS GCP Benchmark v2.0 §6.2"),
    ("CIS-GCP-6.3",  "gcp", "Ensure Cloud SQL DB instances have SSL enforcement","encryption","high",   "CIS GCP Benchmark v2.0 §6.3"),
    ("CIS-GCP-6.4",  "gcp", "Ensure PostgreSQL log connections flag set to on","logging",  "medium",    "CIS GCP Benchmark v2.0 §6.4"),
    ("CIS-GCP-6.5",  "gcp", "Ensure PostgreSQL log disconnections flag set to on","logging","low",      "CIS GCP Benchmark v2.0 §6.5"),
]


def make_cspm_checks() -> list[dict]:
    checks = []
    for check_id, provider, name, category, severity, framework_ref in CSPM_CHECKS_DATA:
        checks.append({
            "check_id": check_id,
            "cloud_provider": provider,
            "title": name,
            "section": category,
            "severity": severity,
            "framework": framework_ref,
            "description": f"Control {check_id}: {name}. Assessed against {framework_ref}.",
            "remediation_steps": (
                f"1. Review configuration for {name.lower()}. "
                f"2. Apply least-privilege principle. "
                f"3. Enable recommended security control. "
                f"4. Validate compliance via Config/Security Center."
            ),
            "automated": True,
            "created_at": days_ago(rng.randint(180, 730)),
        })
    return checks


FINDING_RESOURCES = {
    "identity":    ["arn:aws:iam::account/user/svc-deploy","arn:aws:iam::account/role/AdminRole","azure://subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/ra-001","gcp://projects/proj/serviceAccounts/svc@proj.iam.gserviceaccount.com"],
    "storage":     ["arn:aws:s3:::company-backups-prod","arn:aws:s3:::customer-data-lake","azure://subscriptions/sub/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/stgprod001","gcp://projects/proj/buckets/prod-analytics-data"],
    "network":     ["arn:aws:ec2::region:security-group/sg-open-ssh","arn:aws:ec2::region:security-group/sg-rdp-world","azure://subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-prod","gcp://projects/proj/global/firewalls/allow-all-ingress"],
    "encryption":  ["arn:aws:rds::region:db:prod-postgres-primary","arn:aws:s3:::company-docs-internal","azure://subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-prod-01","gcp://projects/proj/disks/k8s-node-disk-01"],
    "logging":     ["arn:aws:s3:::cloudtrail-logs","arn:aws:cloudtrail::region:trail/org-trail","azure://subscriptions/sub/providers/microsoft.insights/diagnosticSettings","gcp://projects/proj/logs/cloudaudit.googleapis.com%2Factivity"],
    "monitoring":  ["arn:aws:cloudwatch::region:alarm/root-login-alarm","azure://subscriptions/sub/providers/Microsoft.Security/pricings/default","gcp://projects/proj/alertPolicies/iam-changes-alert"],
    "compute":     ["arn:aws:ec2::region:instance/i-0abc123def456","azure://subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-web-01","gcp://projects/proj/zones/us-central1-a/instances/web-server-01"],
}

FINDING_EVIDENCE = [
    "Automated scan detected non-compliant configuration. No exception on record.",
    "Policy evaluation found resource does not meet baseline requirement.",
    "Configuration drift detected from approved baseline during weekly assessment.",
    "Resource created without required control applied — not caught at provisioning time.",
    "Inherited permissive policy not overridden at resource level.",
    "Legacy configuration predates current security baseline — not yet migrated.",
    "Temporary exception expired without renewal — resource reverted to non-compliant.",
    "Terraform state drift — manual change bypassed IaC guardrail.",
]


def make_cspm_findings(accounts: list[dict], checks_with_ids: list[dict], target: int = 4000) -> list[dict]:
    findings = []
    seen = set()

    check_by_provider = {}
    for c in checks_with_ids:
        check_by_provider.setdefault(c["cloud_provider"], []).append(c)

    per_account = max(1, target // len(accounts))

    for account in accounts:
        provider = account["cloud_provider"]
        available_checks = check_by_provider.get(provider, [])
        if not available_checks:
            continue

        account_findings = min(per_account + rng.randint(-10, 20), len(available_checks) * 3)
        added = 0
        attempts = 0

        while added < account_findings and attempts < account_findings * 5:
            attempts += 1
            check = rng.choice(available_checks)
            resource = rng.choice(FINDING_RESOURCES.get(check["section"], FINDING_RESOURCES["compute"]))
            key = (account["_id"], check["_id"], resource[:60])
            if key in seen:
                continue
            seen.add(key)

            first_seen = days_ago(rng.randint(1, 180))
            status_choice = rng.choices(
                ["open","suppressed","resolved","accepted_risk"],
                weights=[55, 10, 25, 10]
            )[0]

            findings.append({
                "cloud_account_id": account["_id"],
                "check_id": check["_id"],
                "resource_id": resource,
                "resource_type": check["section"],
                "resource_name": resource.split("/")[-1][:120],
                "region": account.get("region_primary", "us-east-1"),
                "status": status_choice,
                "severity": check["severity"],
                "title": check["title"],
                "description": check["description"],
                "evidence": {"detail": rng.choice(FINDING_EVIDENCE), "check": check["check_id"]},
                "remediation_effort": rng.choice(["low","medium","high"]),
                "first_seen_at": first_seen,
                "last_seen_at": days_ago(rng.randint(0, 10)),
                "resolved_at": days_ago(rng.randint(0, 30)) if status_choice == "resolved" else None,
                "created_at": first_seen,
                "updated_at": days_ago(rng.randint(0, 10)),
            })
            added += 1

    return findings


# ── Flush helpers ─────────────────────────────────────────────────────────────

async def flush_chunk(session: AsyncSession, objs: list, chunk_size: int = 200) -> list[int]:
    """Add objects in chunks, flush after each chunk. Returns list of PKs."""
    all_ids = []
    for i in range(0, len(objs), chunk_size):
        chunk = objs[i:i + chunk_size]
        session.add_all(chunk)
        await session.flush()
        all_ids.extend(obj.id for obj in chunk)
    return all_ids


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    async with async_session() as session:
        print("Truncating existing enterprise tables...")
        await session.execute(text("""
            TRUNCATE TABLE
                cspm_findings,
                cspm_checks,
                vm_asset_vulnerabilities,
                vm_vulnerabilities,
                product_registry_products,
                product_registry_cloud_accounts,
                cmdb_hardware_assets,
                cmdb_people
            RESTART IDENTITY CASCADE
        """))
        await session.commit()
        print("  done.\n")

        # ── People ────────────────────────────────────────────────────────────
        print("Creating 500 people...")
        people_data = make_people(500)
        people_objs = [CMDBPerson(**{k: v for k, v in p.items() if k != "_id"}) for p in people_data]
        await flush_chunk(session, people_objs)
        await session.commit()
        # Backfill runtime IDs for manager assignment — not needed here (UUIDs used)
        print(f"  Created {len(people_objs)} people.\n")

        # ── Assets ────────────────────────────────────────────────────────────
        print("Creating 1500 hardware assets...")
        assets_data = make_assets(people_data, 1500)
        asset_objs = [CMDBHardwareAsset(**{k: v for k, v in a.items() if k != "_id"}) for a in assets_data]
        await flush_chunk(session, asset_objs, 300)
        await session.flush()
        # Store PKs for vulnerability linking
        for i, obj in enumerate(asset_objs):
            assets_data[i]["_id"] = obj.id
        await session.commit()
        print(f"  Created {len(asset_objs)} assets.\n")

        # ── Cloud Accounts ────────────────────────────────────────────────────
        print("Creating 30 cloud accounts...")
        cloud_data = make_cloud_accounts()
        cloud_objs = [ProductCloudAccount(**{k: v for k, v in c.items() if k != "_id"}) for c in cloud_data]
        await flush_chunk(session, cloud_objs)
        await session.flush()
        for i, obj in enumerate(cloud_objs):
            cloud_data[i]["_id"] = obj.id
        await session.commit()
        print(f"  Created {len(cloud_objs)} cloud accounts.\n")

        # ── Products ──────────────────────────────────────────────────────────
        print("Creating 54 products...")
        products_data = make_products(cloud_data)
        product_objs = [ProductRegistryProduct(**{k: v for k, v in p.items() if k != "_id"}) for p in products_data]
        await flush_chunk(session, product_objs)
        await session.commit()
        print(f"  Created {len(product_objs)} products.\n")

        # ── Vulnerabilities ───────────────────────────────────────────────────
        print("Creating vulnerabilities...")
        vuln_data = make_vulnerabilities()
        vuln_objs = [VMVulnerability(**{k: v for k, v in v.items() if k != "_id"}) for v in vuln_data]
        await flush_chunk(session, vuln_objs)
        await session.flush()
        vuln_ids = [obj.id for obj in vuln_objs]
        await session.commit()
        print(f"  Created {len(vuln_objs)} CVEs.\n")

        # ── Asset-Vulnerability Links ─────────────────────────────────────────
        print("Creating ~8000 asset-vulnerability instances...")
        av_data = make_asset_vulnerabilities(assets_data, vuln_ids, target=8000)
        av_objs = [VMAssetVulnerability(**{k: v for k, v in av.items()}) for av in av_data]
        await flush_chunk(session, av_objs, 500)
        await session.commit()
        print(f"  Created {len(av_objs)} asset-vulnerability links.\n")

        # ── CSPM Checks ───────────────────────────────────────────────────────
        print("Creating CSPM checks...")
        checks_data = make_cspm_checks()
        check_objs = [CSPMCheck(**{k: v for k, v in c.items() if k != "_id"}) for c in checks_data]
        await flush_chunk(session, check_objs)
        await session.flush()
        # Build enriched list with real PKs
        checks_with_ids = []
        for i, obj in enumerate(check_objs):
            d = dict(checks_data[i])
            d["_id"] = obj.id
            checks_with_ids.append(d)
        await session.commit()
        print(f"  Created {len(check_objs)} CSPM checks.\n")

        # ── CSPM Findings ─────────────────────────────────────────────────────
        print("Creating ~4000 CSPM findings...")
        findings_data = make_cspm_findings(cloud_data, checks_with_ids, target=4000)
        finding_objs = [CSPMFinding(**{k: v for k, v in f.items()}) for f in findings_data]
        await flush_chunk(session, finding_objs, 500)
        await session.commit()
        print(f"  Created {len(finding_objs)} CSPM findings.\n")

    print("=" * 60)
    print("Enterprise seed complete!")
    print(f"  People:                {len(people_objs):>6}")
    print(f"  Hardware assets:       {len(asset_objs):>6}")
    print(f"  Cloud accounts:        {len(cloud_objs):>6}")
    print(f"  Products:              {len(product_objs):>6}")
    print(f"  CVEs:                  {len(vuln_objs):>6}")
    print(f"  Asset-vuln links:      {len(av_objs):>6}")
    print(f"  CSPM checks:           {len(check_objs):>6}")
    print(f"  CSPM findings:         {len(finding_objs):>6}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
