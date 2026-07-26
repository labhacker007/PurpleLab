'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Shield, Server, FileText, Zap, Database, Users, Network, Globe,
  Key, Search, AlertTriangle, Lock, ChevronDown, ChevronRight, Copy
} from 'lucide-react'

const BASE = typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8002` : 'http://localhost:8002'

interface Vendor {
  name: string
  file: string
  category: string
  color: string
  authType: string
  authExample: string
  baseUrl: string
  keyEndpoints: { method: string; path: string; desc: string }[]
  jotiConnectorType: string
}

const VENDORS: Vendor[] = [
  // EDR / XDR
  {
    name: 'CrowdStrike Falcon', file: 'crowdstrike.py', category: 'EDR/XDR', color: 'text-blue-400',
    authType: 'OAuth2 Bearer', baseUrl: '/api/vendor/crowdstrike',
    authExample: 'POST /api/vendor/crowdstrike/oauth2/token  body: client_id=x&client_secret=y',
    keyEndpoints: [
      { method: 'GET', path: '/devices/queries/devices/v1?filter=hostname:\'CORP-WS-001\'', desc: 'FQL device search' },
      { method: 'GET', path: '/devices/entities/devices/v2?ids=abc123', desc: 'Device details' },
      { method: 'POST', path: '/devices/entities/devices-actions/v2?action_name=contain', desc: 'Contain host' },
      { method: 'GET', path: '/detects/queries/detects/v1?filter=status:!\'closed\'', desc: 'Open detections' },
      { method: 'GET', path: '/spotlight/queries/vulnerabilities/v1?filter=severity_name:\'CRITICAL\'', desc: 'Spotlight vulns' },
      { method: 'POST', path: '/iocs/entities/indicators/v1', desc: 'Create IOC block' },
      { method: 'POST', path: '/real-time-response/entities/sessions/v1', desc: 'Start RTR session' },
    ],
    jotiConnectorType: 'crowdstrike',
  },
  {
    name: 'Microsoft Defender MDE', file: 'defender.py', category: 'EDR/XDR', color: 'text-blue-400',
    authType: 'OAuth2 Bearer (tenant)', baseUrl: '/api/vendor/defender',
    authExample: 'POST /api/vendor/defender/{tenant_id}/oauth2/v2.0/token  body: client_id=x&client_secret=y&scope=...',
    keyEndpoints: [
      { method: 'GET', path: '/api/machines?$filter=computerDnsName eq \'CORP-WS-001\'', desc: 'OData machine filter' },
      { method: 'GET', path: '/api/alerts?$filter=severity eq \'High\'', desc: 'High severity alerts' },
      { method: 'POST', path: '/api/machines/{id}/isolate', desc: 'Isolate machine' },
      { method: 'POST', path: '/api/advancedqueries/run', desc: 'Advanced Hunting KQL' },
      { method: 'GET', path: '/api/vulnerabilities/machinesVulnerabilities', desc: 'TVM vulnerabilities' },
      { method: 'POST', path: '/api/indicators', desc: 'Custom indicator/IOC block' },
    ],
    jotiConnectorType: 'mde',
  },
  {
    name: 'SentinelOne Singularity', file: 'sentinelone.py', category: 'EDR/XDR', color: 'text-blue-400',
    authType: 'ApiToken header', baseUrl: '/api/vendor/sentinelone',
    authExample: 'Header: Authorization: ApiToken <your-token>',
    keyEndpoints: [
      { method: 'GET', path: '/web/api/v2.1/agents?computerName=CORP-WS-001', desc: 'Agent list with filters' },
      { method: 'POST', path: '/web/api/v2.1/agents/actions/disconnect', desc: 'Disconnect/isolate agent' },
      { method: 'GET', path: '/web/api/v2.1/threats?resolved=false', desc: 'Active threats' },
      { method: 'POST', path: '/web/api/v2.1/threats/mitigate/kill', desc: 'Kill threat' },
      { method: 'POST', path: '/web/api/v2.1/dv/init-query', desc: 'Deep Visibility query init' },
      { method: 'GET', path: '/web/api/v2.1/dv/events?queryId=X', desc: 'Poll DV results' },
    ],
    jotiConnectorType: 'sentinelone',
  },
  {
    name: 'VMware Carbon Black', file: 'carbonblack.py', category: 'EDR/XDR', color: 'text-blue-400',
    authType: 'Bearer org_key', baseUrl: '/api/vendor/carbonblack',
    authExample: 'Header: X-Auth-Token: <api_key>/<org_key>',
    keyEndpoints: [
      { method: 'POST', path: '/appservices/v6/orgs/{org}/devices/_search', desc: 'Search devices' },
      { method: 'POST', path: '/appservices/v6/orgs/{org}/device_actions', desc: 'Isolate/quarantine' },
      { method: 'POST', path: '/appservices/v6/orgs/{org}/alerts/_search', desc: 'Search alerts' },
      { method: 'POST', path: '/threathunter/feedmgr/v2/orgs/{org}/feeds', desc: 'IOC watchlist feed' },
    ],
    jotiConnectorType: 'carbonblack',
  },
  {
    name: 'Palo Alto XSIAM', file: 'xsiam.py', category: 'EDR/XDR', color: 'text-blue-400',
    authType: 'HMAC x-xdr-auth-id + x-xdr-nonce', baseUrl: '/api/vendor/xsiam',
    authExample: 'Headers: x-xdr-auth-id: 1, x-xdr-nonce: <rand>, x-xdr-timestamp: <ms>, Authorization: <hmac>',
    keyEndpoints: [
      { method: 'POST', path: '/public_api/v1/xql/start_xql_query', desc: 'Start async XQL query' },
      { method: 'POST', path: '/public_api/v1/xql/get_query_results', desc: 'Poll XQL results' },
      { method: 'POST', path: '/public_api/v1/incidents/get_incidents', desc: 'Get incidents' },
      { method: 'POST', path: '/public_api/v1/endpoints/isolate', desc: 'Isolate endpoint' },
      { method: 'POST', path: '/public_api/v1/indicators/insert_jsons', desc: 'Block IOC' },
    ],
    jotiConnectorType: 'xsiam',
  },
  // SIEM
  {
    name: 'Splunk Enterprise Security', file: 'splunk.py', category: 'SIEM', color: 'text-yellow-400',
    authType: 'Basic Auth / session key', baseUrl: '/api/vendor/splunk',
    authExample: 'Header: Authorization: Basic base64(admin:changeme)  OR  use session_key from /auth/login',
    keyEndpoints: [
      { method: 'POST', path: '/services/search/jobs', desc: 'Create search job (form-encoded)' },
      { method: 'GET', path: '/services/search/jobs/{sid}/results?output_mode=json', desc: 'Get results' },
      { method: 'POST', path: '/services/notable_update', desc: 'Update notable event status/owner' },
      { method: 'GET', path: '/servicesNS/nobody/SA-ITSI/storage/collections/data/{collection}', desc: 'KV Store read' },
      { method: 'GET', path: '/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches', desc: 'Saved searches' },
    ],
    jotiConnectorType: 'splunk',
  },
  {
    name: 'IBM QRadar SIEM', file: 'qradar.py', category: 'SIEM', color: 'text-yellow-400',
    authType: 'SEC token header', baseUrl: '/api/vendor/qradar',
    authExample: 'Header: SEC: <api-token>',
    keyEndpoints: [
      { method: 'POST', path: '/api/ariel/searches', desc: 'Start AQL search' },
      { method: 'GET', path: '/api/ariel/searches/{id}/results', desc: 'Get results' },
      { method: 'GET', path: '/api/siem/offenses?filter=status%3DOPEN', desc: 'Open offenses' },
      { method: 'POST', path: '/api/siem/offenses/{id}/notes', desc: 'Add offense note' },
      { method: 'GET', path: '/api/reference_data/sets/{name}', desc: 'Reference set (IOC list)' },
    ],
    jotiConnectorType: 'qradar',
  },
  {
    name: 'Elastic SIEM', file: 'elastic.py', category: 'SIEM', color: 'text-yellow-400',
    authType: 'Basic Auth / API key', baseUrl: '/api/vendor/elastic',
    authExample: 'Header: Authorization: ApiKey <base64_id:key>',
    keyEndpoints: [
      { method: 'POST', path: '/{index}/_search', desc: 'Search with ESQL/DSL' },
      { method: 'GET', path: '/api/detection_engine/rules', desc: 'List detection rules' },
      { method: 'POST', path: '/api/detection_engine/rules', desc: 'Create detection rule' },
      { method: 'GET', path: '/api/detection_engine/signals/search', desc: 'Search signals/alerts' },
    ],
    jotiConnectorType: 'elastic',
  },
  // VM / CSPM
  {
    name: 'Tenable.io', file: 'tenable.py', category: 'VM/CSPM', color: 'text-purple-400',
    authType: 'X-ApiKeys header', baseUrl: '/api/vendor/tenable',
    authExample: 'Header: X-ApiKeys: accessKey=<key>;secretKey=<secret>',
    keyEndpoints: [
      { method: 'POST', path: '/vulns/export', desc: 'Start async vuln export' },
      { method: 'GET', path: '/vulns/export/{uuid}/status', desc: 'Poll export status' },
      { method: 'GET', path: '/vulns/export/{uuid}/chunks/{chunk}', desc: 'Download chunk' },
      { method: 'GET', path: '/assets', desc: 'Asset inventory' },
      { method: 'GET', path: '/workbenches/vulnerabilities', desc: 'Vuln workbench' },
    ],
    jotiConnectorType: 'tenable',
  },
  {
    name: 'Qualys VMDR', file: 'qualys.py', category: 'VM/CSPM', color: 'text-purple-400',
    authType: 'Basic Auth + session token', baseUrl: '/api/vendor/qualys',
    authExample: 'POST /api/2.0/fo/session/ with username/password → get QualysSession cookie',
    keyEndpoints: [
      { method: 'GET', path: '/api/2.0/fo/asset/host/?action=list&details=All', desc: 'Host list (XML)' },
      { method: 'GET', path: '/api/2.0/fo/asset/host/vm/detection/?action=list', desc: 'Vuln detections (XML)' },
      { method: 'GET', path: '/api/2.0/fo/knowledge_base/vuln/?action=list&ids=90882', desc: 'KB vuln detail' },
      { method: 'POST', path: '/api/2.0/fo/scan/?action=launch', desc: 'Launch scan' },
    ],
    jotiConnectorType: 'qualys',
  },
  {
    name: 'Wiz CSPM', file: 'wiz.py', category: 'VM/CSPM', color: 'text-purple-400',
    authType: 'OAuth2 Bearer', baseUrl: '/api/vendor/wiz',
    authExample: 'POST /api/vendor/wiz/oauth/token  body: client_id=x&client_secret=y&audience=wiz-api&grant_type=client_credentials',
    keyEndpoints: [
      { method: 'POST', path: '/graphql', desc: 'Single endpoint — all queries (issues, resources, controls, frameworks)' },
      { method: 'GET', path: '/api/v1/issues?severity=CRITICAL', desc: 'REST: list issues' },
      { method: 'GET', path: '/api/v1/cloud-resources', desc: 'REST: cloud resources' },
      { method: 'GET', path: '/api/v1/controls', desc: 'REST: security controls' },
    ],
    jotiConnectorType: 'wiz',
  },
  // ITSM
  {
    name: 'ServiceNow ITSM', file: 'servicenow.py', category: 'ITSM', color: 'text-orange-400',
    authType: 'Basic Auth / OAuth Bearer', baseUrl: '/api/vendor/servicenow',
    authExample: 'Header: Authorization: Basic base64(admin:admin)  OR  Bearer token from /oauth_token.do',
    keyEndpoints: [
      { method: 'GET', path: '/api/now/table/incident?sysparm_query=state=1^priority=1', desc: 'Open critical incidents' },
      { method: 'POST', path: '/api/now/table/incident', desc: 'Create incident' },
      { method: 'PATCH', path: '/api/now/table/incident/{sys_id}', desc: 'Update incident' },
      { method: 'GET', path: '/api/now/table/cmdb_ci_computer?sysparm_query=name=CORP-WS-001', desc: 'CMDB asset lookup' },
      { method: 'GET', path: '/api/now/table/change_request?sysparm_query=state=assess', desc: 'Pending changes' },
    ],
    jotiConnectorType: 'servicenow',
  },
  {
    name: 'Jira Cloud / JSM', file: 'jira.py', category: 'ITSM', color: 'text-orange-400',
    authType: 'Basic Auth (email:token)', baseUrl: '/api/vendor/jira',
    authExample: 'Header: Authorization: Basic base64(user@example.com:api_token)',
    keyEndpoints: [
      { method: 'GET', path: '/rest/api/3/search?jql=project=SEC+AND+status!=Done', desc: 'JQL issue search' },
      { method: 'POST', path: '/rest/api/3/issue', desc: 'Create issue' },
      { method: 'POST', path: '/rest/api/3/issue/{key}/transitions', desc: 'Transition issue status' },
      { method: 'GET', path: '/rest/agile/1.0/board', desc: 'Agile boards' },
      { method: 'GET', path: '/rest/servicedeskapi/servicedesk', desc: 'JSM service desks' },
    ],
    jotiConnectorType: 'jira',
  },
  // IAM
  {
    name: 'Okta Identity', file: 'okta.py', category: 'IAM', color: 'text-red-400',
    authType: 'SSWS API token', baseUrl: '/api/vendor/okta',
    authExample: 'Header: Authorization: SSWS <api-token>',
    keyEndpoints: [
      { method: 'GET', path: '/api/v1/users?search=profile.login+sw+"jsmith"', desc: 'Search users' },
      { method: 'POST', path: '/api/v1/users/{id}/lifecycle/suspend', desc: 'Suspend user' },
      { method: 'DELETE', path: '/api/v1/sessions/{id}', desc: 'Revoke session' },
      { method: 'GET', path: '/api/v1/logs?filter=outcome.result+eq+"FAILURE"', desc: 'Audit logs' },
      { method: 'GET', path: '/api/v1/policies', desc: 'Sign-on policies' },
    ],
    jotiConnectorType: 'okta',
  },
  {
    name: 'Microsoft Entra ID', file: 'entra_id.py', category: 'IAM', color: 'text-red-400',
    authType: 'OAuth2 Bearer (Graph API)', baseUrl: '/api/vendor/entra_id',
    authExample: 'POST /oauth2/v2.0/token  scope=https://graph.microsoft.com/.default',
    keyEndpoints: [
      { method: 'GET', path: '/v1.0/users?$filter=displayName eq \'John Smith\'', desc: 'User lookup' },
      { method: 'POST', path: '/v1.0/users/{id}/revokeSignInSessions', desc: 'Revoke sessions' },
      { method: 'GET', path: '/v1.0/identityProtection/riskyUsers', desc: 'Risky users' },
      { method: 'GET', path: '/v1.0/identity/conditionalAccess/policies', desc: 'Conditional Access policies' },
    ],
    jotiConnectorType: 'entra',
  },
  // Network
  {
    name: 'Palo Alto Panorama', file: 'panorama.py', category: 'Network', color: 'text-green-400',
    authType: 'API key in query param', baseUrl: '/api/vendor/panorama',
    authExample: 'GET /api/?type=keygen&user=admin&password=admin  → returns <key>value</key>',
    keyEndpoints: [
      { method: 'GET', path: '/api/?type=config&action=get&xpath=/config/devices', desc: 'Get config' },
      { method: 'GET', path: '/api/?type=op&cmd=<show><system><info></info></system></show>', desc: 'System info' },
      { method: 'GET', path: '/api/?type=log&log-type=threat&nlogs=20', desc: 'Threat logs' },
      { method: 'POST', path: '/api/?type=commit&cmd=<commit></commit>', desc: 'Commit policy' },
    ],
    jotiConnectorType: 'panorama',
  },
]

const CATEGORIES = ['All', 'EDR/XDR', 'SIEM', 'VM/CSPM', 'ITSM', 'IAM', 'Network']
const CATEGORY_COLORS: Record<string, string> = {
  'EDR/XDR': 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  'SIEM': 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  'VM/CSPM': 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  'ITSM': 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  'IAM': 'bg-red-500/10 text-red-400 border-red-500/30',
  'Network': 'bg-green-500/10 text-green-400 border-green-500/30',
}

function VendorCard({ vendor }: { vendor: Vendor }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)

  function copy(text: string) {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const fullBaseUrl = `http://localhost:8002${vendor.baseUrl}`

  return (
    <Card className="border border-border bg-card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left"
      >
        <CardHeader className="pb-2 pt-4 px-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <span className={`text-sm font-semibold text-foreground truncate`}>{vendor.name}</span>
              <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium ${CATEGORY_COLORS[vendor.category]}`}>
                {vendor.category}
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="text-[10px] text-muted-foreground font-mono hidden sm:block">{vendor.authType}</span>
              {expanded ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
            </div>
          </div>
        </CardHeader>
      </button>

      {expanded && (
        <CardContent className="px-4 pb-4 space-y-3">
          {/* Base URL */}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Base URL (PurpleLab simulation)</p>
            <div className="flex items-center gap-2 bg-muted/40 rounded px-3 py-1.5">
              <code className="text-xs font-mono text-foreground flex-1 break-all">{fullBaseUrl}</code>
              <button onClick={() => copy(fullBaseUrl)} className="shrink-0 text-muted-foreground hover:text-foreground">
                <Copy className="h-3 w-3" />
              </button>
            </div>
          </div>

          {/* Auth */}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Authentication</p>
            <div className="bg-muted/40 rounded px-3 py-1.5">
              <code className="text-xs font-mono text-foreground break-all">{vendor.authExample}</code>
            </div>
          </div>

          {/* Endpoints */}
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Key Endpoints</p>
            <div className="space-y-1">
              {vendor.keyEndpoints.map((ep, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className={`shrink-0 font-mono font-bold text-[10px] mt-0.5 w-10 ${
                    ep.method === 'GET' ? 'text-green-400' :
                    ep.method === 'POST' ? 'text-blue-400' :
                    ep.method === 'PATCH' || ep.method === 'PUT' ? 'text-amber-400' : 'text-red-400'
                  }`}>{ep.method}</span>
                  <code className="text-muted-foreground font-mono text-[10px] flex-1 break-all">{ep.path}</code>
                  <span className="text-muted-foreground text-[10px] shrink-0 hidden md:block">{ep.desc}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Joti connector hint */}
          <div className="rounded bg-primary/5 border border-primary/20 px-3 py-2">
            <p className="text-[10px] text-primary font-medium">Joti connector type: <code className="font-mono">{vendor.jotiConnectorType}</code></p>
            <p className="text-[10px] text-muted-foreground mt-0.5">Point Joti connector base URL to <code className="font-mono">http://purplelab-backend:8000{vendor.baseUrl}</code></p>
          </div>
        </CardContent>
      )}
    </Card>
  )
}

export default function GuidePage() {
  const [categoryFilter, setCategoryFilter] = useState('All')
  const [search, setSearch] = useState('')

  const filtered = VENDORS.filter(v =>
    (categoryFilter === 'All' || v.category === categoryFilter) &&
    (search === '' || v.name.toLowerCase().includes(search.toLowerCase()) || v.category.toLowerCase().includes(search.toLowerCase()))
  )

  const counts = CATEGORIES.slice(1).map(c => ({ cat: c, n: VENDORS.filter(v => v.category === c).length }))

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-foreground">User Guide</h1>
        <p className="text-sm text-muted-foreground mt-1">
          PurpleLab simulates 16 enterprise security products at the API level, grounded in official documentation.
          Connect Joti connectors to these endpoints to test your SOAR playbooks and detection workflows against realistic responses.
        </p>
      </div>

      <Tabs defaultValue="vendors">
        <TabsList>
          <TabsTrigger value="vendors">Vendor APIs (16)</TabsTrigger>
          <TabsTrigger value="seed">Seed Data</TabsTrigger>
          <TabsTrigger value="connect">Connecting from Joti</TabsTrigger>
          <TabsTrigger value="workflows">Workflows</TabsTrigger>
        </TabsList>

        {/* ── Vendor APIs tab ── */}
        <TabsContent value="vendors" className="space-y-4 mt-4">
          {/* Stats */}
          <div className="flex flex-wrap gap-2">
            {counts.map(({ cat, n }) => (
              <span key={cat} className={`rounded border px-2 py-1 text-xs font-medium ${CATEGORY_COLORS[cat]}`}>
                {cat} ×{n}
              </span>
            ))}
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <input
              className="field px-3 py-1.5 text-sm w-56"
              placeholder="Search vendors..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <div className="flex flex-wrap gap-1">
              {CATEGORIES.map(c => (
                <button
                  key={c}
                  onClick={() => setCategoryFilter(c)}
                  className={`rounded px-2 py-1 text-xs font-medium transition-colors ${
                    categoryFilter === c
                      ? 'bg-primary text-white'
                      : 'bg-muted/40 text-muted-foreground hover:text-foreground border border-border'
                  }`}
                >{c}</button>
              ))}
            </div>
          </div>

          {/* Cards */}
          <div className="space-y-2">
            {filtered.map(v => <VendorCard key={v.file} vendor={v} />)}
            {filtered.length === 0 && (
              <div className="text-center py-8 text-sm text-muted-foreground">No vendors match your filter.</div>
            )}
          </div>
        </TabsContent>

        {/* ── Seed Data tab ── */}
        <TabsContent value="seed" className="mt-4">
          <div className="space-y-4">
            <Card>
              <CardHeader><CardTitle className="text-sm">Simulated Endpoints</CardTitle></CardHeader>
              <CardContent>
                <table className="w-full text-xs">
                  <thead className="bg-muted/60 text-muted-foreground border-b border-border">
                    <tr>
                      <th className="text-left px-3 py-2">Hostname</th>
                      <th className="text-left px-3 py-2">IP</th>
                      <th className="text-left px-3 py-2">Role</th>
                      <th className="text-left px-3 py-2">OS</th>
                      <th className="text-left px-3 py-2">User</th>
                      <th className="text-left px-3 py-2">Tier</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { host: 'CORP-WS-001', ip: '10.10.1.101', role: 'Workstation', os: 'Windows 11 Pro', user: 'jsmith', tier: 'T2 (standard)' },
                      { host: 'CORP-SRV-001', ip: '10.10.2.10', role: 'File Server', os: 'Windows Server 2022', user: 'svcFileShare', tier: 'T1 (high value)' },
                      { host: 'CORP-DC-001', ip: '10.10.2.1', role: 'Domain Controller', os: 'Windows Server 2022', user: 'SYSTEM', tier: 'T0 (critical)' },
                    ].map(r => (
                      <tr key={r.host} className="border-b border-border">
                        <td className="px-3 py-2 font-mono font-bold text-foreground">{r.host}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{r.ip}</td>
                        <td className="px-3 py-2">{r.role}</td>
                        <td className="px-3 py-2 text-muted-foreground">{r.os}</td>
                        <td className="px-3 py-2 font-mono">{r.user}</td>
                        <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 text-[10px] border ${r.tier.startsWith('T0') ? 'bg-red-500/10 text-red-400 border-red-500/30' : r.tier.startsWith('T1') ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-muted text-muted-foreground border-border'}`}>{r.tier}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-sm">Active Threats (pre-loaded)</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {[
                  { title: 'PowerShell Encoded Command', technique: 'T1059.001', tactic: 'Execution', host: 'CORP-WS-001', severity: 'High', detail: 'WINWORD.EXE spawned powershell.exe -EncodedCommand SVBDb...' },
                  { title: 'LSASS Memory Access', technique: 'T1003.001', tactic: 'Credential Access', host: 'CORP-WS-001', severity: 'Critical', detail: 'mimikatz.exe opened handle to lsass.exe (PID 668)' },
                  { title: 'CVE-2024-21413 (Outlook RCE)', technique: 'T1203', tactic: 'Initial Access', host: 'CORP-WS-001', severity: 'Critical', detail: 'CVSS 9.8 — Microsoft Outlook Remote Code Execution' },
                ].map((t, i) => (
                  <div key={i} className="rounded border border-border bg-muted/20 p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-foreground">{t.title}</span>
                      <span className={`rounded border px-1.5 py-0.5 text-[10px] ${t.severity === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'}`}>{t.severity}</span>
                    </div>
                    <div className="flex gap-3 text-[10px] text-muted-foreground">
                      <span className="font-mono">{t.technique}</span>
                      <span>{t.tactic}</span>
                      <span>{t.host}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-1 font-mono">{t.detail}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Connecting from Joti tab ── */}
        <TabsContent value="connect" className="mt-4 space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm">Network Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm">
              <p className="text-muted-foreground">Joti connectors must use the Docker internal hostname, not localhost:</p>
              <div className="rounded bg-muted/40 p-3 space-y-1">
                <div className="flex gap-2 text-xs">
                  <span className="text-red-400 w-16 shrink-0">❌ Wrong</span>
                  <code className="font-mono">http://localhost:8002/api/vendor/crowdstrike</code>
                </div>
                <div className="flex gap-2 text-xs">
                  <span className="text-green-400 w-16 shrink-0">✅ Correct</span>
                  <code className="font-mono">http://purplelab-backend:8000/api/vendor/crowdstrike</code>
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">Both Joti and PurpleLab must be on the same Docker network. See <code className="font-mono">docker-compose.yml</code> network config.</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Step-by-Step: Connect CrowdStrike Connector</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {[
                'In Joti: Admin → Connectors → Add Connector → select CrowdStrike Falcon',
                'Base URL: http://purplelab-backend:8000/api/vendor/crowdstrike',
                'Client ID: any value (e.g. sim-client)',
                'Client Secret: any value (e.g. sim-secret)',
                'Click Test Connection → should return {"access_token": "sim-token-...", "token_type": "bearer"}',
                'Save. Joti will use FQL filters automatically against PurpleLab seed data.',
              ].map((s, i) => (
                <div key={i} className="flex gap-3 text-xs">
                  <span className="shrink-0 w-5 h-5 rounded-full bg-primary/20 text-primary text-[10px] font-bold flex items-center justify-center">{i + 1}</span>
                  <span className="text-muted-foreground">{s}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Auth Credentials (all accept any value)</CardTitle></CardHeader>
            <CardContent>
              <table className="w-full text-xs">
                <thead className="bg-muted/60 text-muted-foreground border-b border-border">
                  <tr>
                    <th className="text-left px-3 py-2">Vendor</th>
                    <th className="text-left px-3 py-2">Auth mechanism</th>
                    <th className="text-left px-3 py-2">Credential fields</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['CrowdStrike', 'OAuth2 token endpoint', 'client_id + client_secret'],
                    ['Defender MDE', 'OAuth2 token endpoint', 'tenant_id + client_id + client_secret'],
                    ['SentinelOne', 'Header', 'Authorization: ApiToken <any>'],
                    ['Carbon Black', 'Header', 'X-Auth-Token: <any>/<org_key>'],
                    ['XSIAM', 'HMAC headers', 'x-xdr-auth-id + key + nonce (any values)'],
                    ['Splunk', 'Basic Auth', 'admin:changeme (or any)'],
                    ['QRadar', 'Header', 'SEC: <any token>'],
                    ['Elastic', 'Basic Auth or API key', 'elastic:changeme (or any)'],
                    ['Tenable', 'Header', 'X-ApiKeys: accessKey=X;secretKey=Y (any)'],
                    ['Qualys', 'Session cookie', 'POST /session/ with any username/password'],
                    ['Wiz', 'OAuth2 token endpoint', 'client_id + client_secret (any)'],
                    ['ServiceNow', 'Basic Auth', 'admin:admin (or any)'],
                    ['Jira', 'Basic Auth', 'user@example.com:api_token (or any)'],
                    ['Okta', 'Header', 'Authorization: SSWS <any>'],
                    ['Entra ID', 'OAuth2 token endpoint', 'client_id + client_secret + tenant_id (any)'],
                    ['Panorama', 'API key (query)', 'GET /api/?type=keygen&user=admin&password=admin'],
                  ].map(([v, m, c]) => (
                    <tr key={v} className="border-b border-border">
                      <td className="px-3 py-1.5 font-medium text-foreground">{v}</td>
                      <td className="px-3 py-1.5 text-muted-foreground">{m}</td>
                      <td className="px-3 py-1.5 font-mono text-[10px] text-muted-foreground">{c}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── Workflows tab ── */}
        <TabsContent value="workflows" className="mt-4 space-y-4">
          {[
            {
              title: 'Incident Response Workflow',
              steps: [
                'CrowdStrike: query detections → GET /detects/queries/detects/v1?filter=status:!\'closed\'',
                'CrowdStrike: contain host → POST /devices/entities/devices-actions/v2?action_name=contain',
                'SentinelOne: kill active threat → POST /web/api/v2.1/threats/mitigate/kill',
                'ServiceNow: create incident → POST /api/now/table/incident',
                'Jira: create security ticket → POST /rest/api/3/issue',
                'Splunk: search for lateral movement → search index=* EventCode=4688',
              ],
            },
            {
              title: 'Threat Hunting Workflow',
              steps: [
                'MDE: Advanced Hunting → POST /api/advancedqueries/run  { Query: "DeviceProcessEvents | where FileName == \'mimikatz.exe\'" }',
                'SentinelOne: Deep Visibility → POST /web/api/v2.1/dv/init-query  { query: "EventType = \'Process Creation\'" }',
                'Splunk: SPL search → POST /services/search/jobs  search=search index=* sourcetype=sysmon EventCode=10',
                'CrowdStrike Spotlight: check vuln exposure → GET /spotlight/queries/vulnerabilities/v1?filter=cve.id:\'CVE-2024-21413\'',
              ],
            },
            {
              title: 'Vulnerability Prioritisation Workflow',
              steps: [
                'Tenable: export vulns → POST /vulns/export  { filters: { severity: ["critical"] } }',
                'Qualys: get detections → GET /api/2.0/fo/asset/host/vm/detection/?action=list&severity_levels=4,5',
                'Wiz: CSPM issues → POST /graphql  { query: "{ issues(first:20, filterBy:{severity:CRITICAL}) { nodes { id title } } }" }',
                'ServiceNow CMDB: lookup asset owner → GET /api/now/table/cmdb_ci_computer?sysparm_query=name=CORP-WS-001',
                'Jira: create remediation ticket → POST /rest/api/3/issue',
              ],
            },
            {
              title: 'Identity Compromise Response',
              steps: [
                'Okta: search user → GET /api/v1/users?search=profile.login+sw+"jsmith"',
                'Okta: suspend user → POST /api/v1/users/{id}/lifecycle/suspend',
                'Okta: revoke sessions → DELETE /api/v1/sessions/{id}',
                'Entra ID: check risky user → GET /v1.0/identityProtection/riskyUsers',
                'Entra ID: revoke sign-in → POST /v1.0/users/{id}/revokeSignInSessions',
                'CrowdStrike: block IOC (attacker IP) → POST /iocs/entities/indicators/v1',
              ],
            },
          ].map(({ title, steps }) => (
            <Card key={title}>
              <CardHeader><CardTitle className="text-sm">{title}</CardTitle></CardHeader>
              <CardContent className="space-y-1.5">
                {steps.map((s, i) => (
                  <div key={i} className="flex gap-3 text-xs">
                    <span className="shrink-0 text-primary font-mono">{i + 1}.</span>
                    <code className="font-mono text-[10px] text-muted-foreground break-all">{s}</code>
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  )
}
