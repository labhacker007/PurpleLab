"use client"

import {
  use,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react"
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Handle,
  Position,
  type Node,
  type Edge,
  type Connection,
  type NodeTypes,
  type ReactFlowInstance,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { useRouter } from "next/navigation"
import {
  ArrowLeft,
  Save,
  Play,
  CheckCircle,
  XCircle,
  Circle,
  ChevronRight,
  ChevronLeft,
  Search,
  X,
  Copy,
  Trash2,
  Shield,
  Database,
  Cpu,
  AlertTriangle,
  Info,
  Users,
  Target,
  Network,
  Loader2,
  Link2,
  Crosshair,
  Plug,
  Package,
  Globe,
  Cloud,
  Mail,
  Server,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { authFetch } from "@/lib/auth"
import { API_BASE } from "@/lib/api/client"
import { cn } from "@/lib/utils"

// ── Types ─────────────────────────────────────────────────────────────────────

interface CanvasTopology {
  nodes: Node[]
  edges: Edge[]
}

interface ApiEnvironment {
  id: string
  name: string
  description?: string
  siem_platform?: string
  log_sources?: Array<{ id: string; source_id: string; name?: string; category?: string }>
  settings?: { canvas_topology?: CanvasTopology }
  created_at?: string
  updated_at?: string
}

interface ApiRule {
  id: string
  name: string
  mitre_techniques?: string[]
  severity?: string
  last_result?: "pass" | "fail" | null
}

type SimMode = "attack_chain" | "threat_actor" | "ttps" | "mcp_ingest"

interface SimConfig {
  mode: SimMode
  duration: "quick" | "standard" | "extended"
  // attack_chain
  chains: string[]
  // threat_actor
  threat_actor_id?: string
  threat_actor_name?: string
  threat_actor_ttps?: string[]
  // ttps
  technique_ids?: string[]
  // mcp_ingest
  mcp_preset?: "joti" | "purplelab" | "custom"
  mcp_server_url?: string
  mcp_api_key?: string
  mcp_tool?: string
  mcp_query?: string
}

// ── Palette Data ──────────────────────────────────────────────────────────────

const LOG_SOURCE_PALETTE = [
  { id: "windows_sysmon", label: "Windows Sysmon", category: "endpoint", icon: "🖥️" },
  { id: "windows_security", label: "Windows Security", category: "endpoint", icon: "🛡️" },
  { id: "crowdstrike", label: "CrowdStrike", category: "endpoint", icon: "🦅" },
  { id: "okta", label: "Okta", category: "identity", icon: "🔐" },
  { id: "azure_ad", label: "Azure AD", category: "identity", icon: "☁️" },
  { id: "aws_cloudtrail", label: "AWS CloudTrail", category: "cloud", icon: "☁️" },
  { id: "kubernetes", label: "Kubernetes", category: "cloud", icon: "⚙️" },
  { id: "dns", label: "DNS", category: "network", icon: "🌐" },
  { id: "firewall", label: "Firewall", category: "network", icon: "🔥" },
  { id: "email_gateway", label: "Email Gateway", category: "network", icon: "📧" },
  { id: "asm", label: "Attack Surface Mgmt", category: "asm", icon: "🔭" },
  { id: "cmdb", label: "CMDB", category: "cmdb", icon: "📋" },
  { id: "cspm", label: "CSPM", category: "cspm", icon: "☁️" },
  { id: "product_registry", label: "Product Registry", category: "product_registry", icon: "📦" },
]

const SIEM_PALETTE = [
  { id: "splunk", label: "Splunk", icon: "🔍" },
  { id: "elastic", label: "Elastic/SIEM", icon: "🔎" },
  { id: "sentinel", label: "Microsoft Sentinel", icon: "🛡️" },
]

const CATEGORY_COLORS: Record<string, string> = {
  endpoint:         "border-violet-500/50 bg-violet-500/10 text-violet-300",
  identity:         "border-amber-500/50 bg-amber-500/10 text-amber-300",
  cloud:            "border-sky-500/50 bg-sky-500/10 text-sky-300",
  network:          "border-teal-500/50 bg-teal-500/10 text-teal-300",
  asm:              "border-cyan-500/50 bg-cyan-500/10 text-cyan-300",
  cmdb:             "border-indigo-500/50 bg-indigo-500/10 text-indigo-300",
  cspm:             "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
  product_registry: "border-pink-500/50 bg-pink-500/10 text-pink-300",
}

const ATTACK_CHAINS = [
  { id: "apt29_cred", label: "APT29 Credential Harvest" },
  { id: "ransomware_precursor", label: "Ransomware Precursor" },
  { id: "lateral_movement", label: "Lateral Movement Chain" },
  { id: "exfiltration", label: "Data Exfiltration" },
  { id: "persistence", label: "Persistence & C2" },
]

// ── Infrastructure Palette ────────────────────────────────────────────────────

const INFRA_PALETTE = {
  endpoints: [
    { id: "endpoint-windows", label: "Windows Endpoint", subtype: "endpoint", variant: "windows", icon: "🖥️", user_count: 1 },
    { id: "endpoint-linux", label: "Linux Server", subtype: "endpoint", variant: "linux", icon: "🐧", user_count: 0 },
    { id: "endpoint-mac", label: "macOS Endpoint", subtype: "endpoint", variant: "macos", icon: "🍎", user_count: 1 },
    { id: "endpoint-dc", label: "Domain Controller", subtype: "endpoint", variant: "windows-dc", icon: "🏢", user_count: 0 },
    { id: "endpoint-server", label: "Windows Server", subtype: "endpoint", variant: "windows-server", icon: "🖧", user_count: 0 },
  ],
  cloud: [
    { id: "cloud-aws", label: "AWS Account", subtype: "cloud", variant: "aws", icon: "🔶", services: ["cloudtrail", "guardduty"] },
    { id: "cloud-azure", label: "Azure Tenant", subtype: "cloud", variant: "azure", icon: "🔷", services: ["aad", "defender"] },
    { id: "cloud-gcp", label: "GCP Project", subtype: "cloud", variant: "gcp", icon: "🔵", services: ["cloudlogging"] },
  ],
  email: [
    { id: "email-exchange", label: "Exchange Online", subtype: "email", variant: "exchange", icon: "📧" },
    { id: "email-gsuite", label: "Google Workspace", subtype: "email", variant: "gsuite", icon: "✉️" },
    { id: "email-proofpoint", label: "Proofpoint", subtype: "email", variant: "proofpoint", icon: "🛡️" },
    { id: "email-mimecast", label: "Mimecast", subtype: "email", variant: "mimecast", icon: "🛡️" },
  ],
  edr: [
    { id: "edr-crowdstrike", label: "CrowdStrike Falcon", subtype: "edr", variant: "crowdstrike", icon: "🦅" },
    { id: "edr-defender", label: "Defender for Endpoint", subtype: "edr", variant: "defender", icon: "🛡️" },
    { id: "edr-sentinelone", label: "SentinelOne Agent", subtype: "edr", variant: "sentinelone", icon: "🔵" },
    { id: "edr-carbonblack", label: "Carbon Black Agent", subtype: "edr", variant: "carbonblack", icon: "⬛" },
    { id: "edr-xsiam", label: "Cortex XDR Agent", subtype: "edr", variant: "xsiam", icon: "🔴" },
  ],
  itsm: [
    { id: "itsm-servicenow", label: "ServiceNow CMDB", subtype: "itsm", variant: "servicenow", icon: "🎫" },
    { id: "itsm-jira", label: "Jira Service Mgmt", subtype: "itsm", variant: "jira", icon: "🟦" },
  ],
}

const INFRA_TYPE_CONFIG: Record<string, { label: string; border: string; bg: string; badge: string; handleColor: string }> = {
  endpoint: { label: "Endpoint", border: "border-violet-500/60", bg: "bg-violet-950/40", badge: "text-violet-300 bg-violet-500/20", handleColor: "!bg-violet-500" },
  cloud:    { label: "Cloud",    border: "border-sky-500/60",    bg: "bg-sky-950/40",    badge: "text-sky-300 bg-sky-500/20",    handleColor: "!bg-sky-500" },
  email:    { label: "Email",    border: "border-teal-500/60",   bg: "bg-teal-950/40",   badge: "text-teal-300 bg-teal-500/20",  handleColor: "!bg-teal-500" },
  edr:      { label: "EDR",     border: "border-emerald-500/60", bg: "bg-emerald-950/40", badge: "text-emerald-300 bg-emerald-500/20", handleColor: "!bg-emerald-500" },
  itsm:     { label: "ITSM",    border: "border-orange-500/60",  bg: "bg-orange-950/40",  badge: "text-orange-300 bg-orange-500/20",  handleColor: "!bg-orange-500" },
}

// ── Custom Node Components ────────────────────────────────────────────────────

function LogSourceNode({ data, selected }: { data: Record<string, unknown>; selected: boolean }) {
  const category = String(data.category ?? "endpoint")
  const icon = String(data.icon ?? "🖥️")
  const label = String(data.label ?? "Log Source")
  const catColor = CATEGORY_COLORS[category] ?? CATEGORY_COLORS.endpoint

  return (
    <div
      className={cn(
        "rounded-xl border-2 bg-slate-900 px-4 py-3 min-w-[160px] shadow-lg transition-all",
        "border-slate-700 hover:border-violet-500/70",
        selected && "border-violet-500 ring-2 ring-violet-500/30"
      )}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className="text-base leading-none">{icon}</span>
        <div className={cn("text-[9px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded-full border", catColor)}>
          {category}
        </div>
      </div>
      <div className="text-xs font-semibold text-slate-100 mt-1 leading-tight">{label}</div>
      <Handle
        type="source"
        position={Position.Right}
        className="!w-3 !h-3 !bg-violet-500 !border-2 !border-slate-900"
      />
    </div>
  )
}

function SIEMNode({ data, selected }: { data: Record<string, unknown>; selected: boolean }) {
  const label = String(data.label ?? "SIEM")
  const icon = String(data.icon ?? "🔍")

  return (
    <div
      className={cn(
        "rounded-xl border-2 bg-blue-950 px-5 py-4 min-w-[180px] shadow-xl transition-all",
        "border-blue-700 hover:border-blue-500",
        selected && "border-blue-400 ring-2 ring-blue-400/30"
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!w-3 !h-3 !bg-blue-400 !border-2 !border-blue-950"
      />
      <div className="flex items-center gap-2 mb-1">
        <span className="text-lg leading-none">{icon}</span>
        <div className="text-[9px] text-blue-400 uppercase font-bold tracking-wider">SIEM Platform</div>
      </div>
      <div className="text-sm font-bold text-slate-100">{label}</div>
      <Handle
        type="source"
        position={Position.Right}
        className="!w-3 !h-3 !bg-blue-400 !border-2 !border-blue-950"
      />
    </div>
  )
}

function DetectionRuleNode({ data, selected }: { data: Record<string, unknown>; selected: boolean }) {
  const label = String(data.label ?? "Rule")
  const technique = String(data.technique ?? "")
  const status = data.status as "pass" | "fail" | "untested" | undefined

  const statusConfig = {
    pass: { border: "border-green-500", ring: "ring-green-500/30", icon: <CheckCircle className="h-3.5 w-3.5 text-green-400" />, text: "text-green-400" },
    fail: { border: "border-red-500", ring: "ring-red-500/30", icon: <XCircle className="h-3.5 w-3.5 text-red-400" />, text: "text-red-400" },
    untested: { border: "border-slate-600", ring: "ring-slate-500/20", icon: <Circle className="h-3.5 w-3.5 text-slate-500" />, text: "text-slate-500" },
  }
  const cfg = statusConfig[status ?? "untested"]

  return (
    <div
      className={cn(
        "rounded-xl border-2 bg-slate-900 px-4 py-3 min-w-[160px] max-w-[200px] shadow-lg transition-all",
        cfg.border,
        selected && `ring-2 ${cfg.ring}`
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!w-3 !h-3 !bg-slate-400 !border-2 !border-slate-900"
      />
      <div className="flex items-center justify-between mb-1">
        <div className="text-[9px] text-slate-400 uppercase font-bold tracking-wider">Detection Rule</div>
        {cfg.icon}
      </div>
      <div className="text-xs font-semibold text-slate-100 leading-tight line-clamp-2">{label}</div>
      {technique && (
        <div className="mt-1.5">
          <span className="text-[9px] font-mono bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">
            {technique}
          </span>
        </div>
      )}
    </div>
  )
}

function UseCaseNode({ data, selected }: { data: Record<string, unknown>; selected: boolean }) {
  const label = String(data.label ?? "Use Case")
  const technique = String(data.technique ?? "")
  const status = data.status as "PASS" | "FAIL" | "PENDING" | undefined

  const statusBadge = {
    PASS: "bg-green-500/20 text-green-300 border-green-500/40",
    FAIL: "bg-red-500/20 text-red-300 border-red-500/40",
    PENDING: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  }

  return (
    <div
      className={cn(
        "rounded-xl border-2 bg-amber-950/50 px-4 py-3 min-w-[160px] shadow-lg transition-all",
        "border-amber-700 hover:border-amber-500",
        selected && "border-amber-400 ring-2 ring-amber-400/30"
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!w-3 !h-3 !bg-amber-400 !border-2 !border-amber-950"
      />
      <div className="flex items-center justify-between mb-1">
        <div className="text-[9px] text-amber-400 uppercase font-bold tracking-wider">Use Case</div>
        {status && (
          <span className={cn("text-[9px] font-bold border rounded px-1 py-0.5", statusBadge[status])}>
            {status}
          </span>
        )}
      </div>
      <div className="text-xs font-semibold text-slate-100 leading-tight">{label}</div>
      {technique && (
        <div className="mt-1.5">
          <span className="text-[9px] font-mono bg-amber-900/50 text-amber-300 px-1.5 py-0.5 rounded">
            {technique}
          </span>
        </div>
      )}
    </div>
  )
}

// ── Infrastructure Node (endpoints, cloud, email, EDR, ITSM) ─────────────────

function InfraNode({ data, selected }: { data: Record<string, unknown>; selected: boolean }) {
  const subtype = String(data.subtype ?? "endpoint")
  const label = String(data.label ?? "Infrastructure")
  const hostname = data.hostname ? String(data.hostname) : ""
  const ip = data.ip ? String(data.ip) : ""
  const userCount = data.user_count != null ? Number(data.user_count) : null
  const icon = String(data.icon ?? "🖥️")
  const services = Array.isArray(data.services) ? (data.services as string[]) : []

  const cfg = INFRA_TYPE_CONFIG[subtype] ?? INFRA_TYPE_CONFIG.endpoint

  return (
    <div
      className={cn(
        "rounded-xl border-2 px-4 py-3 min-w-[160px] shadow-lg transition-all",
        cfg.bg, cfg.border,
        selected && "ring-2 ring-white/20"
      )}
    >
      <Handle
        type="target"
        position={Position.Left}
        className={cn("!w-3 !h-3 !border-2 !border-slate-900", cfg.handleColor)}
      />
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-base leading-none">{icon}</span>
        <span className={cn("text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider", cfg.badge)}>
          {cfg.label}
        </span>
      </div>
      <div className="text-xs font-semibold text-slate-100 leading-tight">{label}</div>
      {hostname && <div className="text-[10px] font-mono text-slate-400 mt-0.5">{hostname}</div>}
      {ip && <div className="text-[10px] font-mono text-slate-500">{ip}</div>}
      {userCount != null && userCount > 0 && (
        <div className="text-[9px] text-slate-500 mt-1 flex items-center gap-1">
          <Users className="h-2.5 w-2.5" />{userCount} user{userCount !== 1 ? "s" : ""}
        </div>
      )}
      {services.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5">
          {services.slice(0, 3).map((s) => (
            <span key={s} className="text-[8px] font-mono bg-slate-800/80 text-slate-400 px-1 rounded">{s}</span>
          ))}
        </div>
      )}
      <Handle
        type="source"
        position={Position.Right}
        className={cn("!w-3 !h-3 !border-2 !border-slate-900", cfg.handleColor)}
      />
    </div>
  )
}

const nodeTypes: NodeTypes = {
  logSource: LogSourceNode,
  siem: SIEMNode,
  detectionRule: DetectionRuleNode,
  useCase: UseCaseNode,
  infra: InfraNode,
}

// ── Auto-layout helpers ───────────────────────────────────────────────────────

function buildAutoLayout(
  logSources: typeof LOG_SOURCE_PALETTE,
  siemId: string,
  siemLabel: string,
  siemIcon: string
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []
  const siemNodeId = "siem-0"

  // Log source column (x=80)
  logSources.forEach((src, i) => {
    const nodeId = `ls-${src.id}`
    nodes.push({
      id: nodeId,
      type: "logSource",
      position: { x: 80, y: 80 + i * 110 },
      data: { label: src.label, category: src.category, icon: src.icon, source_id: src.id },
    })
    edges.push({
      id: `e-${nodeId}-${siemNodeId}`,
      source: nodeId,
      target: siemNodeId,
      animated: false,
      style: { stroke: "#6d28d9", strokeWidth: 1.5 },
    })
  })

  // SIEM node (center)
  const siemY = Math.max(0, (logSources.length * 110) / 2 - 40)
  nodes.push({
    id: siemNodeId,
    type: "siem",
    position: { x: 380, y: siemY },
    data: { label: siemLabel, icon: siemIcon, siem_id: siemId },
  })

  return { nodes, edges }
}

// ── Inspector Panel ───────────────────────────────────────────────────────────

function InspectorPanel({
  node,
  onClose,
  onDelete,
  onDuplicate,
}: {
  node: Node
  onClose: () => void
  onDelete: (id: string) => void
  onDuplicate: (id: string) => void
}) {
  const d = node.data as Record<string, unknown>

  const typeLabels: Record<string, string> = {
    logSource: "Log Source",
    siem: "SIEM Platform",
    detectionRule: "Detection Rule",
    useCase: "Use Case",
  }
  const typeIcons: Record<string, React.ReactNode> = {
    logSource: <Database className="h-4 w-4 text-violet-400" />,
    siem: <Shield className="h-4 w-4 text-blue-400" />,
    detectionRule: <AlertTriangle className="h-4 w-4 text-slate-400" />,
    useCase: <Cpu className="h-4 w-4 text-amber-400" />,
  }

  return (
    <div className="w-72 border-l border-slate-800 bg-slate-900 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          {typeIcons[node.type ?? "logSource"] ?? <Info className="h-4 w-4" />}
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            {typeLabels[node.type ?? ""] ?? node.type}
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-500 hover:text-slate-300 transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Details */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Name</div>
          <div className="text-sm font-semibold text-slate-100">{String(d.label ?? "")}</div>
        </div>

        {Boolean(d.category) && (
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Category</div>
            <Badge className={cn("text-[10px]", CATEGORY_COLORS[String(d.category)] ?? "")}>
              {String(d.category)}
            </Badge>
          </div>
        )}

        {Boolean(d.source_id) && (
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Source ID</div>
            <code className="text-xs font-mono text-violet-300 bg-slate-800 px-2 py-1 rounded">
              {String(d.source_id)}
            </code>
          </div>
        )}

        {Boolean(d.technique) && (
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">MITRE Technique</div>
            <code className="text-xs font-mono text-slate-200 bg-slate-800 px-2 py-1 rounded">
              {String(d.technique)}
            </code>
          </div>
        )}

        {d.status !== undefined && (
          <div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Status</div>
            <div className="flex items-center gap-1.5">
              {String(d.status) === "pass" || String(d.status) === "PASS" ? (
                <CheckCircle className="h-4 w-4 text-green-400" />
              ) : String(d.status) === "fail" || String(d.status) === "FAIL" ? (
                <XCircle className="h-4 w-4 text-red-400" />
              ) : (
                <Circle className="h-4 w-4 text-slate-500" />
              )}
              <span className="text-sm text-slate-200">{String(d.status)}</span>
            </div>
          </div>
        )}

        <div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Node ID</div>
          <code className="text-[10px] font-mono text-slate-500 bg-slate-800 px-2 py-0.5 rounded break-all">
            {node.id}
          </code>
        </div>

        <div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Position</div>
          <div className="text-xs text-slate-400 font-mono">
            x: {Math.round(node.position.x)}, y: {Math.round(node.position.y)}
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="p-4 border-t border-slate-800 space-y-2">
        <Button
         
          size="sm"
          className="w-full justify-start text-slate-300 border-slate-700 hover:border-slate-500"
          onClick={() => onDuplicate(node.id)}
        >
          <Copy className="h-3.5 w-3.5" />
          Duplicate Node
        </Button>
        <Button
          size="sm"
          className="w-full justify-start bg-red-950 hover:bg-red-900 text-red-300 border border-red-800"
          onClick={() => onDelete(node.id)}
        >
          <Trash2 className="h-3.5 w-3.5" />
          Delete Node
        </Button>
      </div>
    </div>
  )
}

// ── Products Modal ────────────────────────────────────────────────────────────

interface CatalogVendor {
  vendor: string
  display: string
  index: string
  sourcetype: string
  log_format: string
}

interface CatalogCategory {
  default: string
  vendors: CatalogVendor[]
}

const CATEGORY_META: Record<string, { label: string; icon: React.ReactNode; desc: string }> = {
  edr:            { label: "EDR",                icon: <Shield className="h-4 w-4" />,   desc: "Endpoint Detection & Response" },
  idp:            { label: "Identity",           icon: <Users className="h-4 w-4" />,    desc: "Identity Provider / Directory" },
  firewall:       { label: "Firewall",           icon: <Network className="h-4 w-4" />,  desc: "Next-Gen Firewall / UTM" },
  proxy:          { label: "Web Proxy",          icon: <Globe className="h-4 w-4" />,    desc: "Secure Web Gateway / Proxy" },
  cdn_waf:        { label: "CDN / WAF",          icon: <Globe className="h-4 w-4" />,    desc: "Content Delivery & WAF" },
  cloud:          { label: "Cloud Platform",     icon: <Cloud className="h-4 w-4" />,    desc: "Cloud Infrastructure" },
  email:          { label: "Email Security",     icon: <Mail className="h-4 w-4" />,     desc: "Email Gateway & Security" },
  network_switch: { label: "Network Switch",     icon: <Network className="h-4 w-4" />,  desc: "Managed Switches / Fabric" },
  dhcp_dns:       { label: "DHCP / DNS",         icon: <Server className="h-4 w-4" />,   desc: "DNS Resolver & DHCP Server" },
}

function ProductsModal({
  envId,
  onClose,
  onSaved,
}: {
  envId: string
  onClose: () => void
  onSaved: () => void
}) {
  const [catalog, setCatalog] = useState<Record<string, CatalogCategory>>({})
  const [selections, setSelections] = useState<Record<string, string>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    async function load() {
      setLoading(true)
      try {
        const [catalogRes, productRes] = await Promise.all([
          authFetch(`${API_BASE}/api/v2/environments/catalog/products`),
          authFetch(`${API_BASE}/api/v2/environments/${envId}/products`),
        ])
        if (catalogRes.ok) {
          setCatalog(await catalogRes.json() as Record<string, CatalogCategory>)
        }
        if (productRes.ok) {
          const data = await productRes.json() as { products: Record<string, { vendor: string }> }
          const current: Record<string, string> = {}
          for (const [cat, info] of Object.entries(data.products ?? {})) {
            if (info.vendor) current[cat] = info.vendor
          }
          setSelections(current)
        }
      } catch {
        // silent
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [envId])

  async function handleSave() {
    setSaving(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/environments/${envId}/products`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(selections),
      })
      if (res.ok) {
        onSaved()
        onClose()
      }
    } catch {
      // silent
    } finally {
      setSaving(false)
    }
  }

  const categoryOrder = ["edr", "idp", "firewall", "proxy", "cdn_waf", "cloud", "email", "network_switch", "dhcp_dns"]
  const orderedEntries = categoryOrder
    .filter((c) => catalog[c])
    .map((c) => [c, catalog[c]] as [string, CatalogCategory])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-violet-500/20 border border-violet-500/30">
              <Package className="h-4 w-4 text-violet-400" />
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-100">Security Products</div>
              <div className="text-xs text-slate-500 mt-0.5">
                Vendor selections drive log field schemas — simulated events will match real vendor formats
              </div>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {loading ? (
            <div className="flex items-center justify-center h-40">
              <Loader2 className="h-5 w-5 animate-spin text-slate-500" />
            </div>
          ) : (
            <div className="space-y-2">
              {orderedEntries.map(([category, info]) => {
                const meta = CATEGORY_META[category]
                const currentVendor = selections[category] || info.default
                const currentInfo = info.vendors.find((v) => v.vendor === currentVendor)
                const isDefault = !selections[category] || selections[category] === info.default

                return (
                  <div
                    key={category}
                    className="flex items-center gap-4 rounded-lg border border-slate-800 bg-slate-950 px-4 py-3 hover:border-slate-700 transition-colors"
                  >
                    {/* Category label */}
                    <div className="flex items-center gap-2.5 w-44 shrink-0">
                      <span className="text-slate-400">{meta?.icon}</span>
                      <div>
                        <div className="text-xs font-medium text-slate-200">{meta?.label ?? category}</div>
                        <div className="text-[10px] text-slate-500">{meta?.desc}</div>
                      </div>
                    </div>

                    {/* Vendor select */}
                    <div className="flex-1">
                      <select
                        value={currentVendor}
                        onChange={(e) =>
                          setSelections((prev) => ({ ...prev, [category]: e.target.value }))
                        }
                        className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-violet-500 transition-colors"
                      >
                        {info.vendors.map((v) => (
                          <option key={v.vendor} value={v.vendor}>
                            {v.display}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Sourcetype badge + default indicator */}
                    <div className="flex items-center gap-2 shrink-0">
                      {isDefault && (
                        <span className="text-[9px] uppercase font-bold tracking-wider text-slate-600 border border-slate-700 rounded px-1.5 py-0.5">
                          default
                        </span>
                      )}
                      {currentInfo?.sourcetype && (
                        <code className="text-[9px] font-mono text-slate-500 bg-slate-800 border border-slate-700/50 rounded px-1.5 py-0.5 max-w-[130px] truncate">
                          {currentInfo.sourcetype}
                        </code>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800">
          <div className="text-[10px] text-slate-600">
            Product selections are stored in environment settings and applied to every simulation
          </div>
          <div className="flex gap-2">
            <Button

              size="sm"
              onClick={onClose}
              className="border-slate-700 text-slate-400 hover:text-slate-200"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={saving || loading}
              className="bg-violet-600 hover:bg-violet-500 text-white gap-1.5"
            >
              {saving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Save Products
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Simulate Modal — 3-step wizard ───────────────────────────────────────────

const SIM_MODES: Array<{
  id: SimMode
  label: string
  desc: string
  icon: React.ReactNode
  color: string
}> = [
  {
    id: "attack_chain",
    label: "Attack Chains",
    desc: "Run predefined adversary simulation chains (APT29, ransomware, lateral movement…)",
    icon: <Link2 className="h-5 w-5" />,
    color: "border-violet-500/60 bg-violet-500/10 text-violet-300",
  },
  {
    id: "threat_actor",
    label: "Threat Actor",
    desc: "Pick a known threat group — simulate their real-world TTPs from MITRE ATT&CK",
    icon: <Users className="h-5 w-5" />,
    color: "border-red-500/60 bg-red-500/10 text-red-300",
  },
  {
    id: "ttps",
    label: "By TTPs",
    desc: "Select specific MITRE ATT&CK techniques and generate matching detection events",
    icon: <Crosshair className="h-5 w-5" />,
    color: "border-amber-500/60 bg-amber-500/10 text-amber-300",
  },
  {
    id: "mcp_ingest",
    label: "MCP Ingest",
    desc: "Connect to Joti or a custom MCP server and read live logs to drive simulation",
    icon: <Plug className="h-5 w-5" />,
    color: "border-cyan-500/60 bg-cyan-500/10 text-cyan-300",
  },
]

const DURATION_OPTS: Array<{ value: SimConfig["duration"]; label: string; events: string }> = [
  { value: "quick", label: "Quick", events: "50 events" },
  { value: "standard", label: "Standard", events: "200 events" },
  { value: "extended", label: "Extended", events: "500 events" },
]

const MCP_TOOLS = [
  { id: "siem_search_events", label: "SIEM — Search Events" },
  { id: "siem_get_alerts", label: "SIEM — Recent Alerts" },
  { id: "edr_get_detections", label: "EDR — Detections" },
  { id: "edr_hunt_ioc", label: "EDR — Hunt IOC" },
]

function SimulateModal({
  envName,
  onClose,
  onStart,
}: {
  envName: string
  onClose: () => void
  onStart: (cfg: SimConfig) => void
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [mode, setMode] = useState<SimMode>("attack_chain")
  const [duration, setDuration] = useState<SimConfig["duration"]>("standard")

  // attack_chain state
  const [selectedChains, setSelectedChains] = useState<string[]>(["apt29_cred"])

  // threat_actor state
  const [actorSearch, setActorSearch] = useState("")
  const [actors, setActors] = useState<Array<{ id: string; name: string; aliases?: string[]; ttp_count?: number; ioc_count?: number; article_count?: number; source?: string }>>([])
  const [actorsLoading, setActorsLoading] = useState(false)
  const [selectedActor, setSelectedActor] = useState<{
    id: string; name: string; ttps: string[]
    technique_ids: string[]; ttp_details: Array<{ id: string | null; name: string }>
    iocs: Array<{ value: string; type: string; confidence: number }>
    aliases: string[]; article_count: number; source?: string
  } | null>(null)
  const [actorDetailLoading, setActorDetailLoading] = useState(false)

  // ttps state
  const [ttpSearch, setTtpSearch] = useState("")
  const [techniques, setTechniques] = useState<Array<{ id: string; name: string; tactic?: string }>>([])
  const [techniquesLoading, setTechniquesLoading] = useState(false)
  const [selectedTTPs, setSelectedTTPs] = useState<string[]>([])
  const [ttpInput, setTtpInput] = useState("")

  // mcp state
  const [mcpPreset, setMcpPreset] = useState<"joti" | "custom">("joti")
  const [mcpUrl, setMcpUrl] = useState("")
  const [mcpKey, setMcpKey] = useState("")
  const [mcpTool, setMcpTool] = useState("siem_search_events")
  const [mcpQuery, setMcpQuery] = useState("")
  const [mcpTesting, setMcpTesting] = useState(false)
  const [mcpTestResult, setMcpTestResult] = useState<string | null>(null)

  const FALLBACK_ACTORS = [
    { id: "G0016", name: "APT29 (Cozy Bear)", aliases: ["Cozy Bear"], techniques: ["T1566", "T1078", "T1059", "T1021", "T1083"] },
    { id: "G0007", name: "APT28 (Fancy Bear)", aliases: ["Fancy Bear"], techniques: ["T1566", "T1203", "T1055", "T1070", "T1547"] },
    { id: "G0065", name: "Lazarus Group", aliases: [], techniques: ["T1059", "T1486", "T1490", "T1078", "T1021"] },
    { id: "G0034", name: "Sandworm Team", aliases: [], techniques: ["T1195", "T1059", "T1543", "T1486", "T1561"] },
    { id: "G0096", name: "APT41", aliases: [], techniques: ["T1078", "T1059", "T1055", "T1021", "T1105"] },
    { id: "G0114", name: "Chimera", aliases: [], techniques: ["T1589", "T1078", "T1021", "T1074", "T1567"] },
    { id: "G0046", name: "FIN7", aliases: [], techniques: ["T1566", "T1059", "T1055", "T1027", "T1486"] },
    { id: "G0102", name: "Wizard Spider", aliases: ["UNC1878"], techniques: ["T1486", "T1490", "T1059", "T1078", "T1021"] },
  ]

  // Load actors from Joti (via PurpleLab proxy) when on threat_actor step
  useEffect(() => {
    if (step === 2 && mode === "threat_actor" && actors.length === 0) {
      setActorsLoading(true)
      fetch("/api/v2/threat-intel/joti/actors?limit=100")
        .then((r) => r.json())
        .then((d) => {
          const list = (d.actors || []) as Array<Record<string, unknown>>
          if (list.length === 0) {
            setActors(FALLBACK_ACTORS)
          } else {
            setActors(list.map((a) => ({
              id: String(a.id ?? a.name),
              name: String(a.name),
              aliases: (a.aliases as string[]) || [],
              ttp_count: Number(a.ttp_count ?? 0),
              ioc_count: Number(a.ioc_count ?? 0),
              article_count: Number(a.article_count ?? 0),
              source: "joti",
            })))
          }
        })
        .catch(() => setActors(FALLBACK_ACTORS))
        .finally(() => setActorsLoading(false))
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, mode, actors.length])

  // Load actor detail (TTPs + IOCs) from Joti when actor selected
  async function loadActorDetail(actor: { id: string; name: string; source?: string }) {
    if (!actor.source || actor.source !== "joti") {
      // Fallback actor — use its hardcoded techniques
      const fb = FALLBACK_ACTORS.find((f) => f.id === actor.id)
      setSelectedActor({
        id: actor.id, name: actor.name,
        ttps: [], technique_ids: fb?.techniques ?? [],
        ttp_details: (fb?.techniques ?? []).map((t) => ({ id: t, name: t })),
        iocs: [], aliases: [], article_count: 0,
      })
      return
    }
    setActorDetailLoading(true)
    try {
      const res = await fetch(`/api/v2/threat-intel/joti/actors/${actor.id}`)
      if (res.ok) {
        const d = await res.json() as {
          id: string; name: string; ttps: string[]; technique_ids: string[]
          ttp_details: Array<{ id: string | null; name: string }>
          iocs: Array<{ value: string; type: string; confidence: number }>
          aliases: string[]; article_count: number
        }
        setSelectedActor({
          id: d.id, name: d.name,
          ttps: d.ttps,
          technique_ids: d.technique_ids,
          ttp_details: d.ttp_details,
          iocs: d.iocs,
          aliases: d.aliases,
          article_count: d.article_count,
          source: "joti",
        })
      }
    } catch { /* silent */ }
    finally { setActorDetailLoading(false) }
  }

  // Debounced TTP search
  useEffect(() => {
    if (step !== 2 || mode !== "ttps" || ttpSearch.length < 2) {
      if (ttpSearch.length === 0) setTechniques([])
      return
    }
    setTechniquesLoading(true)
    const t = setTimeout(() => {
      fetch(`/api/v2/threat-intel/techniques?search=${encodeURIComponent(ttpSearch)}&limit=30`)
        .then((r) => r.json())
        .then((d) => {
          const techs = (d.techniques || []) as Array<Record<string, unknown>>
          setTechniques(techs.map((t) => ({
            id: String(t.technique_id ?? t.id),
            name: String(t.name),
            tactic: String(t.tactic ?? (Array.isArray(t.tactics) ? (t.tactics as string[])[0] : "") ?? ""),
          })))
        })
        .catch(() => setTechniques([]))
        .finally(() => setTechniquesLoading(false))
    }, 300)
    return () => clearTimeout(t)
  }, [ttpSearch, step, mode])

  function toggleChain(id: string) {
    setSelectedChains((prev) => prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id])
  }
  function toggleTTP(id: string) {
    setSelectedTTPs((prev) => prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id])
  }
  function addManualTTP() {
    const raw = ttpInput.trim().toUpperCase()
    if (!raw || selectedTTPs.includes(raw)) { setTtpInput(""); return }
    setSelectedTTPs((prev) => [...prev, raw])
    setTtpInput("")
  }

  async function testMcpConnection() {
    setMcpTesting(true)
    setMcpTestResult(null)
    const url = mcpPreset === "joti" ? "/api/v2/mcp-proxy/joti/health" : mcpUrl
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(5000) })
      setMcpTestResult(resp.ok ? "✓ Connected successfully" : `⚠ HTTP ${resp.status}`)
    } catch {
      setMcpTestResult("✗ Could not connect — check URL and API key")
    } finally {
      setMcpTesting(false)
    }
  }

  function canProceed(): boolean {
    if (step === 1) return true
    if (step === 2) {
      if (mode === "attack_chain") return selectedChains.length > 0
      if (mode === "threat_actor") return !!selectedActor
      if (mode === "ttps") return selectedTTPs.length > 0
      if (mode === "mcp_ingest") return mcpPreset === "joti" || !!mcpUrl.trim()
    }
    return true
  }

  function buildConfig(): SimConfig {
    const base: SimConfig = { mode, duration, chains: selectedChains }
    if (mode === "threat_actor" && selectedActor) {
      base.threat_actor_id = selectedActor.id
      base.threat_actor_name = selectedActor.name
      // Prefer resolved MITRE technique IDs; fall back to raw TTP names
      base.threat_actor_ttps = selectedActor.technique_ids.length > 0
        ? selectedActor.technique_ids
        : selectedActor.ttps
    }
    if (mode === "ttps") base.technique_ids = selectedTTPs
    if (mode === "mcp_ingest") {
      base.mcp_preset = mcpPreset
      base.mcp_server_url = mcpPreset === "joti" ? "http://purplelab-backend:8000/api/v2/mcp" : mcpUrl
      base.mcp_api_key = mcpKey
      base.mcp_tool = mcpTool
      base.mcp_query = mcpQuery
    }
    return base
  }

  const currentMode = SIM_MODES.find((m) => m.id === mode)!

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      <div className="relative bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-xl mx-4 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            {step > 1 && (
              <button
                onClick={() => setStep((s) => (s - 1) as 1 | 2 | 3)}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
            )}
            <div>
              <h2 className="text-sm font-bold text-slate-100">Run Simulation</h2>
              <p className="text-xs text-slate-500 mt-0.5">{envName}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Step indicator */}
            <div className="flex items-center gap-1">
              {[1, 2, 3].map((s) => (
                <div
                  key={s}
                  className={cn(
                    "h-1.5 rounded-full transition-all",
                    s === step ? "w-6 bg-violet-400" : s < step ? "w-3 bg-violet-600" : "w-3 bg-slate-700"
                  )}
                />
              ))}
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 max-h-[70vh] overflow-y-auto">

          {/* ── Step 1: Choose Mode ── */}
          {step === 1 && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 mb-4">Choose what drives the simulation</p>
              {SIM_MODES.map((m) => (
                <button
                  key={m.id}
                  onClick={() => setMode(m.id)}
                  className={cn(
                    "w-full flex items-center gap-4 px-4 py-3.5 rounded-xl border transition-all text-left",
                    mode === m.id ? m.color + " border-current" : "border-slate-700 hover:border-slate-600 text-slate-300"
                  )}
                >
                  <div className={cn("shrink-0 rounded-lg p-2", mode === m.id ? "bg-current/10" : "bg-slate-800")}>
                    {m.icon}
                  </div>
                  <div>
                    <div className="text-sm font-semibold">{m.label}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{m.desc}</div>
                  </div>
                  {mode === m.id && <CheckCircle className="h-4 w-4 ml-auto shrink-0 text-current" />}
                </button>
              ))}
            </div>
          )}

          {/* ── Step 2: Mode-specific config ── */}
          {step === 2 && mode === "attack_chain" && (
            <div className="space-y-2">
              <p className="text-xs text-slate-400 mb-3">Select one or more attack chains to simulate</p>
              {ATTACK_CHAINS.map((chain) => {
                const checked = selectedChains.includes(chain.id)
                return (
                  <label
                    key={chain.id}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer transition-colors",
                      checked ? "border-violet-500/50 bg-violet-500/10" : "border-slate-700 hover:border-slate-600"
                    )}
                  >
                    <input type="checkbox" checked={checked} onChange={() => toggleChain(chain.id)} className="accent-violet-500" />
                    <span className="text-sm text-slate-200">{chain.label}</span>
                  </label>
                )
              })}
            </div>
          )}

          {step === 2 && mode === "threat_actor" && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 mb-1">Select a threat actor — their real ATT&CK TTPs will drive the simulation</p>
              <div className="relative">
                <Search className="absolute left-3 top-2 h-3.5 w-3.5 text-slate-500" />
                <input
                  className="w-full bg-slate-800 border border-slate-600 rounded-lg pl-8 pr-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-violet-500"
                  placeholder="Search threat actors…"
                  value={actorSearch}
                  onChange={(e) => setActorSearch(e.target.value)}
                />
              </div>

              {actorsLoading ? (
                <div className="flex items-center justify-center py-8 text-slate-500 gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span className="text-xs">Loading threat groups…</span>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                  {actors
                    .filter((a) =>
                      !actorSearch ||
                      a.name.toLowerCase().includes(actorSearch.toLowerCase()) ||
                      a.aliases?.some((al) => al.toLowerCase().includes(actorSearch.toLowerCase()))
                    )
                    .map((actor) => {
                      const isSelected = selectedActor?.id === actor.id
                      return (
                        <button
                          key={actor.id}
                          onClick={() => {
                            if (isSelected) { setSelectedActor(null); return }
                            void loadActorDetail(actor)
                          }}
                          className={cn(
                            "w-full flex items-center justify-between px-3 py-2.5 rounded-lg border text-left transition-colors",
                            isSelected ? "border-red-500/50 bg-red-500/10" : "border-slate-700 hover:border-slate-600"
                          )}
                        >
                          <div>
                            <div className="text-sm font-medium text-slate-200">{actor.name}</div>
                            {actor.aliases && actor.aliases.length > 0 && (
                              <div className="text-[10px] text-slate-500 mt-0.5">aka {actor.aliases.slice(0, 3).join(", ")}</div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0 ml-3">
                            {(actor.ttp_count ?? 0) > 0 && (
                              <span className="text-[10px] text-slate-500">{actor.ttp_count} TTPs</span>
                            )}
                            {(actor.ioc_count ?? 0) > 0 && (
                              <span className="text-[10px] text-blue-400">{actor.ioc_count} IOCs</span>
                            )}
                            {(actor.article_count ?? 0) > 0 && (
                              <span className="text-[10px] text-slate-600">{actor.article_count} articles</span>
                            )}
                            {actor.source === "joti" && (
                              <span className="text-[9px] text-violet-400 border border-violet-500/30 rounded px-1">JOTI</span>
                            )}
                            {isSelected && <CheckCircle className="h-3.5 w-3.5 text-red-400" />}
                          </div>
                        </button>
                      )
                    })}
                </div>
              )}

              {/* Actor detail panel */}
              {actorDetailLoading && (
                <div className="flex items-center gap-2 text-xs text-slate-500 px-1">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Loading actor intelligence from Joti…
                </div>
              )}
              {selectedActor && !actorDetailLoading && (
                <div className="rounded-lg bg-red-500/10 border border-red-500/30 px-3 py-2.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-semibold text-red-300">{selectedActor.name}</div>
                    {selectedActor.source === "joti" && (
                      <span className="text-[9px] text-violet-400 border border-violet-500/30 rounded px-1">from Joti TIP</span>
                    )}
                  </div>
                  {/* MITRE technique IDs */}
                  {selectedActor.technique_ids.length > 0 && (
                    <div>
                      <div className="text-[10px] text-slate-500 mb-1">MITRE Techniques ({selectedActor.technique_ids.length})</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedActor.technique_ids.slice(0, 12).map((t) => (
                          <span key={t} className="px-1.5 py-0.5 bg-red-500/20 border border-red-500/30 rounded text-[10px] font-mono text-red-300">{t}</span>
                        ))}
                        {selectedActor.technique_ids.length > 12 && (
                          <span className="text-[10px] text-slate-500">+{selectedActor.technique_ids.length - 12} more</span>
                        )}
                      </div>
                    </div>
                  )}
                  {/* TTP names when no MITRE IDs resolved */}
                  {selectedActor.technique_ids.length === 0 && selectedActor.ttp_details.length > 0 && (
                    <div>
                      <div className="text-[10px] text-slate-500 mb-1">TTPs ({selectedActor.ttp_details.length})</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedActor.ttp_details.slice(0, 8).map((t, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-slate-700 border border-slate-600 rounded text-[10px] text-slate-300">{t.name}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* IOCs */}
                  {selectedActor.iocs.length > 0 && (
                    <div>
                      <div className="text-[10px] text-slate-500 mb-1">Associated IOCs ({selectedActor.iocs.length})</div>
                      <div className="flex flex-wrap gap-1">
                        {selectedActor.iocs.slice(0, 6).map((ioc, i) => (
                          <span key={i} className="px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/30 rounded text-[10px] font-mono text-blue-300 max-w-[180px] truncate" title={ioc.value}>{ioc.value}</span>
                        ))}
                        {selectedActor.iocs.length > 6 && (
                          <span className="text-[10px] text-slate-500">+{selectedActor.iocs.length - 6} more IOCs</span>
                        )}
                      </div>
                    </div>
                  )}
                  {selectedActor.article_count > 0 && (
                    <div className="text-[10px] text-slate-600">Referenced in {selectedActor.article_count} Joti articles</div>
                  )}
                </div>
              )}
            </div>
          )}

          {step === 2 && mode === "ttps" && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 mb-1">Search MITRE ATT&CK techniques or type a technique ID directly</p>

              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3 top-2 h-3.5 w-3.5 text-slate-500" />
                <input
                  className="w-full bg-slate-800 border border-slate-600 rounded-lg pl-8 pr-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  placeholder="Search techniques (min 2 chars)…"
                  value={ttpSearch}
                  onChange={(e) => setTtpSearch(e.target.value)}
                />
              </div>

              {/* Manual input */}
              <div className="flex gap-2">
                <input
                  className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-amber-500"
                  placeholder="T1059.001"
                  value={ttpInput}
                  onChange={(e) => setTtpInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addManualTTP()}
                />
                <button
                  onClick={addManualTTP}
                  className="px-3 py-2 rounded-lg bg-amber-500/20 border border-amber-500/40 text-amber-300 text-xs font-medium hover:bg-amber-500/30 transition-colors"
                >
                  Add
                </button>
              </div>

              {/* Search results */}
              {techniquesLoading ? (
                <div className="flex items-center gap-2 py-3 text-slate-500">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span className="text-xs">Searching…</span>
                </div>
              ) : techniques.length > 0 ? (
                <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
                  {techniques.map((t) => {
                    const sel = selectedTTPs.includes(t.id)
                    return (
                      <button
                        key={t.id}
                        onClick={() => toggleTTP(t.id)}
                        className={cn(
                          "w-full flex items-center gap-3 px-3 py-2 rounded-lg border text-left transition-colors text-xs",
                          sel ? "border-amber-500/50 bg-amber-500/10" : "border-slate-700 hover:border-slate-600"
                        )}
                      >
                        <span className="font-mono text-amber-300 w-20 shrink-0">{t.id}</span>
                        <span className="text-slate-200 flex-1">{t.name}</span>
                        {t.tactic && <span className="text-slate-500 shrink-0">{t.tactic}</span>}
                        {sel && <CheckCircle className="h-3.5 w-3.5 text-amber-400 shrink-0" />}
                      </button>
                    )
                  })}
                </div>
              ) : ttpSearch.length >= 2 ? (
                <p className="text-xs text-slate-500 py-2">No techniques found — use the manual input above</p>
              ) : null}

              {/* Selected TTPs chip list */}
              {selectedTTPs.length > 0 && (
                <div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Selected ({selectedTTPs.length})</div>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTTPs.map((t) => (
                      <button
                        key={t}
                        onClick={() => setSelectedTTPs((prev) => prev.filter((x) => x !== t))}
                        className="flex items-center gap-1 px-2 py-1 rounded bg-amber-500/20 border border-amber-500/30 text-[10px] font-mono text-amber-300 hover:bg-red-500/20 hover:border-red-500/30 hover:text-red-300 transition-colors"
                      >
                        {t} <X className="h-2.5 w-2.5" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {step === 2 && mode === "mcp_ingest" && (
            <div className="space-y-4">
              <p className="text-xs text-slate-400 mb-1">Connect to a security platform via MCP to read live logs and determine what to simulate</p>

              {/* Preset selector */}
              <div className="flex gap-2">
                {(["joti", "custom"] as const).map((preset) => (
                  <button
                    key={preset}
                    onClick={() => setMcpPreset(preset)}
                    className={cn(
                      "flex-1 py-2.5 rounded-lg border text-xs font-medium transition-colors",
                      mcpPreset === preset
                        ? "border-cyan-500/60 bg-cyan-500/10 text-cyan-300"
                        : "border-slate-700 text-slate-400 hover:border-slate-600"
                    )}
                  >
                    {preset === "joti" ? "🔗 Joti TIP (pre-configured)" : "⚙️ Custom MCP Server"}
                  </button>
                ))}
              </div>

              {mcpPreset === "joti" && (
                <div className="rounded-lg bg-cyan-500/10 border border-cyan-500/30 px-3 py-2.5 text-xs text-cyan-300">
                  <div className="font-semibold mb-0.5">Joti Threat Intelligence Platform</div>
                  <div className="text-cyan-400/70">Reads SIEM alerts, threat actor data, and IOC sightings from your Joti instance via the registered MCP server.</div>
                </div>
              )}

              {mcpPreset === "custom" && (
                <div className="space-y-2">
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase tracking-wider">MCP Server URL</label>
                    <input
                      className="w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                      placeholder="http://your-siem:8000/api/v2/mcp"
                      value={mcpUrl}
                      onChange={(e) => setMcpUrl(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase tracking-wider">API Key (optional)</label>
                    <input
                      className="w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                      placeholder="your-api-key"
                      type="password"
                      value={mcpKey}
                      onChange={(e) => setMcpKey(e.target.value)}
                    />
                  </div>
                  <button
                    onClick={testMcpConnection}
                    disabled={mcpTesting || !mcpUrl.trim()}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-600 text-xs text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
                  >
                    {mcpTesting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Network className="h-3 w-3" />}
                    Test connection
                  </button>
                  {mcpTestResult && (
                    <p className={cn("text-xs", mcpTestResult.startsWith("✓") ? "text-green-400" : "text-amber-400")}>
                      {mcpTestResult}
                    </p>
                  )}
                </div>
              )}

              {/* Tool selector */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Log Source / Tool</label>
                <select
                  className="w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  value={mcpTool}
                  onChange={(e) => setMcpTool(e.target.value)}
                >
                  {MCP_TOOLS.map((t) => (
                    <option key={t.id} value={t.id}>{t.label}</option>
                  ))}
                </select>
              </div>

              {/* Optional search query */}
              <div>
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Search Query (optional)</label>
                <input
                  className="w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                  placeholder="e.g. severity:high sourcetype:crowdstrike"
                  value={mcpQuery}
                  onChange={(e) => setMcpQuery(e.target.value)}
                />
              </div>

              <div className="rounded-lg bg-slate-800 border border-slate-700 px-3 py-2.5 text-[11px] text-slate-400">
                <strong className="text-slate-300">How it works:</strong> After starting, PurpleLab calls the MCP server to retrieve recent logs/alerts. It extracts the MITRE techniques from those events and generates matching simulation traffic in this environment.
              </div>
            </div>
          )}

          {/* ── Step 3: Duration & Review ── */}
          {step === 3 && (
            <div className="space-y-5">
              {/* Mode summary */}
              <div className={cn("rounded-lg border px-4 py-3 flex items-center gap-3", currentMode.color)}>
                {currentMode.icon}
                <div>
                  <div className="text-sm font-semibold">{currentMode.label}</div>
                  <div className="text-[11px] opacity-80 mt-0.5">
                    {mode === "attack_chain" && `${selectedChains.length} chain${selectedChains.length !== 1 ? "s" : ""} selected`}
                    {mode === "threat_actor" && selectedActor && `${selectedActor.name} · ${selectedActor.ttps.length} TTPs`}
                    {mode === "ttps" && `${selectedTTPs.length} technique${selectedTTPs.length !== 1 ? "s" : ""} selected`}
                    {mode === "mcp_ingest" && `${mcpPreset === "joti" ? "Joti TIP" : "Custom server"} · ${MCP_TOOLS.find((t) => t.id === mcpTool)?.label ?? mcpTool}`}
                  </div>
                </div>
              </div>

              {/* Duration */}
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Simulation Volume</div>
                <div className="flex gap-2">
                  {DURATION_OPTS.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setDuration(opt.value)}
                      className={cn(
                        "flex-1 flex flex-col items-center py-3 rounded-lg border text-xs font-medium transition-colors",
                        duration === opt.value
                          ? "border-violet-500 bg-violet-500/20 text-violet-200"
                          : "border-slate-700 text-slate-400 hover:border-slate-500"
                      )}
                    >
                      <span className="font-semibold">{opt.label}</span>
                      <span className="text-[10px] mt-0.5 opacity-70">{opt.events}</span>
                    </button>
                  ))}
                </div>
              </div>

              {mode === "mcp_ingest" && (
                <div className="rounded-lg bg-amber-500/10 border border-amber-500/30 px-3 py-2.5 text-[11px] text-amber-300">
                  <strong>Note:</strong> MCP Ingest will first fetch logs from the external system, then generate simulation events that mirror the detected techniques. Volume setting applies to the generated simulation traffic.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800">
          <Button variant="ghost" size="sm" onClick={onClose} className="text-slate-400">
            Cancel
          </Button>
          <div className="flex items-center gap-2">
            {step < 3 ? (
              <Button
                size="sm"
                onClick={() => setStep((s) => (s + 1) as 2 | 3)}
                disabled={!canProceed()}
                className="bg-violet-600 hover:bg-violet-500 text-white"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => onStart(buildConfig())}
                className="bg-violet-600 hover:bg-violet-500 text-white"
              >
                <Play className="h-3.5 w-3.5" />
                Start Simulation
                <ChevronRight className="h-3.5 w-3.5" />
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function Toast({ message, type }: { message: string; type: "success" | "error" }) {
  return (
    <div
      className={cn(
        "fixed bottom-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-xl border shadow-xl text-sm font-medium",
        type === "success"
          ? "bg-green-950 border-green-700 text-green-300"
          : "bg-red-950 border-red-700 text-red-300"
      )}
    >
      {type === "success" ? (
        <CheckCircle className="h-4 w-4 shrink-0" />
      ) : (
        <XCircle className="h-4 w-4 shrink-0" />
      )}
      {message}
    </div>
  )
}

// ── Context Menu ──────────────────────────────────────────────────────────────

function ContextMenu({
  x,
  y,
  nodeId,
  onDelete,
  onDuplicate,
  onInspect,
  onClose,
}: {
  x: number
  y: number
  nodeId: string
  onDelete: (id: string) => void
  onDuplicate: (id: string) => void
  onInspect: (id: string) => void
  onClose: () => void
}) {
  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        className="fixed z-50 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl py-1 min-w-[160px]"
        style={{ left: x, top: y }}
      >
        <button
          className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
          onClick={() => { onInspect(nodeId); onClose() }}
        >
          <Info className="h-3.5 w-3.5 text-slate-400" />
          View Details
        </button>
        <button
          className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
          onClick={() => { onDuplicate(nodeId); onClose() }}
        >
          <Copy className="h-3.5 w-3.5 text-slate-400" />
          Duplicate
        </button>
        <div className="my-1 border-t border-slate-800" />
        <button
          className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-red-400 hover:bg-red-950/50 transition-colors"
          onClick={() => { onDelete(nodeId); onClose() }}
        >
          <Trash2 className="h-3.5 w-3.5" />
          Delete Node
        </button>
      </div>
    </>
  )
}

// ── Palette Sidebar ───────────────────────────────────────────────────────────

function PaletteSidebar({ rules }: { rules: ApiRule[] }) {
  const [ruleSearch, setRuleSearch] = useState("")
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({})

  const filteredRules = rules.filter((r) =>
    r.name.toLowerCase().includes(ruleSearch.toLowerCase()) ||
    (r.mitre_techniques ?? []).some((t) => t.toLowerCase().includes(ruleSearch.toLowerCase()))
  )

  function toggleSection(key: string) {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  function onDragStartItem(e: React.DragEvent, nodeType: string, nodeData: Record<string, unknown>) {
    e.dataTransfer.setData("application/reactflow-type", nodeType)
    e.dataTransfer.setData("application/reactflow-data", JSON.stringify(nodeData))
    e.dataTransfer.effectAllowed = "move"
  }

  return (
    <div className="w-64 shrink-0 border-r border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800">
        <div className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Node Palette</div>
      </div>
      <div className="flex-1 overflow-y-auto">

        {/* LOG SOURCES */}
        <div>
          <button
            onClick={() => toggleSection("log")}
            className="w-full flex items-center justify-between px-4 py-2.5 text-[10px] font-bold text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
          >
            Log Sources
            <ChevronRight className={cn("h-3 w-3 transition-transform", !collapsed.log && "rotate-90")} />
          </button>
          {!collapsed.log && (
            <div className="px-3 pb-3 space-y-1.5">
              {LOG_SOURCE_PALETTE.map((src) => (
                <div
                  key={src.id}
                  draggable
                  onDragStart={(e) =>
                    onDragStartItem(e, "logSource", {
                      label: src.label,
                      category: src.category,
                      icon: src.icon,
                      source_id: src.id,
                    })
                  }
                  className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-slate-300 cursor-grab active:cursor-grabbing hover:border-violet-500/50 hover:bg-slate-800 transition-all"
                >
                  <span className="text-sm leading-none">{src.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium truncate">{src.label}</div>
                    <div className="text-[9px] text-slate-500 capitalize">{src.category}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* SIEM PLATFORMS */}
        <div>
          <button
            onClick={() => toggleSection("siem")}
            className="w-full flex items-center justify-between px-4 py-2.5 text-[10px] font-bold text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
          >
            SIEM Platforms
            <ChevronRight className={cn("h-3 w-3 transition-transform", !collapsed.siem && "rotate-90")} />
          </button>
          {!collapsed.siem && (
            <div className="px-3 pb-3 space-y-1.5">
              {SIEM_PALETTE.map((s) => (
                <div
                  key={s.id}
                  draggable
                  onDragStart={(e) =>
                    onDragStartItem(e, "siem", {
                      label: s.label,
                      icon: s.icon,
                      siem_id: s.id,
                    })
                  }
                  className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-slate-300 cursor-grab active:cursor-grabbing hover:border-blue-500/50 hover:bg-slate-800 transition-all"
                >
                  <span className="text-sm leading-none">{s.icon}</span>
                  <span className="font-medium">{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* DETECTION RULES */}
        <div>
          <button
            onClick={() => toggleSection("rules")}
            className="w-full flex items-center justify-between px-4 py-2.5 text-[10px] font-bold text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
          >
            Detection Rules
            <ChevronRight className={cn("h-3 w-3 transition-transform", !collapsed.rules && "rotate-90")} />
          </button>
          {!collapsed.rules && (
            <div className="px-3 pb-3 space-y-2">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-500" />
                <Input
                  value={ruleSearch}
                  onChange={(e) => setRuleSearch(e.target.value)}
                  placeholder="Filter rules..."
                  className="pl-7 h-7 text-xs bg-slate-900 border-slate-700 text-slate-300 placeholder:text-slate-600"
                />
              </div>
              {filteredRules.length === 0 && rules.length === 0 && (
                <div className="text-[10px] text-slate-600 text-center py-3">
                  No rules loaded. Connect your SIEM.
                </div>
              )}
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {filteredRules.slice(0, 30).map((rule) => (
                  <div
                    key={rule.id}
                    draggable
                    onDragStart={(e) =>
                      onDragStartItem(e, "detectionRule", {
                        label: rule.name,
                        technique: rule.mitre_techniques?.[0] ?? "",
                        rule_id: rule.id,
                        status: rule.last_result ?? "untested",
                      })
                    }
                    className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-2 text-[10px] text-slate-300 cursor-grab active:cursor-grabbing hover:border-green-500/40 hover:bg-slate-800 transition-all"
                  >
                    <AlertTriangle className="h-3 w-3 text-slate-500 mt-0.5 shrink-0" />
                    <div className="min-w-0">
                      <div className="font-medium truncate">{rule.name}</div>
                      {rule.mitre_techniques?.[0] && (
                        <div className="font-mono text-slate-500">{rule.mitre_techniques[0]}</div>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Static demo rules when no API rules */}
              {rules.length === 0 && (
                <div className="space-y-1 pt-1">
                  {[
                    { id: "demo-1", name: "LSASS Memory Access", tech: "T1003.001" },
                    { id: "demo-2", name: "PowerShell Encoded Command", tech: "T1059.001" },
                    { id: "demo-3", name: "Scheduled Task Creation", tech: "T1053.005" },
                    { id: "demo-4", name: "Pass-the-Hash", tech: "T1550.002" },
                    { id: "demo-5", name: "DCSync Attack", tech: "T1003.006" },
                  ].map((r) => (
                    <div
                      key={r.id}
                      draggable
                      onDragStart={(e) =>
                        onDragStartItem(e, "detectionRule", {
                          label: r.name,
                          technique: r.tech,
                          rule_id: r.id,
                          status: "untested",
                        })
                      }
                      className="flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-2 text-[10px] text-slate-300 cursor-grab active:cursor-grabbing hover:border-green-500/40 hover:bg-slate-800 transition-all"
                    >
                      <AlertTriangle className="h-3 w-3 text-slate-500 mt-0.5 shrink-0" />
                      <div className="min-w-0">
                        <div className="font-medium truncate">{r.name}</div>
                        <div className="font-mono text-slate-500">{r.tech}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* INFRASTRUCTURE */}
        <div>
          <button
            onClick={() => toggleSection("infra")}
            className="w-full flex items-center justify-between px-4 py-2.5 text-[10px] font-bold text-violet-400/80 uppercase tracking-widest hover:text-violet-300 transition-colors"
          >
            ⚙ Infrastructure
            <ChevronRight className={cn("h-3 w-3 transition-transform", !collapsed.infra && "rotate-90")} />
          </button>
          {!collapsed.infra && (
            <div className="px-3 pb-3 space-y-3">
              {/* Endpoints */}
              <div>
                <div className="text-[9px] text-slate-600 uppercase tracking-widest font-bold px-1 mb-1.5">Endpoints</div>
                <div className="space-y-1">
                  {INFRA_PALETTE.endpoints.map((item) => (
                    <div key={item.id} draggable
                      onDragStart={(e) => onDragStartItem(e, "infra", { ...item, hostname: "", ip: "" })}
                      className="flex items-center gap-2 rounded-lg border border-violet-900/50 bg-violet-950/20 px-2.5 py-1.5 text-[10px] text-violet-300 cursor-grab active:cursor-grabbing hover:border-violet-500/50 hover:bg-violet-950/40 transition-all"
                    >
                      <span className="text-sm leading-none">{item.icon}</span>
                      <span className="font-medium truncate">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* Cloud Accounts */}
              <div>
                <div className="text-[9px] text-slate-600 uppercase tracking-widest font-bold px-1 mb-1.5">Cloud Accounts</div>
                <div className="space-y-1">
                  {INFRA_PALETTE.cloud.map((item) => (
                    <div key={item.id} draggable
                      onDragStart={(e) => onDragStartItem(e, "infra", { ...item, hostname: "", ip: "" })}
                      className="flex items-center gap-2 rounded-lg border border-sky-900/50 bg-sky-950/20 px-2.5 py-1.5 text-[10px] text-sky-300 cursor-grab active:cursor-grabbing hover:border-sky-500/50 hover:bg-sky-950/40 transition-all"
                    >
                      <span className="text-sm leading-none">{item.icon}</span>
                      <div className="min-w-0">
                        <div className="font-medium truncate">{item.label}</div>
                        <div className="text-[8px] text-sky-500/70">{(item.services ?? []).join(", ")}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {/* Email Platforms */}
              <div>
                <div className="text-[9px] text-slate-600 uppercase tracking-widest font-bold px-1 mb-1.5">Email Platforms</div>
                <div className="space-y-1">
                  {INFRA_PALETTE.email.map((item) => (
                    <div key={item.id} draggable
                      onDragStart={(e) => onDragStartItem(e, "infra", { ...item, hostname: "", ip: "" })}
                      className="flex items-center gap-2 rounded-lg border border-teal-900/50 bg-teal-950/20 px-2.5 py-1.5 text-[10px] text-teal-300 cursor-grab active:cursor-grabbing hover:border-teal-500/50 hover:bg-teal-950/40 transition-all"
                    >
                      <span className="text-sm leading-none">{item.icon}</span>
                      <span className="font-medium truncate">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* EDR Sensors */}
              <div>
                <div className="text-[9px] text-slate-600 uppercase tracking-widest font-bold px-1 mb-1.5">EDR Sensors</div>
                <div className="space-y-1">
                  {INFRA_PALETTE.edr.map((item) => (
                    <div key={item.id} draggable
                      onDragStart={(e) => onDragStartItem(e, "infra", { ...item, hostname: "", ip: "" })}
                      className="flex items-center gap-2 rounded-lg border border-emerald-900/50 bg-emerald-950/20 px-2.5 py-1.5 text-[10px] text-emerald-300 cursor-grab active:cursor-grabbing hover:border-emerald-500/50 hover:bg-emerald-950/40 transition-all"
                    >
                      <span className="text-sm leading-none">{item.icon}</span>
                      <span className="font-medium truncate">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              {/* ITSM / CMDB */}
              <div>
                <div className="text-[9px] text-slate-600 uppercase tracking-widest font-bold px-1 mb-1.5">ITSM / CMDB</div>
                <div className="space-y-1">
                  {INFRA_PALETTE.itsm.map((item) => (
                    <div key={item.id} draggable
                      onDragStart={(e) => onDragStartItem(e, "infra", { ...item, hostname: "", ip: "" })}
                      className="flex items-center gap-2 rounded-lg border border-orange-900/50 bg-orange-950/20 px-2.5 py-1.5 text-[10px] text-orange-300 cursor-grab active:cursor-grabbing hover:border-orange-500/50 hover:bg-orange-950/40 transition-all"
                    >
                      <span className="text-sm leading-none">{item.icon}</span>
                      <span className="font-medium truncate">{item.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* USE CASES */}
        <div>
          <button
            onClick={() => toggleSection("usecases")}
            className="w-full flex items-center justify-between px-4 py-2.5 text-[10px] font-bold text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
          >
            Use Cases
            <ChevronRight className={cn("h-3 w-3 transition-transform", !collapsed.usecases && "rotate-90")} />
          </button>
          {!collapsed.usecases && (
            <div className="px-3 pb-3 space-y-1.5">
              {[
                { id: "uc-1", label: "Credential Harvesting", tech: "T1003" },
                { id: "uc-2", label: "Lateral Movement", tech: "T1021" },
                { id: "uc-3", label: "Persistence via Registry", tech: "T1547" },
                { id: "uc-4", label: "Exfiltration over HTTPS", tech: "T1041" },
              ].map((uc) => (
                <div
                  key={uc.id}
                  draggable
                  onDragStart={(e) =>
                    onDragStartItem(e, "useCase", {
                      label: uc.label,
                      technique: uc.tech,
                      status: "PENDING",
                    })
                  }
                  className="flex items-center gap-2.5 rounded-lg border border-amber-900/50 bg-amber-950/20 px-2.5 py-2 text-[10px] text-amber-300/80 cursor-grab active:cursor-grabbing hover:border-amber-600/50 hover:bg-amber-950/40 transition-all"
                >
                  <Cpu className="h-3 w-3 shrink-0" />
                  <div className="min-w-0">
                    <div className="font-medium truncate">{uc.label}</div>
                    <div className="font-mono text-amber-500/60">{uc.tech}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Page Component ────────────────────────────────────────────────────────────

export default function EnvironmentCanvasPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()

  const [envName, setEnvName] = useState("")
  const [editingName, setEditingName] = useState(false)
  const [rules, setRules] = useState<ApiRule[]>([])
  const [loading, setLoading] = useState(true)

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [showSimModal, setShowSimModal] = useState(false)
  const [showProductsModal, setShowProductsModal] = useState(false)
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; nodeId: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [deploying, setDeploying] = useState(false)

  const reactFlowInstance = useRef<ReactFlowInstance | null>(null)
  const reactFlowWrapper = useRef<HTMLDivElement | null>(null)

  // ── Load environment ────────────────────────────────────────────────────────
  useEffect(() => {
    async function load() {
      setLoading(true)
      try {
        const res = await authFetch(`${API_BASE}/api/v2/environments/${id}`)
        if (res.ok) {
          const data = (await res.json()) as ApiEnvironment
          setEnvName(data.name)

          const topology = data.settings?.canvas_topology
          // Guard: template topologies store nodes as string[] — fall through to auto-layout
          const hasValidNodes =
            topology?.nodes?.length &&
            typeof (topology.nodes as unknown[])[0] === 'object'
          if (hasValidNodes) {
            setNodes(topology!.nodes)
            setEdges(topology!.edges ?? [])
          } else {
            // Auto-layout from log_sources + siem_platform
            const siemInfo = SIEM_PALETTE.find((s) => s.id === data.siem_platform) ??
              SIEM_PALETTE[0]
            const sources = data.log_sources?.length
              ? data.log_sources.map((ls) => {
                  const known = LOG_SOURCE_PALETTE.find((p) => p.id === ls.source_id)
                  return known ?? {
                    id: ls.source_id,
                    label: ls.name ?? ls.source_id,
                    category: ls.category ?? "endpoint",
                    icon: "🖥️",
                  }
                })
              : LOG_SOURCE_PALETTE.slice(0, 4)
            const auto = buildAutoLayout(sources, siemInfo.id, siemInfo.label, siemInfo.icon)
            setNodes(auto.nodes)
            setEdges(auto.edges)
          }
        } else {
          // Fallback: demo layout
          setEnvName("New Environment")
          const auto = buildAutoLayout(
            LOG_SOURCE_PALETTE.slice(0, 3),
            "splunk",
            "Splunk",
            "🔍"
          )
          setNodes(auto.nodes)
          setEdges(auto.edges)
        }
      } catch {
        setEnvName("New Environment")
        const auto = buildAutoLayout(
          LOG_SOURCE_PALETTE.slice(0, 3),
          "splunk",
          "Splunk",
          "🔍"
        )
        setNodes(auto.nodes)
        setEdges(auto.edges)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  // ── Load rules ──────────────────────────────────────────────────────────────
  useEffect(() => {
    async function loadRules() {
      try {
        const res = await authFetch(`${API_BASE}/api/v2/rules?limit=100`)
        if (res.ok) {
          const data = (await res.json()) as { items?: ApiRule[] } | ApiRule[]
          setRules(Array.isArray(data) ? data : (data.items ?? []))
        }
      } catch {
        // silent — demo rules shown from palette
      }
    }
    loadRules()
  }, [])

  // ── Toast auto-dismiss ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3000)
    return () => clearTimeout(t)
  }, [toast])

  // ── Callbacks ───────────────────────────────────────────────────────────────

  const onConnect = useCallback(
    (connection: Connection) =>
      setEdges((eds) =>
        addEdge(
          {
            ...connection,
            animated: false,
            style: { stroke: "#6d28d9", strokeWidth: 1.5 },
          },
          eds
        )
      ),
    [setEdges]
  )

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      const nodeType = e.dataTransfer.getData("application/reactflow-type")
      const rawData = e.dataTransfer.getData("application/reactflow-data")
      if (!nodeType || !rawData) return

      let nodeData: Record<string, unknown> = {}
      try { nodeData = JSON.parse(rawData) as Record<string, unknown> } catch { return }

      if (!reactFlowInstance.current) return

      const position = reactFlowInstance.current.screenToFlowPosition({
        x: e.clientX,
        y: e.clientY,
      })

      const newNode: Node = {
        id: `${nodeType}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        type: nodeType,
        position,
        data: nodeData,
      }
      setNodes((nds) => [...nds, newNode])
    },
    [setNodes]
  )

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.dataTransfer.dropEffect = "move"
  }, [])

  function handleNodeClick(_: React.MouseEvent, node: Node) {
    setSelectedNode(node)
    setContextMenu(null)
  }

  function handlePaneClick() {
    setSelectedNode(null)
    setContextMenu(null)
  }

  function handleNodeContextMenu(e: React.MouseEvent, node: Node) {
    e.preventDefault()
    setContextMenu({ x: e.clientX, y: e.clientY, nodeId: node.id })
  }

  function deleteNode(nodeId: string) {
    setNodes((nds) => nds.filter((n) => n.id !== nodeId))
    setEdges((eds) => eds.filter((e) => e.source !== nodeId && e.target !== nodeId))
    if (selectedNode?.id === nodeId) setSelectedNode(null)
  }

  function duplicateNode(nodeId: string) {
    const node = nodes.find((n) => n.id === nodeId)
    if (!node) return
    const newNode: Node = {
      ...node,
      id: `${node.type}-${Date.now()}`,
      position: { x: node.position.x + 30, y: node.position.y + 30 },
    }
    setNodes((nds) => [...nds, newNode])
  }

  function inspectNode(nodeId: string) {
    const node = nodes.find((n) => n.id === nodeId)
    if (node) setSelectedNode(node)
  }

  // ── Save ────────────────────────────────────────────────────────────────────

  async function handleSave() {
    setSaving(true)
    try {
      const topology: CanvasTopology = { nodes, edges }
      const res = await authFetch(`${API_BASE}/api/v2/environments/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: envName,
          settings: { canvas_topology: topology },
        }),
      })
      if (res.ok) {
        setToast({ message: "Topology saved", type: "success" })
      } else {
        setToast({ message: "Failed to save", type: "error" })
      }
    } catch {
      setToast({ message: "Save error", type: "error" })
    } finally {
      setSaving(false)
    }
  }

  // ── Deploy — populate CMDB assets from infrastructure nodes ─────────────────

  async function handleDeploy() {
    const infraNodes = nodes.filter((n) => n.type === "infra")
    if (infraNodes.length === 0) return
    setDeploying(true)
    try {
      // Auto-save topology first
      await authFetch(`${API_BASE}/api/v2/environments/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: envName, settings: { canvas_topology: { nodes, edges } } }),
      })
      // Deploy infrastructure — creates asset records from endpoint/cloud nodes
      const res = await authFetch(`${API_BASE}/api/v2/environments/${id}/deploy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          infrastructure: infraNodes.map((n) => ({
            node_id: n.id,
            subtype: n.data.subtype,
            variant: n.data.variant,
            label: n.data.label,
            hostname: n.data.hostname ?? "",
            ip: n.data.ip ?? "",
            user_count: n.data.user_count ?? 0,
            services: n.data.services ?? [],
          })),
        }),
      })
      if (res.ok) {
        const result = (await res.json()) as { assets_created: number; message?: string }
        setToast({ message: `Deployed: ${result.assets_created} assets registered in CMDB`, type: "success" })
      } else {
        setToast({ message: "Deploy failed — check backend logs", type: "error" })
      }
    } catch {
      setToast({ message: "Deploy error", type: "error" })
    } finally {
      setDeploying(false)
    }
  }

  // ── Simulate ────────────────────────────────────────────────────────────────

  async function handleStartSim(cfg: SimConfig) {
    setShowSimModal(false)
    try {
      const durationMap = { quick: 50, standard: 200, extended: 500 }

      // Resolve MCP server URL: joti preset points to Joti's MCP endpoint
      let mcpUrl = cfg.mcp_server_url
      if (cfg.mode === "mcp_ingest" && cfg.mcp_preset === "joti") {
        mcpUrl = `${API_BASE}/api/v2/mcp`
      }

      // Extract infrastructure nodes from canvas for backend log routing
      const canvasInfra = nodes
        .filter((n) => n.type === "infra")
        .map((n) => ({ id: n.id, subtype: n.data.subtype, variant: n.data.variant, label: n.data.label, services: n.data.services ?? [] }))

      const body: Record<string, unknown> = {
        environment_id: id,
        simulation_mode: cfg.mode,
        event_count: durationMap[cfg.duration],
        auto_start: true,
        // infrastructure topology from canvas
        canvas_infrastructure: canvasInfra,
        // attack_chain
        attack_chains: cfg.chains,
        // threat_actor
        ...(cfg.mode === "threat_actor" && {
          threat_actor_id: cfg.threat_actor_id,
          threat_actor_name: cfg.threat_actor_name,
          threat_actor_ttps: cfg.threat_actor_ttps ?? [],
        }),
        // ttps
        ...(cfg.mode === "ttps" && {
          technique_ids: cfg.technique_ids ?? [],
        }),
        // mcp_ingest
        ...(cfg.mode === "mcp_ingest" && {
          mcp_server_url: mcpUrl,
          mcp_api_key: cfg.mcp_api_key,
          mcp_tool: cfg.mcp_tool ?? "siem_search_events",
          mcp_query: cfg.mcp_query,
        }),
      }

      const res = await authFetch(`${API_BASE}/api/v2/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        const session = (await res.json()) as { id: string }
        setToast({ message: "Simulation started!", type: "success" })
        router.push(`/sessions/${session.id}`)
      } else {
        const err = await res.json().catch(() => ({})) as { detail?: string }
        setToast({ message: err.detail ?? "Failed to start simulation", type: "error" })
      }
    } catch {
      setToast({ message: "Simulation error", type: "error" })
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-3.5rem)]">
        <div className="text-slate-500 text-sm animate-pulse">Loading environment...</div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] -m-6 overflow-hidden bg-slate-950">
      {/* Top Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-slate-800 bg-slate-950 shrink-0 z-10">
        <button
          onClick={() => router.push("/environments")}
          className="flex items-center gap-1.5 text-slate-400 hover:text-slate-200 transition-colors text-xs"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back
        </button>
        <div className="w-px h-5 bg-slate-800" />

        {/* Editable env name */}
        {editingName ? (
          <input
            autoFocus
            value={envName}
            onChange={(e) => setEnvName(e.target.value)}
            onBlur={() => setEditingName(false)}
            onKeyDown={(e) => e.key === "Enter" && setEditingName(false)}
            className="bg-slate-800 text-slate-100 text-sm font-semibold px-2 py-1 rounded border border-slate-600 focus:outline-none focus:border-violet-500 min-w-0 w-48"
          />
        ) : (
          <button
            onClick={() => setEditingName(true)}
            className="text-sm font-semibold text-slate-200 hover:text-white transition-colors truncate max-w-xs"
            title="Click to rename"
          >
            {envName}
          </button>
        )}

        {/* Stats */}
        <div className="flex items-center gap-2 ml-1">
          <Badge className="text-[10px] border-slate-700 bg-slate-800 text-slate-400">
            {nodes.length} nodes
          </Badge>
          <Badge className="text-[10px] border-slate-700 bg-slate-800 text-slate-400">
            {edges.length} connections
          </Badge>
        </div>

        <div className="flex-1" />

        {/* Actions */}
        <Button

          size="sm"
          onClick={() => setShowProductsModal(true)}
          className="border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100 gap-1.5"
          title="Configure security product vendors"
        >
          <Package className="h-3.5 w-3.5" />
          Products
        </Button>
        <Button

          size="sm"
          onClick={handleSave}
          disabled={saving}
          className="border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100 gap-1.5"
        >
          <Save className="h-3.5 w-3.5" />
          {saving ? "Saving…" : "Save"}
        </Button>
        <Button
          size="sm"
          onClick={() => void handleDeploy()}
          disabled={deploying || nodes.filter((n) => n.type === "infra").length === 0}
          className="border-emerald-700/50 text-emerald-400 hover:border-emerald-500 hover:text-emerald-300 gap-1.5"
          title="Deploy environment — auto-populate CMDB from infrastructure nodes"
        >
          {deploying ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Server className="h-3.5 w-3.5" />}
          Deploy
        </Button>
        <Button
          size="sm"
          onClick={() => setShowSimModal(true)}
          className="bg-violet-600 hover:bg-violet-500 text-white gap-1.5"
        >
          <Play className="h-3.5 w-3.5" />
          Simulate
        </Button>
      </div>

      {/* Body: Palette + Canvas + Inspector */}
      <div className="flex flex-1 overflow-hidden">
        {/* Palette */}
        <PaletteSidebar rules={rules} />

        {/* Canvas */}
        <div
          ref={reactFlowWrapper}
          className="flex-1 relative"
          onDrop={onDrop}
          onDragOver={onDragOver}
        >
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={handleNodeClick}
            onPaneClick={handlePaneClick}
            onNodeContextMenu={handleNodeContextMenu}
            onInit={(instance) => { reactFlowInstance.current = instance }}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            style={{ background: "#020617" }}
            defaultEdgeOptions={{
              style: { stroke: "#6d28d9", strokeWidth: 1.5 },
              animated: false,
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background
              color="#1e293b"
              gap={20}
              size={1}
              style={{ backgroundColor: "#020617" }}
            />
            <Controls
              style={{
                background: "#0f172a",
                border: "1px solid #1e293b",
                borderRadius: "0.5rem",
              }}
            />
            <MiniMap
              nodeColor={(node) => {
                if (node.type === "infra") {
                  const subtypeColors: Record<string, string> = {
                    endpoint: "#7c3aed", cloud: "#0284c7", email: "#0d9488", edr: "#059669", itsm: "#ea580c",
                  }
                  return subtypeColors[String(node.data?.subtype ?? "")] ?? "#6d28d9"
                }
                const colors: Record<string, string> = {
                  logSource: "#7c3aed", siem: "#2563eb", detectionRule: "#16a34a", useCase: "#d97706",
                }
                return colors[node.type ?? ""] ?? "#4b5563"
              }}
              style={{
                background: "#0f172a",
                border: "1px solid #1e293b",
                borderRadius: "0.5rem",
              }}
              maskColor="rgba(2,6,23,0.7)"
            />
          </ReactFlow>

          {/* Empty state hint */}
          {nodes.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="text-center">
                <div className="text-slate-700 text-4xl mb-3">⬡</div>
                <div className="text-slate-600 text-sm font-medium">Drag nodes from the palette to build your environment</div>
              </div>
            </div>
          )}
        </div>

        {/* Inspector Panel */}
        {selectedNode && (
          <InspectorPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
            onDelete={deleteNode}
            onDuplicate={duplicateNode}
          />
        )}
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          nodeId={contextMenu.nodeId}
          onDelete={deleteNode}
          onDuplicate={duplicateNode}
          onInspect={inspectNode}
          onClose={() => setContextMenu(null)}
        />
      )}

      {/* Products Modal */}
      {showProductsModal && (
        <ProductsModal
          envId={id}
          onClose={() => setShowProductsModal(false)}
          onSaved={() => setToast({ message: "Product selections saved", type: "success" })}
        />
      )}

      {/* Simulate Modal */}
      {showSimModal && (
        <SimulateModal
          envName={envName}
          onClose={() => setShowSimModal(false)}
          onStart={handleStartSim}
        />
      )}

      {/* Toast */}
      {toast && <Toast message={toast.message} type={toast.type} />}
    </div>
  )
}
