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
  Search,
  X,
  Copy,
  Trash2,
  Shield,
  Database,
  Cpu,
  AlertTriangle,
  Info,
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

interface SimConfig {
  chains: string[]
  duration: "quick" | "standard" | "extended"
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
]

const SIEM_PALETTE = [
  { id: "splunk", label: "Splunk", icon: "🔍" },
  { id: "elastic", label: "Elastic/SIEM", icon: "🔎" },
  { id: "sentinel", label: "Microsoft Sentinel", icon: "🛡️" },
]

const CATEGORY_COLORS: Record<string, string> = {
  endpoint: "border-violet-500/50 bg-violet-500/10 text-violet-300",
  identity: "border-amber-500/50 bg-amber-500/10 text-amber-300",
  cloud: "border-sky-500/50 bg-sky-500/10 text-sky-300",
  network: "border-teal-500/50 bg-teal-500/10 text-teal-300",
}

const ATTACK_CHAINS = [
  { id: "apt29_cred", label: "APT29 Credential Harvest" },
  { id: "ransomware_precursor", label: "Ransomware Precursor" },
  { id: "lateral_movement", label: "Lateral Movement Chain" },
  { id: "exfiltration", label: "Data Exfiltration" },
  { id: "persistence", label: "Persistence & C2" },
]

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

const nodeTypes: NodeTypes = {
  logSource: LogSourceNode,
  siem: SIEMNode,
  detectionRule: DetectionRuleNode,
  useCase: UseCaseNode,
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

// ── Simulate Modal ────────────────────────────────────────────────────────────

function SimulateModal({
  envName,
  onClose,
  onStart,
}: {
  envName: string
  onClose: () => void
  onStart: (cfg: SimConfig) => void
}) {
  const [selectedChains, setSelectedChains] = useState<string[]>(["apt29_cred"])
  const [duration, setDuration] = useState<SimConfig["duration"]>("standard")

  function toggleChain(id: string) {
    setSelectedChains((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]
    )
  }

  const durationOpts: Array<{ value: SimConfig["duration"]; label: string; events: string }> = [
    { value: "quick", label: "Quick", events: "50 events" },
    { value: "standard", label: "Standard", events: "200 events" },
    { value: "extended", label: "Extended", events: "500 events" },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />

      {/* Modal */}
      <div className="relative bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div>
            <h2 className="text-sm font-bold text-slate-100">Run Simulation</h2>
            <p className="text-xs text-slate-500 mt-0.5">{envName}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Attack chains */}
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Select Attack Chains
            </div>
            <div className="space-y-2">
              {ATTACK_CHAINS.map((chain) => {
                const checked = selectedChains.includes(chain.id)
                return (
                  <label
                    key={chain.id}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer transition-colors",
                      checked
                        ? "border-violet-500/50 bg-violet-500/10"
                        : "border-slate-700 hover:border-slate-600"
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleChain(chain.id)}
                      className="accent-violet-500"
                    />
                    <span className="text-sm text-slate-200">{chain.label}</span>
                  </label>
                )
              })}
            </div>
          </div>

          {/* Duration */}
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Simulation Duration
            </div>
            <div className="flex gap-2">
              {durationOpts.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setDuration(opt.value)}
                  className={cn(
                    "flex-1 flex flex-col items-center py-2.5 rounded-lg border text-xs font-medium transition-colors",
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
        </div>

        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-800">
          <Button variant="ghost" size="sm" onClick={onClose} className="text-slate-400">
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={() => onStart({ chains: selectedChains, duration })}
            disabled={selectedChains.length === 0}
            className="bg-violet-600 hover:bg-violet-500 text-white"
          >
            <Play className="h-3.5 w-3.5" />
            Start Simulation
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
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
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; nodeId: string } | null>(null)
  const [saving, setSaving] = useState(false)

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
          if (topology?.nodes?.length) {
            setNodes(topology.nodes)
            setEdges(topology.edges ?? [])
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

      const bounds = reactFlowWrapper.current?.getBoundingClientRect()
      if (!bounds || !reactFlowInstance.current) return

      const position = reactFlowInstance.current.screenToFlowPosition({
        x: e.clientX - bounds.left,
        y: e.clientY - bounds.top,
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

  // ── Simulate ────────────────────────────────────────────────────────────────

  async function handleStartSim(cfg: SimConfig) {
    setShowSimModal(false)
    try {
      const durationMap = { quick: 50, standard: 200, extended: 500 }
      const res = await authFetch(`${API_BASE}/api/v2/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          environment_id: id,
          attack_chains: cfg.chains,
          event_count: durationMap[cfg.duration],
        }),
      })
      if (res.ok) {
        const session = (await res.json()) as { id: string }
        setToast({ message: "Simulation started!", type: "success" })
        router.push(`/sessions/${session.id}`)
      } else {
        setToast({ message: "Failed to start simulation", type: "error" })
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
          onClick={handleSave}
          disabled={saving}
          className="border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100 gap-1.5"
        >
          <Save className="h-3.5 w-3.5" />
          {saving ? "Saving…" : "Save"}
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
                const colors: Record<string, string> = {
                  logSource: "#7c3aed",
                  siem: "#2563eb",
                  detectionRule: "#16a34a",
                  useCase: "#d97706",
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
