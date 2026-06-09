'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Search,
  ShieldAlert,
  PlayCircle,
  Copy,
  Check,
  ChevronDown,
  Loader2,
  AlertCircle,
  RefreshCw,
  Terminal,
  FileCode2,
  ClipboardList,
  Zap,
  Eye,
  Download,
  ExternalLink,
  Fingerprint,
  KeyRound,
  UserX,
  Globe,
  Lock,
  Key,
  Layers,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Drawer } from '@/components/ui/Drawer'
import { apiGet, apiPost } from '@/lib/api/client'
import { AskAboutThis } from '@/components/AskAboutThis'

// ─── Types ─────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'

interface ScenarioSummary {
  id: string
  name: string
  technique_id: string
  mitre_tactic: string
  severity: Severity
  platforms: string[]
  step_count: number
}

interface SimStep {
  step: number
  action: string
  command: string
  tool: string
  description: string
  purplelab_atomic?: string
  simulated?: boolean
}

interface ExpectedLog {
  source: string
  event_id?: number
  description: string
  key_fields?: string[]
}

interface ScenarioDetail extends ScenarioSummary {
  description: string
  prerequisites: string[]
  simulation_steps: SimStep[]
  expected_logs: ExpectedLog[]
  detection_sigma: string
  hunt_query_spl: string
  hunt_query_kql: string
}

interface SimulateResult {
  status: string
  scenario: string
  technique_id: string
  steps?: SimStep[]
  expected_logs?: ExpectedLog[]
  message: string
}

// ─── Helpers ───────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/10 border-red-500/20 text-red-400',
  high: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
}

const PLATFORM_ICONS: Record<string, React.ElementType> = {
  windows: Terminal,
  active_directory: Layers,
  azure_ad: Globe,
  entra_id: Globe,
  okta: KeyRound,
  duo: Lock,
  office_365: Key,
  default: Fingerprint,
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn('rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize', SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.medium)}>
      {severity}
    </span>
  )
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  function handleCopy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs text-slate-400 hover:text-white hover:border-slate-600 transition-colors"
    >
      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      {label ?? (copied ? 'Copied' : 'Copy')}
    </button>
  )
}

function TacticIcon({ tactic }: { tactic: string }) {
  if (tactic.includes('Credential')) return <KeyRound className="h-4 w-4 text-orange-400" />
  if (tactic.includes('Lateral')) return <Globe className="h-4 w-4 text-blue-400" />
  if (tactic.includes('Privilege')) return <Layers className="h-4 w-4 text-violet-400" />
  if (tactic.includes('Defense')) return <ShieldAlert className="h-4 w-4 text-yellow-400" />
  if (tactic.includes('Persistence')) return <Lock className="h-4 w-4 text-red-400" />
  if (tactic.includes('Initial')) return <UserX className="h-4 w-4 text-pink-400" />
  return <Fingerprint className="h-4 w-4 text-slate-400" />
}

// ─── Detail Drawer content ─────────────────────────────────────────────────

type DetailTab = 'overview' | 'logs' | 'detection' | 'hunt'

function ScenarioDetailContent({ scenario }: { scenario: ScenarioDetail }) {
  const [tab, setTab] = useState<DetailTab>('overview')
  const [simulating, setSimulating] = useState(false)
  const [dryRun, setDryRun] = useState(true)
  const [envId, setEnvId] = useState('')
  const [notes, setNotes] = useState('')
  const [simResult, setSimResult] = useState<SimulateResult | null>(null)
  const [simError, setSimError] = useState('')

  async function handleSimulate() {
    setSimulating(true)
    setSimError('')
    setSimResult(null)
    try {
      const result = await apiPost<SimulateResult>(`/api/v2/itdr/scenarios/${scenario.id}/simulate`, {
        dry_run: dryRun,
        environment_id: envId || undefined,
        notes: notes || undefined,
      })
      setSimResult(result)
      if (!dryRun) setTab('overview')
    } catch (e) {
      setSimError(e instanceof Error ? e.message : 'Simulation failed')
    } finally {
      setSimulating(false)
    }
  }

  const tabs: { key: DetailTab; label: string; icon: React.ElementType }[] = [
    { key: 'overview', label: 'Overview', icon: ClipboardList },
    { key: 'logs', label: 'Expected Logs', icon: Eye },
    { key: 'detection', label: 'Sigma Rule', icon: FileCode2 },
    { key: 'hunt', label: 'Hunt Queries', icon: Search },
  ]

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-800">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="rounded-md bg-violet-500/10 border border-violet-500/20 px-2 py-0.5 font-mono text-[11px] text-violet-400">
                {scenario.technique_id}
              </span>
              <SeverityBadge severity={scenario.severity} />
            </div>
            <p className="text-xs text-slate-500 mt-1">{scenario.mitre_tactic} · {scenario.platforms.join(', ')}</p>
          </div>
          <a
            href={`https://attack.mitre.org/techniques/${scenario.technique_id.replace('.', '/')}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-violet-400 transition-colors shrink-0"
          >
            MITRE <ExternalLink className="h-3 w-3" />
          </a>
        </div>

        {/* Tabs */}
        <div className="flex gap-0.5 mt-4 rounded-lg border border-slate-800 bg-slate-900 p-1">
          {tabs.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={cn(
                'flex-1 flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-colors',
                tab === key ? 'bg-slate-800 text-slate-200' : 'text-slate-500 hover:text-slate-300'
              )}
            >
              <Icon className="h-3 w-3" />
              <span className="hidden sm:inline">{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Tab body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4">

        {/* ── Overview tab ── */}
        {tab === 'overview' && (
          <>
            <p className="text-sm text-slate-300 leading-relaxed">{scenario.description}</p>

            {/* Prerequisites */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">Prerequisites</h3>
              <ul className="space-y-1">
                {scenario.prerequisites.map((p, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm text-slate-400">
                    <span className="h-1.5 w-1.5 rounded-full bg-slate-600 shrink-0" />
                    {p}
                  </li>
                ))}
              </ul>
            </div>

            {/* Simulation steps */}
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
                Simulation Steps ({scenario.simulation_steps.length})
              </h3>
              <div className="space-y-3">
                {scenario.simulation_steps.map((step) => (
                  <div key={step.step} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-violet-500/20 text-[10px] font-bold text-violet-400">
                        {step.step}
                      </span>
                      <span className="text-sm font-medium text-slate-200">{step.description}</span>
                      {step.simulated && (
                        <span className="ml-auto rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500">
                          simulated
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-wrap mt-2">
                      <span className="rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500">
                        {step.tool}
                      </span>
                      {step.purplelab_atomic && (
                        <span className="rounded-md bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 text-[10px] text-violet-400">
                          atomic: {step.purplelab_atomic}
                        </span>
                      )}
                    </div>
                    {step.command && (
                      <div className="mt-2 flex items-start gap-2">
                        <pre className="flex-1 rounded-md bg-black/40 border border-slate-800 px-3 py-2 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap break-all">
                          {step.command}
                        </pre>
                        <CopyButton text={step.command} />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Simulate panel */}
            <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 p-4 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-violet-400 flex items-center gap-1.5">
                <Zap className="h-3.5 w-3.5" /> Run This Simulation
              </h3>

              <label className="flex items-center gap-3 cursor-pointer">
                <div
                  onClick={() => setDryRun(!dryRun)}
                  className={cn(
                    'w-9 h-5 rounded-full transition-colors relative cursor-pointer',
                    dryRun ? 'bg-slate-700' : 'bg-violet-600'
                  )}
                >
                  <span className={cn(
                    'absolute top-0.5 h-4 w-4 rounded-full bg-white transition-transform',
                    dryRun ? 'left-0.5' : 'left-[1.1rem]'
                  )} />
                </div>
                <div>
                  <span className="text-xs font-medium text-slate-300">{dryRun ? 'Dry Run (preview only)' : 'Live Simulation (creates session)'}</span>
                  <p className="text-[11px] text-slate-500">
                    {dryRun ? 'Returns expected steps and logs without creating a session.' : 'Dispatches to the exercise engine. A new Session will be created.'}
                  </p>
                </div>
              </label>

              {!dryRun && (
                <>
                  <div>
                    <label className="text-[11px] text-slate-500 block mb-1">Environment ID (optional)</label>
                    <input
                      value={envId}
                      onChange={e => setEnvId(e.target.value)}
                      placeholder="e.g. env-123"
                      className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] text-slate-500 block mb-1">Notes (optional)</label>
                    <textarea
                      value={notes}
                      onChange={e => setNotes(e.target.value)}
                      placeholder="Session context or test objectives…"
                      rows={2}
                      className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500 resize-none"
                    />
                  </div>
                </>
              )}

              <button
                onClick={() => void handleSimulate()}
                disabled={simulating}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-50 transition-colors"
              >
                {simulating ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
                {simulating ? 'Running…' : dryRun ? 'Preview Dry Run' : 'Launch Simulation'}
              </button>

              {simError && (
                <p className="flex items-center gap-1.5 text-xs text-red-400">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />{simError}
                </p>
              )}

              {simResult && (
                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 space-y-2">
                  <p className="text-xs font-medium text-emerald-400 flex items-center gap-1.5">
                    <Check className="h-3.5 w-3.5" />
                    {simResult.status === 'dry_run' ? 'Dry Run Complete' : 'Simulation Started'}
                  </p>
                  <p className="text-xs text-slate-400">{simResult.message}</p>
                  {simResult.status === 'simulation_started' && (
                    <a href="/sessions" className="flex items-center gap-1 text-xs text-violet-400 hover:underline">
                      View in Sessions <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
              )}
            </div>
          </>
        )}

        {/* ── Expected Logs tab ── */}
        {tab === 'logs' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-500">
              Log events your SIEM / identity platform should generate when this attack occurs.
              Use these to validate your detection coverage before running the simulation.
            </p>
            {scenario.expected_logs.map((log, i) => (
              <div key={i} className="rounded-lg border border-slate-800 bg-slate-900 p-3">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[11px] font-medium text-slate-300">
                    {log.source}
                  </span>
                  {log.event_id && (
                    <span className="rounded-md bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 font-mono text-[11px] text-violet-400">
                      Event {log.event_id}
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-300">{log.description}</p>
                {log.key_fields && log.key_fields.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {log.key_fields.map((f, j) => (
                      <span key={j} className="rounded-md bg-black/30 border border-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-emerald-400">
                        {f}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── Detection / Sigma tab ── */}
        {tab === 'detection' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-500">Production-ready Sigma rule. Import into any compatible SIEM.</p>
              <div className="flex gap-2">
                <CopyButton text={scenario.detection_sigma} label="Copy Sigma" />
                <button
                  onClick={() => {
                    const blob = new Blob([scenario.detection_sigma], { type: 'text/yaml' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `sigma_${scenario.id}.yml`
                    a.click()
                    URL.revokeObjectURL(url)
                  }}
                  className="flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs text-slate-400 hover:text-white transition-colors"
                >
                  <Download className="h-3 w-3" /> Download .yml
                </button>
              </div>
            </div>
            <pre className="rounded-xl border border-slate-800 bg-black/50 p-4 text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed">
              {scenario.detection_sigma}
            </pre>
          </div>
        )}

        {/* ── Hunt Queries tab ── */}
        {tab === 'hunt' && (
          <div className="space-y-5">
            {/* SPL */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <span className="rounded-md bg-orange-500/10 border border-orange-500/20 px-1.5 py-0.5 text-[10px] text-orange-400">SPL</span>
                  Splunk Hunt Query
                </h3>
                <CopyButton text={scenario.hunt_query_spl} label="Copy SPL" />
              </div>
              <pre className="rounded-xl border border-slate-800 bg-black/50 p-4 text-[11px] font-mono text-sky-300 overflow-x-auto whitespace-pre-wrap">
                {scenario.hunt_query_spl}
              </pre>
            </div>

            {/* KQL */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <span className="rounded-md bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 text-[10px] text-blue-400">KQL</span>
                  Microsoft Sentinel Hunt Query
                </h3>
                <CopyButton text={scenario.hunt_query_kql} label="Copy KQL" />
              </div>
              <pre className="rounded-xl border border-slate-800 bg-black/50 p-4 text-[11px] font-mono text-violet-300 overflow-x-auto whitespace-pre-wrap">
                {scenario.hunt_query_kql}
              </pre>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900 p-3">
              <p className="text-xs text-slate-500">
                Run these queries against your live SIEM after executing the simulation to validate detection coverage.
                Connect your SIEM under <a href="/settings/integrations" className="text-violet-400 hover:underline">Settings → Integrations</a>.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────

const TACTIC_OPTIONS = ['All Tactics', 'Credential Access', 'Lateral Movement', 'Privilege Escalation', 'Defense Evasion', 'Persistence', 'Initial Access']
const SEVERITY_OPTIONS = ['All Severities', 'critical', 'high', 'medium', 'low']
const PLATFORM_OPTIONS = ['All Platforms', 'windows', 'active_directory', 'azure_ad', 'entra_id', 'okta']

export default function ITDRPage() {
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('All Severities')
  const [tacticFilter, setTacticFilter] = useState('All Tactics')
  const [platformFilter, setPlatformFilter] = useState('All Platforms')
  const [selected, setSelected] = useState<ScenarioSummary | null>(null)
  const [detail, setDetail] = useState<ScenarioDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [toast, setToast] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await apiGet<{ scenarios: ScenarioSummary[]; total: number }>('/api/v2/itdr/scenarios')
      setScenarios(res.scenarios)
    } catch {
      setError('Could not load scenarios. Check that the PurpleLab backend is running.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function openDetail(s: ScenarioSummary) {
    setSelected(s)
    setDetail(null)
    setDetailLoading(true)
    try {
      const full = await apiGet<ScenarioDetail>(`/api/v2/itdr/scenarios/${s.id}`)
      setDetail(full)
    } catch {
      setToast('Failed to load scenario detail')
    } finally {
      setDetailLoading(false)
    }
  }

  const filtered = scenarios.filter((s) => {
    if (search && !s.name.toLowerCase().includes(search.toLowerCase()) && !s.technique_id.toLowerCase().includes(search.toLowerCase())) return false
    if (severityFilter !== 'All Severities' && s.severity !== severityFilter) return false
    if (tacticFilter !== 'All Tactics' && s.mitre_tactic !== tacticFilter) return false
    if (platformFilter !== 'All Platforms' && !s.platforms.includes(platformFilter)) return false
    return true
  })

  // Stats
  const criticalCount = scenarios.filter(s => s.severity === 'critical').length
  const highCount = scenarios.filter(s => s.severity === 'high').length
  const uniqueTactics = [...new Set(scenarios.map(s => s.mitre_tactic))].length

  return (
    <>
      <div className="space-y-5">

        {/* Page header */}
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-violet-400" />
              ITDR Simulation Scenarios
            </h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Identity Threat Detection &amp; Response — {scenarios.length} attack scenarios across {uniqueTactics} MITRE tactics
            </p>
          </div>
          <div className="flex items-center gap-2">
            <AskAboutThis
              goal="identity_threat_detection"
              message="Show me the ITDR scenarios. Which identity threats am I most exposed to? Help me prioritize which simulations to run first."
              label="Ask AI"
              size="md"
            />
            <button
              onClick={() => void load()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
          </div>
        </div>

        {/* Stats row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Total Scenarios', value: scenarios.length, color: 'text-slate-200', bg: 'bg-slate-800 border-slate-700' },
            { label: 'Critical Severity', value: criticalCount, color: 'text-red-400', bg: 'bg-red-500/5 border-red-500/20' },
            { label: 'High Severity', value: highCount, color: 'text-orange-400', bg: 'bg-orange-500/5 border-orange-500/20' },
            { label: 'MITRE Tactics', value: uniqueTactics, color: 'text-violet-400', bg: 'bg-violet-500/5 border-violet-500/20' },
          ].map(({ label, value, color, bg }) => (
            <div key={label} className={cn('rounded-xl border p-4', bg)}>
              <div className={cn('text-2xl font-bold', color)}>{value}</div>
              <div className="text-xs text-slate-500 mt-0.5">{label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search scenarios or technique IDs…"
              className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
            />
          </div>

          {/* Severity filter */}
          <div className="relative">
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="appearance-none rounded-lg border border-slate-700 bg-slate-800 pl-3 pr-7 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500 capitalize"
            >
              {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          </div>

          {/* Tactic filter */}
          <div className="relative">
            <select
              value={tacticFilter}
              onChange={e => setTacticFilter(e.target.value)}
              className="appearance-none rounded-lg border border-slate-700 bg-slate-800 pl-3 pr-7 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500"
            >
              {TACTIC_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          </div>

          {/* Platform filter */}
          <div className="relative">
            <select
              value={platformFilter}
              onChange={e => setPlatformFilter(e.target.value)}
              className="appearance-none rounded-lg border border-slate-700 bg-slate-800 pl-3 pr-7 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500 capitalize"
            >
              {PLATFORM_OPTIONS.map(p => <option key={p} value={p}>{p.replace('_', ' ')}</option>)}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          </div>

          {(search || severityFilter !== 'All Severities' || tacticFilter !== 'All Tactics' || platformFilter !== 'All Platforms') && (
            <button
              onClick={() => { setSearch(''); setSeverityFilter('All Severities'); setTacticFilter('All Tactics'); setPlatformFilter('All Platforms') }}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />{error}
          </div>
        )}

        {/* Scenario grid */}
        {loading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-sm text-slate-500">
            <Loader2 className="h-5 w-5 animate-spin" /> Loading scenarios…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-2 text-slate-500">
            <Fingerprint className="h-10 w-10 text-slate-700" />
            <p className="text-sm">No scenarios match your filters.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {filtered.map(s => (
              <button
                key={s.id}
                onClick={() => void openDetail(s)}
                className="group relative rounded-xl border border-slate-800 bg-slate-900 p-4 text-left transition-all hover:border-violet-500/40 hover:bg-slate-800/60 hover:shadow-lg"
              >
                {/* Severity indicator strip */}
                <div className={cn(
                  'absolute left-0 top-4 bottom-4 w-0.5 rounded-full',
                  s.severity === 'critical' ? 'bg-red-500' :
                  s.severity === 'high' ? 'bg-orange-500' :
                  s.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                )} />

                <div className="pl-3">
                  {/* Top row */}
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <TacticIcon tactic={s.mitre_tactic} />
                      <span className="truncate text-sm font-semibold text-slate-200 group-hover:text-white">
                        {s.name}
                      </span>
                    </div>
                    <SeverityBadge severity={s.severity} />
                  </div>

                  {/* Technique + tactic */}
                  <div className="flex items-center gap-2 mb-3">
                    <span className="rounded-md bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 font-mono text-[11px] text-violet-400">
                      {s.technique_id}
                    </span>
                    <span className="text-[11px] text-slate-500 truncate">{s.mitre_tactic}</span>
                  </div>

                  {/* Platforms */}
                  <div className="flex items-center gap-1 flex-wrap mb-3">
                    {s.platforms.map(p => {
                      const Icon = PLATFORM_ICONS[p] ?? PLATFORM_ICONS.default
                      return (
                        <span key={p} className="flex items-center gap-1 rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500 capitalize">
                          <Icon className="h-2.5 w-2.5" />
                          {p.replace('_', ' ')}
                        </span>
                      )
                    })}
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-slate-600">{s.step_count} simulation steps</span>
                    <span className="flex items-center gap-1 text-[11px] text-violet-500 opacity-0 group-hover:opacity-100 transition-opacity">
                      View details <Eye className="h-3 w-3" />
                    </span>
                  </div>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Detail drawer */}
      <Drawer
        open={!!selected}
        onClose={() => { setSelected(null); setDetail(null) }}
        title={selected?.name ?? 'Scenario Detail'}
      >
        {detailLoading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-sm text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading scenario…
          </div>
        ) : detail ? (
          <ScenarioDetailContent scenario={detail} />
        ) : null}
      </Drawer>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-slate-900 px-4 py-3 shadow-2xl">
          <Check className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="text-sm text-slate-200">{toast}</span>
        </div>
      )}
    </>
  )
}
