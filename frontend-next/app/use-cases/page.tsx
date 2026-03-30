'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Search,
  PlayCircle,
  Plus,
  ClipboardCheck,
  Check,
  X,
  Loader2,
  AlertCircle,
  RefreshCw,
  Trash2,
  ChevronDown,
  Clock,
  BarChart3,
  Tag,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Drawer } from '@/components/ui/Drawer'
import { apiGet, apiPost, apiDelete } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

type UseCaseStatus = 'passed' | 'failed' | 'partial' | 'never' | 'running'
type Severity = 'critical' | 'high' | 'medium' | 'low'
type Tactic =
  | 'Initial Access'
  | 'Execution'
  | 'Persistence'
  | 'Privilege Escalation'
  | 'Defense Evasion'
  | 'Credential Access'
  | 'Discovery'
  | 'Lateral Movement'
  | 'Collection'
  | 'Command and Control'
  | 'Exfiltration'
  | 'Impact'

interface UseCase {
  id: string
  name: string
  description?: string
  tactic: Tactic | string
  technique_ids: string[]
  severity: Severity
  expected_log_sources: string[]
  tags: string[]
  active: boolean
  status: UseCaseStatus
  last_run?: string
  created_at: string
  updated_at: string
}

interface UseCaseRun {
  id: string
  use_case_id: string
  status: UseCaseStatus
  events_generated: number
  rules_tested: number
  rules_fired: number
  started_at: string
  completed_at?: string
}

interface RuleResult {
  rule_id: string
  rule_name: string
  language: string
  fired: boolean
  matched_events: number
}

interface UseCaseDetail extends UseCase {
  last_run_detail?: {
    events_generated: number
    rules_tested: number
    rules_fired: number
    rule_results: RuleResult[]
  }
}

interface CoverageStats {
  total: number
  passing: number
  failing: number
  never_run: number
}

// ─── Seed data ────────────────────────────────────────────────────────────────

const SEED_USE_CASES: UseCase[] = [
  {
    id: 'uc1',
    name: 'Mimikatz LSASS Dump',
    description: 'Simulates credential dumping from LSASS process memory using Mimikatz-style access patterns.',
    tactic: 'Credential Access',
    technique_ids: ['T1003.001'],
    severity: 'critical',
    expected_log_sources: ['Sysmon', 'Windows Security'],
    tags: ['apt29', 'credential-access'],
    active: true,
    status: 'passed',
    last_run: new Date(Date.now() - 7200000).toISOString(),
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
    updated_at: new Date(Date.now() - 7200000).toISOString(),
  },
  {
    id: 'uc2',
    name: 'PowerShell Encoded Execution',
    description: 'Tests detection of PowerShell with encoded command-line arguments used for obfuscation.',
    tactic: 'Execution',
    technique_ids: ['T1059.001'],
    severity: 'high',
    expected_log_sources: ['PowerShell Event Log', 'Sysmon'],
    tags: ['apt29', 'execution'],
    active: true,
    status: 'failed',
    last_run: new Date(Date.now() - 86400000).toISOString(),
    created_at: new Date(Date.now() - 86400000 * 8).toISOString(),
    updated_at: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'uc3',
    name: 'Kerberoasting Attack',
    description: 'Requests service tickets for SPNs to enable offline cracking of service account passwords.',
    tactic: 'Credential Access',
    technique_ids: ['T1558.003'],
    severity: 'high',
    expected_log_sources: ['Windows Security 4769'],
    tags: ['apt29', 'kerberos'],
    active: true,
    status: 'never',
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: 'uc4',
    name: 'DNS Tunneling C2',
    description: 'Simulates command-and-control communication via DNS TXT record queries.',
    tactic: 'Command and Control',
    technique_ids: ['T1071.004'],
    severity: 'medium',
    expected_log_sources: ['DNS Logs', 'Network Flow'],
    tags: ['lazarus', 'c2'],
    active: true,
    status: 'partial',
    last_run: new Date(Date.now() - 3600000 * 3).toISOString(),
    created_at: new Date(Date.now() - 86400000 * 6).toISOString(),
    updated_at: new Date(Date.now() - 3600000 * 3).toISOString(),
  },
  {
    id: 'uc5',
    name: 'Ransomware File Encryption',
    description: 'Detects mass file rename or extension change patterns indicative of ransomware encryption.',
    tactic: 'Impact',
    technique_ids: ['T1486'],
    severity: 'critical',
    expected_log_sources: ['EDR File Events', 'Sysmon'],
    tags: ['lazarus', 'impact'],
    active: true,
    status: 'passed',
    last_run: new Date(Date.now() - 3600000).toISOString(),
    created_at: new Date(Date.now() - 86400000 * 14).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'uc6',
    name: 'RDP Lateral Movement',
    description: 'Tests detection of RDP-based lateral movement via Windows logon event analysis.',
    tactic: 'Lateral Movement',
    technique_ids: ['T1021.001'],
    severity: 'high',
    expected_log_sources: ['Windows Security 4624'],
    tags: ['lateral-movement'],
    active: false,
    status: 'failed',
    last_run: new Date(Date.now() - 86400000 * 2).toISOString(),
    created_at: new Date(Date.now() - 86400000 * 20).toISOString(),
    updated_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
]

const SEED_DETAIL: UseCaseDetail = {
  ...SEED_USE_CASES[0],
  last_run_detail: {
    events_generated: 12,
    rules_tested: 3,
    rules_fired: 3,
    rule_results: [
      { rule_id: 'r1', rule_name: 'Mimikatz LSASS Access', language: 'sigma', fired: true, matched_events: 8 },
      { rule_id: 'r2', rule_name: 'LSASS Memory Read', language: 'sigma', fired: true, matched_events: 4 },
      { rule_id: 'r3', rule_name: 'Suspicious Process Access', language: 'spl', fired: true, matched_events: 12 },
    ],
  },
}

const SEED_RUNS: UseCaseRun[] = [
  { id: 'run1', use_case_id: 'uc1', status: 'passed', events_generated: 12, rules_tested: 3, rules_fired: 3, started_at: new Date(Date.now() - 7200000).toISOString(), completed_at: new Date(Date.now() - 7195000).toISOString() },
  { id: 'run2', use_case_id: 'uc1', status: 'passed', events_generated: 10, rules_tested: 3, rules_fired: 3, started_at: new Date(Date.now() - 86400000).toISOString(), completed_at: new Date(Date.now() - 86395000).toISOString() },
  { id: 'run3', use_case_id: 'uc1', status: 'partial', events_generated: 10, rules_tested: 3, rules_fired: 2, started_at: new Date(Date.now() - 86400000 * 2).toISOString(), completed_at: new Date(Date.now() - 86400000 * 2 + 5000).toISOString() },
]

// ─── Utility ──────────────────────────────────────────────────────────────────

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 60000) return 'just now'
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`
  const days = Math.floor(ms / 86400000)
  return `${days}d ago`
}

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<UseCaseStatus, string> = {
  passed: 'bg-green-500/15 text-green-400 border-green-500/30',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
  partial: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  never: 'bg-slate-700/50 text-slate-500 border-slate-600/30',
  running: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

function StatusBadge({ status }: { status: UseCaseStatus }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium',
        STATUS_STYLES[status]
      )}
    >
      {status === 'passed' && <Check className="h-2.5 w-2.5" />}
      {status === 'failed' && <X className="h-2.5 w-2.5" />}
      {status === 'partial' && <span className="text-[9px] font-bold">~</span>}
      {status === 'running' && <Loader2 className="h-2.5 w-2.5 animate-spin" />}
      {status === 'never' && <span>—</span>}
      {status !== 'never' && (
        <span className="capitalize">{status}</span>
      )}
    </span>
  )
}

// ─── Severity badge ───────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize',
        SEVERITY_STYLES[severity]
      )}
    >
      {severity}
    </span>
  )
}

// ─── Language badge ───────────────────────────────────────────────────────────

const LANG_STYLES: Record<string, string> = {
  sigma: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  spl: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  kql: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  esql: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
}

function LangBadge({ lang }: { lang: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-mono font-medium uppercase',
        LANG_STYLES[lang] ?? 'bg-slate-700/50 text-slate-400 border-slate-600/30'
      )}
    >
      {lang}
    </span>
  )
}

// ─── Coverage bar ─────────────────────────────────────────────────────────────

function CoverageBar({ stats }: { stats: CoverageStats }) {
  const pct = stats.total > 0 ? Math.round((stats.passing / stats.total) * 100) : 0

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-violet-400" />
          <span className="text-sm font-medium text-slate-300">Detection Coverage</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-slate-500">
          <span>
            <span className="text-green-400 font-medium">{stats.passing}</span> passing
          </span>
          <span>
            <span className="text-red-400 font-medium">{stats.failing}</span> failing
          </span>
          <span>
            <span className="text-slate-400 font-medium">{stats.never_run}</span> never run
          </span>
          <span className="text-slate-400 font-semibold">{stats.total} total</span>
        </div>
      </div>
      <div className="relative h-2 rounded-full bg-slate-800 overflow-hidden">
        <div
          style={{ width: `${pct}%` }}
          className="h-2 bg-violet-500 rounded-full transition-all duration-500"
        />
      </div>
      <div className="mt-1.5 text-right">
        <span className="text-sm font-bold text-violet-400">{pct}%</span>
        <span className="text-xs text-slate-500 ml-1">passing</span>
      </div>
    </div>
  )
}

// ─── Use case detail drawer ───────────────────────────────────────────────────

interface UseCaseDetailProps {
  useCase: UseCase
  onClose: () => void
  onRun: (id: string) => void
  onDelete: (id: string) => void
}

function UseCaseDetailContent({ useCase, onClose, onRun, onDelete }: UseCaseDetailProps) {
  const [detail, setDetail] = useState<UseCaseDetail | null>(null)
  const [runs, setRuns] = useState<UseCaseRun[]>([])
  const [loadingDetail, setLoadingDetail] = useState(true)
  const [running, setRunning] = useState(false)

  useEffect(() => {
    setLoadingDetail(true)
    Promise.all([
      apiGet<UseCaseDetail>(`/api/v2/use-cases/${useCase.id}`),
      apiGet<UseCaseRun[]>(`/api/v2/use-cases/${useCase.id}/runs`),
    ])
      .then(([det, r]) => {
        setDetail(det)
        setRuns(r)
      })
      .catch(() => {
        setDetail({ ...SEED_DETAIL, ...useCase })
        setRuns(SEED_RUNS.map((r) => ({ ...r, use_case_id: useCase.id })))
      })
      .finally(() => setLoadingDetail(false))
  }, [useCase])

  async function handleRun() {
    setRunning(true)
    try {
      await onRun(useCase.id)
    } finally {
      setRunning(false)
    }
  }

  const d = detail ?? useCase
  const lastRun = detail?.last_run_detail
  const passRate =
    lastRun && lastRun.rules_tested > 0
      ? Math.round((lastRun.rules_fired / lastRun.rules_tested) * 100)
      : null

  return (
    <div className="p-5 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1.5 flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={d.severity as Severity} />
            <StatusBadge status={d.status} />
          </div>
          <h3 className="text-base font-semibold text-slate-100">{d.name}</h3>
          {d.description && (
            <p className="text-xs text-slate-400 leading-relaxed">{d.description}</p>
          )}
        </div>
        <button
          onClick={() => void handleRun()}
          disabled={running || d.status === 'running'}
          className="shrink-0 flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-50 transition-colors"
        >
          {running || d.status === 'running' ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <PlayCircle className="h-3.5 w-3.5" />
          )}
          Run Now
        </button>
      </div>

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 space-y-0.5">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Tactic</p>
          <p className="text-xs font-medium text-slate-300">{d.tactic}</p>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 space-y-0.5">
          <p className="text-[10px] uppercase tracking-wider text-slate-500">Last Run</p>
          <p className="text-xs font-medium text-slate-300">
            {d.last_run ? relativeDate(d.last_run) : 'Never'}
          </p>
        </div>
      </div>

      {/* MITRE techniques */}
      {d.technique_ids.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[11px] uppercase tracking-wider font-medium text-slate-500">
            MITRE Techniques
          </p>
          <div className="flex flex-wrap gap-1.5">
            {d.technique_ids.map((tid) => (
              <a
                key={tid}
                href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-1 text-[11px] font-mono text-violet-300 hover:bg-violet-500/20 transition-colors"
              >
                {tid}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Expected log sources */}
      {d.expected_log_sources.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[11px] uppercase tracking-wider font-medium text-slate-500">
            Expected Log Sources
          </p>
          <div className="flex flex-wrap gap-1.5">
            {d.expected_log_sources.map((src) => (
              <span
                key={src}
                className="rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300"
              >
                {src}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Tags */}
      {d.tags.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          <Tag className="h-3 w-3 text-slate-500 shrink-0" />
          {d.tags.map((tag) => (
            <span
              key={tag}
              className="rounded-full border border-slate-700 px-2 py-0.5 text-[10px] text-slate-500"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Last run results */}
      {loadingDetail ? (
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Loader2 className="h-3 w-3 animate-spin" />
          Loading run details…
        </div>
      ) : lastRun ? (
        <div className="space-y-3">
          <p className="text-[11px] uppercase tracking-wider font-medium text-slate-500">
            Last Run Results
          </p>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: 'Events', value: lastRun.events_generated },
              { label: 'Rules Tested', value: lastRun.rules_tested },
              { label: 'Rules Fired', value: lastRun.rules_fired },
            ].map(({ label, value }) => (
              <div
                key={label}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-center"
              >
                <p className="text-lg font-bold text-slate-100">{value}</p>
                <p className="text-[10px] text-slate-500">{label}</p>
              </div>
            ))}
          </div>

          {/* Pass rate bar */}
          {passRate !== null && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Rule coverage</span>
                <span
                  className={cn(
                    'font-semibold',
                    passRate === 100
                      ? 'text-green-400'
                      : passRate >= 50
                      ? 'text-amber-400'
                      : 'text-red-400'
                  )}
                >
                  {passRate}%
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  style={{ width: `${passRate}%` }}
                  className={cn(
                    'h-1.5 rounded-full transition-all duration-500',
                    passRate === 100
                      ? 'bg-green-500'
                      : passRate >= 50
                      ? 'bg-amber-500'
                      : 'bg-red-500'
                  )}
                />
              </div>
            </div>
          )}

          {/* Per-rule breakdown */}
          <div className="space-y-1.5">
            <p className="text-[11px] uppercase tracking-wider font-medium text-slate-500">
              Rule Breakdown
            </p>
            <div className="space-y-1">
              {lastRun.rule_results.map((r) => (
                <div
                  key={r.rule_id}
                  className={cn(
                    'flex items-center gap-2.5 rounded-lg border px-3 py-2',
                    r.fired
                      ? 'border-green-500/20 bg-green-500/5'
                      : 'border-red-500/20 bg-red-500/5'
                  )}
                >
                  {r.fired ? (
                    <Check className="h-3 w-3 text-green-400 shrink-0" />
                  ) : (
                    <X className="h-3 w-3 text-red-400 shrink-0" />
                  )}
                  <span className="flex-1 text-xs text-slate-300 truncate">{r.rule_name}</span>
                  <LangBadge lang={r.language} />
                  {r.fired && (
                    <span className="text-[10px] text-slate-500">{r.matched_events} events</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : null}

      {/* Run history */}
      {runs.length > 0 && (
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider font-medium text-slate-500">
            Run History
          </p>
          <div className="rounded-xl border border-slate-800 overflow-hidden">
            <div className="grid grid-cols-[1fr_6rem_5rem_5rem] gap-2 border-b border-slate-800 px-3 py-2 text-[10px] font-medium uppercase tracking-wider text-slate-600">
              <span>Started</span>
              <span>Status</span>
              <span>Rules</span>
              <span>Events</span>
            </div>
            <div className="divide-y divide-slate-800">
              {runs.slice(0, 10).map((run) => (
                <div
                  key={run.id}
                  className="grid grid-cols-[1fr_6rem_5rem_5rem] gap-2 px-3 py-2 text-xs items-center"
                >
                  <span className="text-slate-400 flex items-center gap-1">
                    <Clock className="h-3 w-3 text-slate-600" />
                    {relativeDate(run.started_at)}
                  </span>
                  <StatusBadge status={run.status} />
                  <span className="text-slate-400">
                    {run.rules_fired}/{run.rules_tested}
                  </span>
                  <span className="text-slate-500">{run.events_generated}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Delete action */}
      <div className="border-t border-slate-800 pt-3">
        <button
          onClick={() => {
            onDelete(useCase.id)
            onClose()
          }}
          className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300 hover:bg-red-500/20 transition-colors"
        >
          <Trash2 className="h-3 w-3" />
          Delete Use Case
        </button>
      </div>
    </div>
  )
}

// ─── New use case drawer ──────────────────────────────────────────────────────

const TACTICS: Tactic[] = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

interface NewUseCaseFormProps {
  onClose: () => void
  onCreated: () => void
}

function NewUseCaseForm({ onClose, onCreated }: NewUseCaseFormProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [tactic, setTactic] = useState<Tactic | ''>('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [techniqueInput, setTechniqueInput] = useState('')
  const [techniqueIds, setTechniqueIds] = useState<string[]>([])
  const [logSourceInput, setLogSourceInput] = useState('')
  const [logSources, setLogSources] = useState<string[]>([])
  const [tagInput, setTagInput] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [active, setActive] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function handleTechniqueKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const val = techniqueInput.trim().toUpperCase()
      if (val && !techniqueIds.includes(val)) {
        setTechniqueIds((prev) => [...prev, val])
      }
      setTechniqueInput('')
    }
  }

  function handleLogSourceKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const val = logSourceInput.trim()
      if (val && !logSources.includes(val)) {
        setLogSources((prev) => [...prev, val])
      }
      setLogSourceInput('')
    }
  }

  function handleTagKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const val = tagInput.trim().toLowerCase()
      if (val && !tags.includes(val)) {
        setTags((prev) => [...prev, val])
      }
      setTagInput('')
    }
  }

  async function handleSubmit() {
    if (!name.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost('/api/v2/use-cases', {
        name: name.trim(),
        description: description.trim() || undefined,
        tactic: tactic || undefined,
        severity: severity || 'medium',
        technique_ids: techniqueIds,
        expected_log_sources: logSources,
        tags,
        active,
      })
      onCreated()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create use case')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-5 space-y-5">
      {/* Name */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">
          Name <span className="text-red-400">*</span>
        </label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Mimikatz LSASS Dump"
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
        />
      </div>

      {/* Description */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">Description</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What does this use case simulate?"
          rows={3}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500 resize-none"
        />
      </div>

      {/* Tactic + Severity row */}
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">Tactic</label>
          <select
            value={tactic}
            onChange={(e) => setTactic(e.target.value as Tactic | '')}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500"
          >
            <option value="">Select tactic…</option>
            {TACTICS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-400">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | '')}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500"
          >
            <option value="">Select severity…</option>
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Technique IDs */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">
          MITRE Technique IDs
          <span className="ml-1 text-slate-600 font-normal">(type and press Enter)</span>
        </label>
        <input
          value={techniqueInput}
          onChange={(e) => setTechniqueInput(e.target.value)}
          onKeyDown={handleTechniqueKey}
          placeholder="e.g. T1003.001"
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
        />
        {techniqueIds.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {techniqueIds.map((tid) => (
              <span
                key={tid}
                className="inline-flex items-center gap-1 rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[11px] font-mono text-violet-300"
              >
                {tid}
                <button
                  onClick={() => setTechniqueIds((prev) => prev.filter((t) => t !== tid))}
                  className="text-violet-500 hover:text-violet-200"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Log sources */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">
          Expected Log Sources
          <span className="ml-1 text-slate-600 font-normal">(press Enter to add)</span>
        </label>
        <input
          value={logSourceInput}
          onChange={(e) => setLogSourceInput(e.target.value)}
          onKeyDown={handleLogSourceKey}
          placeholder="e.g. Sysmon, Windows Security"
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
        />
        {logSources.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {logSources.map((src) => (
              <span
                key={src}
                className="inline-flex items-center gap-1 rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300"
              >
                {src}
                <button
                  onClick={() => setLogSources((prev) => prev.filter((s) => s !== src))}
                  className="text-slate-500 hover:text-slate-200"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Tags */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-slate-400">
          Tags
          <span className="ml-1 text-slate-600 font-normal">(press Enter to add)</span>
        </label>
        <input
          value={tagInput}
          onChange={(e) => setTagInput(e.target.value)}
          onKeyDown={handleTagKey}
          placeholder="e.g. apt29, ransomware"
          className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
        />
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center gap-1 rounded-full border border-slate-700 px-2.5 py-0.5 text-[10px] text-slate-400"
              >
                {tag}
                <button
                  onClick={() => setTags((prev) => prev.filter((t) => t !== tag))}
                  className="text-slate-600 hover:text-slate-300"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Active toggle */}
      <div className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-900 px-4 py-3">
        <div>
          <p className="text-sm font-medium text-slate-300">Active</p>
          <p className="text-xs text-slate-500">Continuously tested in automated runs</p>
        </div>
        <button
          role="switch"
          aria-checked={active}
          onClick={() => setActive((v) => !v)}
          className={cn(
            'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none',
            active ? 'bg-violet-600' : 'bg-slate-700'
          )}
        >
          <span
            className={cn(
              'inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform',
              active ? 'translate-x-[18px]' : 'translate-x-1'
            )}
          />
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
          <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
          {error}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2 pt-1">
        <button
          onClick={onClose}
          className="flex-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => void handleSubmit()}
          disabled={!name.trim() || submitting}
          className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-violet-600 px-3 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
          {submitting ? 'Creating…' : 'Create Use Case'}
        </button>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

const ALL_TACTICS = ['All', ...TACTICS]

export default function UseCasesPage() {
  const [useCases, setUseCases] = useState<UseCase[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<UseCaseStatus | 'all'>('all')
  const [tacticFilter, setTacticFilter] = useState('All')

  // Selection
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Drawers
  const [detailUseCase, setDetailUseCase] = useState<UseCase | null>(null)
  const [newDrawerOpen, setNewDrawerOpen] = useState(false)

  // Bulk run state
  const [runningAll, setRunningAll] = useState(false)

  // Toast
  const [toast, setToast] = useState<string | null>(null)

  // Coverage stats (derived)
  const [coverage, setCoverage] = useState<CoverageStats>({
    total: 0,
    passing: 0,
    failing: 0,
    never_run: 0,
  })

  // ── Load ──────────────────────────────────────────────────────────────────

  const loadUseCases = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const raw = await apiGet<UseCase[] | { use_cases: UseCase[] }>('/api/v2/use-cases?active_only=false')
      const list = Array.isArray(raw) ? raw : (raw.use_cases ?? [])
      setUseCases(list)
    } catch {
      setUseCases(SEED_USE_CASES)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadUseCases()
  }, [loadUseCases])

  // Derive coverage stats from use cases
  useEffect(() => {
    const total = useCases.length
    const passing = useCases.filter((uc) => uc.status === 'passed').length
    const failing = useCases.filter((uc) => uc.status === 'failed' || uc.status === 'partial').length
    const never_run = useCases.filter((uc) => uc.status === 'never').length
    setCoverage({ total, passing, failing, never_run })
  }, [useCases])

  // Toast auto-dismiss
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 4000)
    return () => clearTimeout(t)
  }, [toast])

  // ── Filters ───────────────────────────────────────────────────────────────

  const filtered = useCases.filter((uc) => {
    if (search && !uc.name.toLowerCase().includes(search.toLowerCase())) return false
    if (statusFilter !== 'all' && uc.status !== statusFilter) return false
    if (tacticFilter !== 'All' && uc.tactic !== tacticFilter) return false
    return true
  })

  // ── Selection helpers ────────────────────────────────────────────────────

  const allSelected = filtered.length > 0 && filtered.every((uc) => selected.has(uc.id))

  function toggleSelectAll() {
    if (allSelected) {
      setSelected((prev) => {
        const next = new Set(prev)
        filtered.forEach((uc) => next.delete(uc.id))
        return next
      })
    } else {
      setSelected((prev) => {
        const next = new Set(prev)
        filtered.forEach((uc) => next.add(uc.id))
        return next
      })
    }
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  async function handleRunAll() {
    setRunningAll(true)
    try {
      await apiPost('/api/v2/use-cases/run-all', {})
    } catch {
      // Proceed
    }
    setRunningAll(false)
    setToast(`Validation started for ${useCases.filter((uc) => uc.active).length} active use cases`)
    // Optimistically mark active ones as running
    setUseCases((prev) =>
      prev.map((uc) => (uc.active ? { ...uc, status: 'running' } : uc))
    )
  }

  async function handleRun(id: string) {
    try {
      await apiPost(`/api/v2/use-cases/${id}/run`, {})
    } catch {
      // Proceed
    }
    setUseCases((prev) =>
      prev.map((uc) => (uc.id === id ? { ...uc, status: 'running' } : uc))
    )
    setToast('Use case run started')
  }

  async function handleDelete(id: string) {
    try {
      await apiDelete(`/api/v2/use-cases/${id}`)
    } catch {
      // Ignore
    }
    setUseCases((prev) => prev.filter((uc) => uc.id !== id))
    setSelected((prev) => {
      const next = new Set(prev)
      next.delete(id)
      return next
    })
  }

  async function bulkRun() {
    for (const id of selected) {
      await handleRun(id)
    }
    setSelected(new Set())
    setToast(`Started ${selected.size} use case runs`)
  }

  async function bulkDelete() {
    if (!window.confirm(`Delete ${selected.size} use cases?`)) return
    for (const id of selected) {
      await handleDelete(id)
    }
    setSelected(new Set())
  }

  function bulkEnable(enabled: boolean) {
    setUseCases((prev) =>
      prev.map((uc) => (selected.has(uc.id) ? { ...uc, active: enabled } : uc))
    )
    setSelected(new Set())
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      <div className="space-y-4">
        {/* Page header */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Use Cases</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              {useCases.length} detection use cases across {[...new Set(useCases.map((uc) => uc.tactic))].length} tactics
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadUseCases()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
            <button
              onClick={() => void handleRunAll()}
              disabled={runningAll}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              {runningAll ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlayCircle className="h-3.5 w-3.5" />
              )}
              Run All
            </button>
            <button
              onClick={() => setNewDrawerOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-xs font-medium text-white hover:bg-violet-500 transition-colors"
            >
              <Plus className="h-3.5 w-3.5" />
              New Use Case
            </button>
          </div>
        </div>

        {/* Coverage bar */}
        <CoverageBar stats={coverage} />

        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search use cases…"
              className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
            />
          </div>

          {/* Status filter pills */}
          <div className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 p-1">
            {(
              [
                { key: 'all', label: 'All' },
                { key: 'passed', label: 'Passing' },
                { key: 'failed', label: 'Failing' },
                { key: 'never', label: 'Never Run' },
              ] as const
            ).map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setStatusFilter(key)}
                className={cn(
                  'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                  statusFilter === key
                    ? 'bg-slate-700 text-slate-200'
                    : 'text-slate-500 hover:text-slate-300'
                )}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Tactic filter */}
          <div className="relative">
            <select
              value={tacticFilter}
              onChange={(e) => setTacticFilter(e.target.value)}
              className="appearance-none rounded-lg border border-slate-700 bg-slate-800 pl-3 pr-8 py-2 text-sm text-slate-300 focus:outline-none focus:border-violet-500"
            >
              {ALL_TACTICS.map((t) => (
                <option key={t} value={t}>
                  {t === 'All' ? 'All Tactics' : t}
                </option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          </div>
        </div>

        {/* Bulk actions bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-2 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2">
            <span className="text-xs text-violet-300 font-medium">{selected.size} selected</span>
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => void bulkRun()}
                className="flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors"
              >
                <PlayCircle className="h-3 w-3" />
                Run Selected
              </button>
              <button
                onClick={() => bulkEnable(true)}
                className="flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors"
              >
                <Check className="h-3 w-3" />
                Enable
              </button>
              <button
                onClick={() => bulkEnable(false)}
                className="flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors"
              >
                <X className="h-3 w-3" />
                Disable
              </button>
              <button
                onClick={() => void bulkDelete()}
                className="flex items-center gap-1.5 rounded-md bg-red-500/10 border border-red-500/30 px-2.5 py-1.5 text-xs text-red-300 hover:bg-red-500/20 transition-colors"
              >
                <Trash2 className="h-3 w-3" />
                Delete
              </button>
              <button
                onClick={() => setSelected(new Set())}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            {error}
          </div>
        )}

        {/* Table */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[2rem_2fr_8rem_7rem_7rem_7rem_3rem] gap-3 border-b border-slate-800 px-4 py-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={toggleSelectAll}
                className="rounded border-slate-600 bg-slate-800 text-violet-500 focus:ring-violet-500"
              />
            </label>
            <span>Name</span>
            <span>Tactic</span>
            <span>Technique</span>
            <span>Status</span>
            <span>Last Run</span>
            <span className="text-center">Run</span>
          </div>

          {/* Rows */}
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading use cases…
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2 text-sm text-slate-500">
              <ClipboardCheck className="h-8 w-8 text-slate-700" />
              No use cases found
              {useCases.length === 0 && (
                <button
                  onClick={() => setNewDrawerOpen(true)}
                  className="mt-2 flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-xs font-medium text-white hover:bg-violet-500 transition-colors"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Create first use case
                </button>
              )}
            </div>
          ) : (
            <div className="divide-y divide-slate-800">
              {filtered.map((uc) => (
                <div
                  key={uc.id}
                  onClick={() => setDetailUseCase(uc)}
                  className={cn(
                    'grid grid-cols-[2rem_2fr_8rem_7rem_7rem_7rem_3rem] gap-3 items-center px-4 py-3 text-sm cursor-pointer transition-colors hover:bg-slate-800/40',
                    selected.has(uc.id) && 'bg-violet-500/5'
                  )}
                >
                  {/* Checkbox */}
                  <label
                    className="flex items-center cursor-pointer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(uc.id)}
                      onChange={() => toggleSelect(uc.id)}
                      className="rounded border-slate-600 bg-slate-800 text-violet-500 focus:ring-violet-500"
                    />
                  </label>

                  {/* Name */}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm text-slate-200 font-medium">{uc.name}</span>
                      {!uc.active && (
                        <span className="shrink-0 rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-500">
                          inactive
                        </span>
                      )}
                    </div>
                    {uc.tags.length > 0 && (
                      <div className="flex gap-1 mt-0.5">
                        {uc.tags.slice(0, 2).map((tag) => (
                          <span key={tag} className="text-[10px] text-slate-600">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Tactic */}
                  <span className="truncate text-xs text-slate-400">{uc.tactic}</span>

                  {/* Techniques */}
                  <div className="flex flex-wrap gap-1">
                    {uc.technique_ids.slice(0, 2).map((tid) => (
                      <span
                        key={tid}
                        className="rounded-md bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 text-[10px] font-mono text-violet-400"
                      >
                        {tid}
                      </span>
                    ))}
                    {uc.technique_ids.length > 2 && (
                      <span className="text-[10px] text-slate-600">
                        +{uc.technique_ids.length - 2}
                      </span>
                    )}
                  </div>

                  {/* Status */}
                  <StatusBadge status={uc.status} />

                  {/* Last run */}
                  <span className="text-xs text-slate-500">
                    {uc.last_run ? relativeDate(uc.last_run) : 'Never'}
                  </span>

                  {/* Run button */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      void handleRun(uc.id)
                    }}
                    disabled={uc.status === 'running'}
                    title="Run use case"
                    className="flex items-center justify-center h-7 w-7 rounded-lg border border-slate-700 text-slate-500 hover:text-violet-400 hover:border-violet-500/50 disabled:opacity-50 transition-colors"
                  >
                    {uc.status === 'running' ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <PlayCircle className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail drawer */}
      <Drawer
        open={!!detailUseCase}
        onClose={() => setDetailUseCase(null)}
        title={detailUseCase?.name ?? 'Use Case'}
      >
        {detailUseCase && (
          <UseCaseDetailContent
            useCase={detailUseCase}
            onClose={() => setDetailUseCase(null)}
            onRun={(id) => handleRun(id)}
            onDelete={(id) => {
              void handleDelete(id)
              setDetailUseCase(null)
            }}
          />
        )}
      </Drawer>

      {/* New use case drawer */}
      <Drawer
        open={newDrawerOpen}
        onClose={() => setNewDrawerOpen(false)}
        title="New Use Case"
      >
        <NewUseCaseForm
          onClose={() => setNewDrawerOpen(false)}
          onCreated={() => void loadUseCases()}
        />
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
