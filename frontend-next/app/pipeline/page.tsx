'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Plus,
  Play,
  Trash2,
  Pencil,
  RefreshCw,
  Clock,
  Workflow,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Bell,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Drawer } from '@/components/ui/Drawer'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

type PipelineStatus = 'pending' | 'running' | 'completed' | 'failed'
type ScheduleType = 'none' | 'hourly' | 'daily' | 'weekly'

interface AttackChain {
  id: string
  label: string
  description: string
}

interface Pipeline {
  id: string
  name: string
  description: string
  status: PipelineStatus
  schedule: ScheduleType
  schedule_time?: string
  chains: string[]
  siem_connection?: string
  hitl_enabled: boolean
  slack_channel?: string
  last_run?: string
  created_at: string
}

interface PipelineRun {
  id: string
  pipeline_id: string
  pipeline_name: string
  status: PipelineStatus
  started_at: string
  finished_at?: string
  events_generated: number
  des_delta: number
  error?: string
}

// ─── Constants (fallback values used when backend is unreachable) ─────────────

const FALLBACK_ATTACK_CHAINS: AttackChain[] = [
  { id: 'apt29', label: 'APT29 (Cozy Bear)', description: 'Russian nation-state TTPs' },
  { id: 'apt41', label: 'APT41', description: 'Chinese espionage + financial' },
  { id: 'cloud_takeover', label: 'Cloud Takeover', description: 'AWS/Azure privilege escalation' },
  { id: 'ransomware_sim', label: 'Ransomware Simulation', description: 'Full kill chain w/ exfil' },
  { id: 'lateral_movement', label: 'Lateral Movement', description: 'SMB/WMI spread techniques' },
  { id: 'cred_dumping', label: 'Credential Dumping', description: 'LSASS + SAM extraction' },
  { id: 'data_exfil', label: 'Data Exfiltration', description: 'DNS/HTTPS exfil channels' },
  { id: 'persistence', label: 'Persistence Suite', description: 'Registry + scheduled tasks' },
]

interface SIEMOption { value: string; label: string }

const FALLBACK_SIEM_OPTIONS: SIEMOption[] = [
  { value: 'Splunk Production', label: 'Splunk Production' },
  { value: 'Elastic SIEM', label: 'Elastic SIEM' },
  { value: 'Azure Sentinel', label: 'Azure Sentinel' },
  { value: 'IBM QRadar', label: 'IBM QRadar' },
  { value: 'Custom', label: 'Custom' },
]

// ─── Status badge helpers ─────────────────────────────────────────────────────

function StatusBadge({ status }: { status: PipelineStatus }) {
  const configs: Record<PipelineStatus, { variant: 'default' | 'info' | 'success' | 'destructive'; label: string; pulse?: boolean }> = {
    pending: { variant: 'default', label: 'Pending' },
    running: { variant: 'info', label: 'Running', pulse: true },
    completed: { variant: 'success', label: 'Completed' },
    failed: { variant: 'destructive', label: 'Failed' },
  }
  const { variant, label, pulse } = configs[status]
  return (
    <Badge variant={variant} className={cn('text-[10px]', pulse && 'animate-pulse')}>
      {label}
    </Badge>
  )
}

function StatusIcon({ status }: { status: PipelineStatus }) {
  if (status === 'completed') return <CheckCircle2 className="h-4 w-4 text-green" />
  if (status === 'failed') return <XCircle className="h-4 w-4 text-red" />
  if (status === 'running') return <Loader2 className="h-4 w-4 text-blue animate-spin" />
  return <Clock className="h-4 w-4 text-muted" />
}

// ─── Time helpers ─────────────────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function duration(start: string, end?: string): string {
  const ms = new Date(end ?? new Date().toISOString()).getTime() - new Date(start).getTime()
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── New Pipeline Form ────────────────────────────────────────────────────────

interface PipelineFormState {
  name: string
  description: string
  schedule: ScheduleType
  schedule_time: string
  chains: string[]
  siem_connection: string
  hitl_enabled: boolean
  slack_channel: string
}

const DEFAULT_FORM: PipelineFormState = {
  name: '',
  description: '',
  schedule: 'none',
  schedule_time: '09:00',
  chains: [],
  siem_connection: '',
  hitl_enabled: false,
  slack_channel: '',
}

function NewPipelineDrawer({
  open,
  onClose,
  onCreated,
  attackChains,
  siemOptions,
  chainsLoading,
}: {
  open: boolean
  onClose: () => void
  onCreated: () => void
  attackChains: AttackChain[]
  siemOptions: SIEMOption[]
  chainsLoading: boolean
}) {
  const [form, setForm] = useState<PipelineFormState>(DEFAULT_FORM)
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function toggleChain(id: string) {
    setForm((f) => ({
      ...f,
      chains: f.chains.includes(id) ? f.chains.filter((c) => c !== id) : [...f.chains, id],
    }))
  }

  async function handleSubmit() {
    if (!form.name.trim()) {
      setError('Pipeline name is required.')
      return
    }
    if (form.chains.length === 0) {
      setError('Select at least one attack chain.')
      return
    }
    setError(null)
    setIsSaving(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/pipeline`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      if (!res.ok) {
        const data = (await res.json()) as { detail?: string }
        throw new Error(data.detail ?? 'Failed to create pipeline')
      }
      setForm(DEFAULT_FORM)
      onCreated()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create pipeline')
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <Drawer open={open} onClose={onClose} title="New Pipeline">
      <div className="space-y-5 p-5">
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red/30 bg-red/10 px-3 py-2.5">
            <AlertCircle className="h-4 w-4 text-red shrink-0 mt-0.5" />
            <p className="text-sm text-red">{error}</p>
          </div>
        )}

        {/* Name */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide">
            Pipeline name *
          </label>
          <Input
            placeholder="e.g. Weekly Red Team Sim"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          />
        </div>

        {/* Description */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide">
            Description
          </label>
          <textarea
            className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:border-primary resize-none"
            rows={2}
            placeholder="What does this pipeline test?"
            value={form.description}
            onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
          />
        </div>

        {/* Schedule */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide">Schedule</label>
          <div className="grid grid-cols-2 gap-2">
            {(['none', 'hourly', 'daily', 'weekly'] as ScheduleType[]).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setForm((f) => ({ ...f, schedule: s }))}
                className={cn(
                  'rounded-lg border px-3 py-2 text-sm capitalize transition-colors',
                  form.schedule === s
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted hover:border-primary/50 hover:text-text'
                )}
              >
                {s === 'none' ? 'Manual only' : s}
              </button>
            ))}
          </div>
          {(form.schedule === 'daily' || form.schedule === 'weekly') && (
            <div className="mt-2 space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wide">Time</label>
              <Input
                type="time"
                value={form.schedule_time}
                onChange={(e) => setForm((f) => ({ ...f, schedule_time: e.target.value }))}
              />
            </div>
          )}
        </div>

        {/* Attack chains */}
        <div className="space-y-2">
          <label className="text-xs font-medium text-muted uppercase tracking-wide flex items-center gap-1.5">
            Attack chains *
            {chainsLoading && <Loader2 className="h-3 w-3 animate-spin text-muted" />}
          </label>
          <div className="space-y-1.5">
            {attackChains.map((chain) => {
              const selected = form.chains.includes(chain.id)
              return (
                <button
                  key={chain.id}
                  type="button"
                  onClick={() => toggleChain(chain.id)}
                  className={cn(
                    'flex w-full items-start gap-3 rounded-lg border p-3 text-left transition-colors',
                    selected
                      ? 'border-primary/50 bg-primary/10'
                      : 'border-border hover:border-border/80 hover:bg-bg'
                  )}
                >
                  <div
                    className={cn(
                      'mt-0.5 h-4 w-4 shrink-0 rounded border transition-colors',
                      selected ? 'border-primary bg-primary' : 'border-border'
                    )}
                  >
                    {selected && (
                      <svg viewBox="0 0 16 16" fill="none" className="h-full w-full p-0.5">
                        <path d="M3 8l3.5 3.5L13 4.5" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-text">{chain.label}</p>
                    <p className="text-xs text-muted">{chain.description}</p>
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* SIEM Connection */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide">
            SIEM connection
          </label>
          <select
            className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
            value={form.siem_connection}
            onChange={(e) => setForm((f) => ({ ...f, siem_connection: e.target.value }))}
          >
            <option value="">— None —</option>
            {siemOptions.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>
        </div>

        {/* HITL */}
        <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-4 py-3">
          <div>
            <p className="text-sm font-medium text-text">Require HITL approval</p>
            <p className="text-xs text-muted">Human-in-the-loop before each chain runs</p>
          </div>
          <button
            type="button"
            onClick={() => setForm((f) => ({ ...f, hitl_enabled: !f.hitl_enabled }))}
            className={cn(
              'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
              form.hitl_enabled ? 'bg-primary' : 'bg-border'
            )}
          >
            <span
              className={cn(
                'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform',
                form.hitl_enabled ? 'translate-x-6' : 'translate-x-1'
              )}
            />
          </button>
        </div>

        {/* Slack channel */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide flex items-center gap-1.5">
            <Bell className="h-3 w-3" />
            Slack notification channel
          </label>
          <Input
            placeholder="#security-alerts"
            value={form.slack_channel}
            onChange={(e) => setForm((f) => ({ ...f, slack_channel: e.target.value }))}
          />
        </div>

        {/* Submit */}
        <div className="flex gap-3 pt-2">
          <Button className="flex-1" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button className="flex-1" onClick={() => void handleSubmit()} disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Creating…
              </>
            ) : (
              'Create Pipeline'
            )}
          </Button>
        </div>
      </div>
    </Drawer>
  )
}

// ─── Pipeline card ────────────────────────────────────────────────────────────

function PipelineCard({
  pipeline,
  onRun,
  onDelete,
  running,
  attackChains,
}: {
  pipeline: Pipeline
  onRun: (id: string) => void
  onDelete: (id: string) => void
  running: boolean
  attackChains: AttackChain[]
}) {
  const [expanded, setExpanded] = useState(false)
  const scheduleLabel =
    pipeline.schedule === 'none'
      ? 'Manual'
      : pipeline.schedule === 'daily'
      ? `Daily at ${pipeline.schedule_time ?? '09:00'}`
      : pipeline.schedule === 'weekly'
      ? `Weekly at ${pipeline.schedule_time ?? '09:00'}`
      : 'Hourly'

  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-text">{pipeline.name}</span>
              <StatusBadge status={pipeline.status} />
              {pipeline.hitl_enabled && (
                <Badge variant="warning" className="text-[10px]">HITL</Badge>
              )}
            </div>
            {pipeline.description && (
              <p className="mt-1 text-xs text-muted">{pipeline.description}</p>
            )}

            <div className="mt-3 flex items-center gap-4 text-xs text-muted flex-wrap">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {scheduleLabel}
              </span>
              {pipeline.last_run && (
                <span>Last run: {timeAgo(pipeline.last_run)}</span>
              )}
              {pipeline.siem_connection && (
                <span>SIEM: {pipeline.siem_connection}</span>
              )}
            </div>

            {pipeline.chains.length > 0 && (
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {pipeline.chains.map((c) => {
                  const chain = attackChains.find((a) => a.id === c)
                  return (
                    <Badge key={c} variant="primary" className="text-[10px]">
                      {chain?.label ?? c}
                    </Badge>
                  )
                })}
              </div>
            )}
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            <Button
              size="sm"
             
              onClick={() => onRun(pipeline.id)}
              disabled={running || pipeline.status === 'running'}
            >
              {running ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              Run Now
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setExpanded((v) => !v)}
              className="h-8 w-8"
            >
              {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => onDelete(pipeline.id)}
              className="h-8 w-8 text-muted hover:text-red hover:bg-red/10"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {expanded && (
          <div className="mt-4 pt-4 border-t border-border space-y-2 text-xs text-muted">
            <div className="grid grid-cols-2 gap-y-1.5">
              <span>Pipeline ID</span>
              <span className="font-mono text-text">{pipeline.id}</span>
              <span>Created</span>
              <span className="text-text">{new Date(pipeline.created_at).toLocaleDateString()}</span>
              {pipeline.slack_channel && (
                <>
                  <span>Slack</span>
                  <span className="text-text">{pipeline.slack_channel}</span>
                </>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Pipeline page ────────────────────────────────────────────────────────────

export default function PipelinePage() {
  const [pipelines, setPipelines] = useState<Pipeline[]>([])
  const [runs, setRuns] = useState<PipelineRun[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [runningIds, setRunningIds] = useState<Set<string>>(new Set())
  const [attackChains, setAttackChains] = useState<AttackChain[]>(FALLBACK_ATTACK_CHAINS)
  const [siemOptions, setSiemOptions] = useState<SIEMOption[]>(FALLBACK_SIEM_OPTIONS)
  const [chainsLoading, setChainsLoading] = useState(true)

  // Fetch dynamic attack chains and SIEM connections on mount
  useEffect(() => {
    async function loadDynamicOptions() {
      setChainsLoading(true)
      await Promise.allSettled([
        (async () => {
          try {
            const res = await authFetch(`${API_BASE}/api/v2/log-sources/attack-chains`)
            if (res.ok) {
              const data = (await res.json()) as { chains?: Array<{ id: string; name?: string; description?: string }> }
              if (data.chains && data.chains.length > 0) {
                setAttackChains(
                  data.chains.map((c) => ({
                    id: c.id,
                    label: c.name ?? c.id,
                    description: c.description ?? '',
                  }))
                )
              }
            }
          } catch {
            // fall back to hardcoded list (already default state)
          }
        })(),
        (async () => {
          try {
            const res = await authFetch(`${API_BASE}/api/v2/siem/connections`)
            if (res.ok) {
              const data = (await res.json()) as Array<{ id: string; name: string }>
              if (data && data.length > 0) {
                setSiemOptions(data.map((c) => ({ value: c.name, label: c.name })))
              }
            }
          } catch {
            // fall back to hardcoded list (already default state)
          }
        })(),
      ])
      setChainsLoading(false)
    }
    void loadDynamicOptions()
  }, [])

  const fetchData = useCallback(async () => {
    setIsLoading(true)
    try {
      const [plRes, runsRes] = await Promise.all([
        authFetch(`${API_BASE}/api/v2/pipeline`),
        authFetch(`${API_BASE}/api/v2/pipeline/runs`).catch(() => null),
      ])
      if (plRes.ok) {
        const data = (await plRes.json()) as Pipeline[]
        setPipelines(data)
      } else {
        setPipelines(getMockPipelines())
      }
      if (runsRes?.ok) {
        const runsData = (await runsRes.json()) as PipelineRun[]
        setRuns(runsData)
      } else {
        setRuns(getMockRuns())
      }
    } catch {
      setPipelines(getMockPipelines())
      setRuns(getMockRuns())
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    void fetchData()
  }, [fetchData])

  async function handleRun(id: string) {
    setRunningIds((prev) => new Set(prev).add(id))
    try {
      const res = await authFetch(`${API_BASE}/api/v2/pipeline/${id}/run`, { method: 'POST' })
      if (res.ok) {
        // Optimistically update status
        setPipelines((prev) =>
          prev.map((p) => (p.id === id ? { ...p, status: 'running', last_run: new Date().toISOString() } : p))
        )
        // Refresh after a short delay
        setTimeout(() => void fetchData(), 2000)
      }
    } catch {
      // ignore
    } finally {
      setRunningIds((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this pipeline? This cannot be undone.')) return
    try {
      await authFetch(`${API_BASE}/api/v2/pipeline/${id}`, { method: 'DELETE' })
    } catch {
      // ignore — optimistically remove anyway
    }
    setPipelines((prev) => prev.filter((p) => p.id !== id))
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="animate-pulse h-7 w-48 rounded-lg bg-border/60" />
          <div className="animate-pulse h-9 w-36 rounded-lg bg-border/60" />
        </div>
        {[...Array(3)].map((_, i) => (
          <Skeleton key={i} className="h-36" />
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Purple Team Pipeline</h1>
          <p className="text-xs text-muted mt-0.5">Continuous automated attack simulations</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={() => void fetchData()}>
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" onClick={() => setDrawerOpen(true)}>
            <Plus className="h-4 w-4" />
            New Pipeline
          </Button>
        </div>
      </div>

      {/* Pipeline cards */}
      {pipelines.length === 0 ? (
        <Card>
          <CardContent className="py-16 flex flex-col items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10 border border-primary/20">
              <Workflow className="h-6 w-6 text-primary" />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium text-text">No pipelines configured</p>
              <p className="text-xs text-muted mt-1 max-w-xs">
                Create your first purple team pipeline to start automated attack simulations.
              </p>
            </div>
            <Button onClick={() => setDrawerOpen(true)}>
              <Plus className="h-4 w-4" />
              Create Pipeline
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {pipelines.map((p) => (
            <PipelineCard
              key={p.id}
              pipeline={p}
              onRun={handleRun}
              onDelete={handleDelete}
              running={runningIds.has(p.id)}
              attackChains={attackChains}
            />
          ))}
        </div>
      )}

      {/* Recent Runs */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Recent Runs</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {runs.length === 0 ? (
            <p className="px-5 py-6 text-center text-sm text-muted">No runs yet</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-5 py-2.5 text-left font-medium text-muted">Pipeline</th>
                    <th className="px-4 py-2.5 text-left font-medium text-muted">Status</th>
                    <th className="px-4 py-2.5 text-left font-medium text-muted">Duration</th>
                    <th className="px-4 py-2.5 text-left font-medium text-muted">Events</th>
                    <th className="px-4 py-2.5 text-left font-medium text-muted">DES delta</th>
                    <th className="px-5 py-2.5 text-left font-medium text-muted">Started</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <tr key={run.id} className="border-b border-border/50 hover:bg-bg/50 transition-colors">
                      <td className="px-5 py-3 font-medium text-text">{run.pipeline_name}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <StatusIcon status={run.status} />
                          <StatusBadge status={run.status} />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-muted">
                        {run.finished_at
                          ? duration(run.started_at, run.finished_at)
                          : run.status === 'running'
                          ? duration(run.started_at)
                          : '—'}
                      </td>
                      <td className="px-4 py-3 text-text">{run.events_generated.toLocaleString()}</td>
                      <td className="px-4 py-3">
                        <span className={cn('font-medium', run.des_delta > 0 ? 'text-green' : run.des_delta < 0 ? 'text-red' : 'text-muted')}>
                          {run.des_delta > 0 ? '+' : ''}{(run.des_delta * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="px-5 py-3 text-muted">{timeAgo(run.started_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* New Pipeline Drawer */}
      <NewPipelineDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onCreated={() => void fetchData()}
        attackChains={attackChains}
        siemOptions={siemOptions}
        chainsLoading={chainsLoading}
      />
    </div>
  )
}

// ─── Mock data ────────────────────────────────────────────────────────────────

function getMockPipelines(): Pipeline[] {
  return [
    {
      id: 'pl_001',
      name: 'Weekly APT29 Simulation',
      description: 'Full APT29 kill chain across production environment',
      status: 'completed',
      schedule: 'weekly',
      schedule_time: '02:00',
      chains: ['apt29', 'lateral_movement'],
      siem_connection: 'Splunk Production',
      hitl_enabled: false,
      slack_channel: '#security-alerts',
      last_run: new Date(Date.now() - 86_400_000).toISOString(),
      created_at: new Date(Date.now() - 7 * 86_400_000).toISOString(),
    },
    {
      id: 'pl_002',
      name: 'Cloud Security Assessment',
      description: 'Cloud privilege escalation and data exfiltration tests',
      status: 'running',
      schedule: 'daily',
      schedule_time: '06:00',
      chains: ['cloud_takeover', 'data_exfil'],
      siem_connection: 'Elastic SIEM',
      hitl_enabled: true,
      last_run: new Date(Date.now() - 300_000).toISOString(),
      created_at: new Date(Date.now() - 3 * 86_400_000).toISOString(),
    },
  ]
}

function getMockRuns(): PipelineRun[] {
  return [
    {
      id: 'run_001',
      pipeline_id: 'pl_001',
      pipeline_name: 'Weekly APT29 Simulation',
      status: 'completed',
      started_at: new Date(Date.now() - 86_400_000).toISOString(),
      finished_at: new Date(Date.now() - 86_400_000 + 3_720_000).toISOString(),
      events_generated: 2341,
      des_delta: 0.08,
    },
    {
      id: 'run_002',
      pipeline_id: 'pl_002',
      pipeline_name: 'Cloud Security Assessment',
      status: 'running',
      started_at: new Date(Date.now() - 300_000).toISOString(),
      events_generated: 412,
      des_delta: 0.02,
    },
    {
      id: 'run_003',
      pipeline_id: 'pl_001',
      pipeline_name: 'Weekly APT29 Simulation',
      status: 'failed',
      started_at: new Date(Date.now() - 14 * 86_400_000).toISOString(),
      finished_at: new Date(Date.now() - 14 * 86_400_000 + 600_000).toISOString(),
      events_generated: 0,
      des_delta: 0,
      error: 'SIEM connection timeout',
    },
  ]
}
