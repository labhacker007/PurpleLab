'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import {
  Plus,
  Activity,
  Play,
  ArrowRight,
  RefreshCw,
  Loader2,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Dialog, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

type SessionStatus = 'stopped' | 'running' | 'paused' | 'completed' | 'failed'

interface SimSession {
  id: string
  name: string
  status: SessionStatus
  events_sent: number
  errors: number
  config: Record<string, unknown>
  created_at: string
  updated_at: string
  last_event_at: string | null
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

function durationStr(start: string, end?: string | null): string {
  const ms = new Date(end ?? new Date().toISOString()).getTime() - new Date(start).getTime()
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

const STATUS_CONFIG: Record<string, { label: string; color: string; pulse?: boolean; icon: React.ReactNode }> = {
  running: {
    label: 'RUNNING',
    color: 'text-blue',
    pulse: true,
    icon: <Loader2 className="h-3 w-3 animate-spin" />,
  },
  stopped: {
    label: 'STOPPED',
    color: 'text-muted',
    icon: <Clock className="h-3 w-3" />,
  },
  completed: {
    label: 'COMPLETED',
    color: 'text-green',
    icon: <CheckCircle2 className="h-3 w-3" />,
  },
  failed: {
    label: 'FAILED',
    color: 'text-red',
    icon: <XCircle className="h-3 w-3" />,
  },
  paused: {
    label: 'PAUSED',
    color: 'text-amber',
    icon: <Clock className="h-3 w-3" />,
  },
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.stopped
  return (
    <span className={cn('flex items-center gap-1 text-xs font-mono font-medium', cfg.color, cfg.pulse && 'animate-pulse')}>
      {cfg.icon}
      {cfg.label}
    </span>
  )
}

// ─── New Session Dialog ────────────────────────────────────────────────────────

interface AttackChain {
  id: string
  label: string
  description: string
}

const FALLBACK_ATTACK_CHAINS: AttackChain[] = [
  { id: 'apt29', label: 'APT29 (Cozy Bear)', description: 'Russian nation-state TTPs' },
  { id: 'apt41', label: 'APT41', description: 'Chinese espionage + financial' },
  { id: 'cloud_takeover', label: 'Cloud Takeover', description: 'AWS/Azure privilege escalation' },
  { id: 'ransomware_sim', label: 'Ransomware Simulation', description: 'Full kill chain w/ exfil' },
  { id: 'lateral_movement', label: 'Lateral Movement', description: 'SMB/WMI spread techniques' },
  { id: 'cred_dumping', label: 'Credential Dumping', description: 'LSASS + SAM extraction' },
]

function NewSessionDialog({
  open,
  onClose,
  onCreated,
  attackChains,
  chainsLoading,
}: {
  open: boolean
  onClose: () => void
  onCreated: (id: string) => void
  attackChains: AttackChain[]
  chainsLoading: boolean
}) {
  const [name, setName] = useState('')
  const [chains, setChains] = useState<string[]>([])
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function toggleChain(id: string) {
    setChains((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]))
  }

  async function handleCreate() {
    if (!name.trim()) {
      setError('Session name is required.')
      return
    }
    setError(null)
    setIsSaving(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), config: { attack_chains: chains } }),
      })
      if (!res.ok) {
        const data = (await res.json()) as { detail?: string }
        throw new Error(data.detail ?? 'Failed to create session')
      }
      const session = (await res.json()) as SimSession
      setName('')
      setChains([])
      onCreated(session.id)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create session')
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <Dialog open={open} onClose={onClose}>
      <DialogHeader>
        <DialogTitle>New Simulation Session</DialogTitle>
      </DialogHeader>
      <div className="space-y-4 py-1">
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red/30 bg-red/10 px-3 py-2.5">
            <AlertCircle className="h-4 w-4 text-red shrink-0 mt-0.5" />
            <p className="text-sm text-red">{error}</p>
          </div>
        )}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wide">Session name *</label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. APT29 Simulation #4"
            autoFocus
          />
        </div>
        <div className="space-y-2">
          <label className="text-xs font-medium text-muted uppercase tracking-wide flex items-center gap-1.5">
            Attack chains
            {chainsLoading && <Loader2 className="h-3 w-3 animate-spin text-muted" />}
          </label>
          <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
            {attackChains.map((chain) => {
              const selected = chains.includes(chain.id)
              return (
                <button
                  key={chain.id}
                  type="button"
                  onClick={() => toggleChain(chain.id)}
                  className={cn(
                    'flex w-full items-start gap-3 rounded-lg border p-2.5 text-left transition-colors',
                    selected
                      ? 'border-primary/50 bg-primary/10'
                      : 'border-border hover:border-border/80 hover:bg-bg'
                  )}
                >
                  <div className={cn('mt-0.5 h-4 w-4 shrink-0 rounded border transition-colors', selected ? 'border-primary bg-primary' : 'border-border')}>
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
      </div>
      <DialogFooter>
        <Button variant="ghost" onClick={onClose} disabled={isSaving}>Cancel</Button>
        <Button onClick={() => void handleCreate()} disabled={isSaving || !name.trim()}>
          {isSaving ? <><Loader2 className="h-4 w-4 animate-spin" /> Creating...</> : 'Create Session'}
        </Button>
      </DialogFooter>
    </Dialog>
  )
}

// ─── Filter tabs ──────────────────────────────────────────────────────────────

const FILTERS: { label: string; value: string | null }[] = [
  { label: 'All', value: null },
  { label: 'Running', value: 'running' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Stopped', value: 'stopped' },
]

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SessionsPage() {
  const router = useRouter()
  const [sessions, setSessions] = useState<SimSession[]>([])
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [attackChains, setAttackChains] = useState<AttackChain[]>(FALLBACK_ATTACK_CHAINS)
  const [chainsLoading, setChainsLoading] = useState(true)

  // Fetch dynamic attack chains on mount
  useEffect(() => {
    async function loadChains() {
      setChainsLoading(true)
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
      } finally {
        setChainsLoading(false)
      }
    }
    void loadChains()
  }, [])

  const fetchSessions = useCallback(async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams({ limit: '50' })
      if (statusFilter) params.set('status', statusFilter)
      const res = await authFetch(`${API_BASE}/api/v2/sessions?${params}`)
      if (res.ok) {
        const data = (await res.json()) as { sessions: SimSession[]; total: number }
        setSessions(data.sessions)
        setTotal(data.total)
      }
    } catch {
      // ignore
    } finally {
      setIsLoading(false)
    }
  }, [statusFilter])

  useEffect(() => {
    void fetchSessions()
  }, [fetchSessions])

  function handleCreated(id: string) {
    router.push(`/sessions/${id}`)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Simulation Sessions</h1>
          <p className="text-xs text-muted mt-0.5">
            Live attack simulation runs — {total} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void fetchSessions()}>
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New Session
          </Button>
        </div>
      </div>

      {/* Status filters */}
      <div className="flex items-center gap-2">
        {FILTERS.map((f) => (
          <button
            key={f.label}
            onClick={() => setStatusFilter(f.value)}
            className={cn(
              'rounded-lg px-3 py-1.5 text-xs font-medium transition-colors',
              statusFilter === f.value
                ? 'bg-primary/10 text-primary border border-primary/30'
                : 'text-muted hover:text-text border border-border hover:border-border/80'
            )}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-2 p-4">
              {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-12" />)}
            </div>
          ) : sessions.length === 0 ? (
            <div className="py-16 flex flex-col items-center gap-4">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10 border border-primary/20">
                <Activity className="h-6 w-6 text-primary" />
              </div>
              <div className="text-center">
                <p className="text-sm font-medium text-text">No sessions yet</p>
                <p className="text-xs text-muted mt-1 max-w-xs">
                  Start your first simulation session to generate attack telemetry.
                </p>
              </div>
              <Button onClick={() => setShowCreate(true)}>
                <Plus className="h-4 w-4" />
                New Session
              </Button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-5 py-3 text-left font-medium text-muted">Name</th>
                    <th className="px-4 py-3 text-left font-medium text-muted">Status</th>
                    <th className="px-4 py-3 text-left font-medium text-muted">Events</th>
                    <th className="px-4 py-3 text-left font-medium text-muted">Started</th>
                    <th className="px-4 py-3 text-left font-medium text-muted">Duration</th>
                    <th className="px-5 py-3 text-right font-medium text-muted"></th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr
                      key={s.id}
                      onClick={() => router.push(`/sessions/${s.id}`)}
                      className="border-b border-border/50 hover:bg-bg/60 transition-colors cursor-pointer"
                    >
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          {s.status === 'running' && (
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue opacity-75" />
                              <span className="relative inline-flex h-2 w-2 rounded-full bg-blue" />
                            </span>
                          )}
                          <span className="font-medium text-text">{s.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="px-4 py-3 font-mono text-text">
                        {s.events_sent.toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-muted">{timeAgo(s.created_at)}</td>
                      <td className="px-4 py-3 text-muted font-mono">
                        {durationStr(s.created_at, s.status !== 'running' ? s.updated_at : null)}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            router.push(`/sessions/${s.id}`)
                          }}
                          className="inline-flex items-center gap-1 text-muted hover:text-primary transition-colors"
                        >
                          <Play className="h-3 w-3" />
                          <ArrowRight className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <NewSessionDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={handleCreated}
        attackChains={attackChains}
        chainsLoading={chainsLoading}
      />
    </div>
  )
}
