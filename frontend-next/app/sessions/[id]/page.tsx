'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useRouter } from 'next/navigation'
import {
  ArrowLeft,
  Square,
  Download,
  Pause,
  Play,
  Trash2,
  Loader2,
  Activity,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch, getAccessToken } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'
import Link from 'next/link'

// ─── Types ─────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type SessionStatus = 'stopped' | 'running' | 'paused' | 'completed' | 'failed'

interface LiveEvent {
  id: string
  source_type: string
  technique_id: string
  severity: Severity
  payload: Record<string, unknown>
  created_at: string
}

interface Session {
  id: string
  name: string
  status: SessionStatus
  events_sent: number
  errors: number
  created_at: string
  updated_at: string
  last_event_at: string | null
  config: Record<string, unknown>
}

interface StatsState {
  total: number
  by_severity: Record<string, number>
  by_source: Record<string, number>
  top_techniques: Array<{ technique_id: string; count: number }>
}

// ─── Severity config ──────────────────────────────────────────────────────────

const SEV_CONFIG: Record<string, { label: string; bg: string; text: string; dot: string }> = {
  critical: { label: 'CRIT', bg: 'bg-red/10 border-red/30', text: 'text-red', dot: 'bg-red' },
  high: { label: 'HIGH', bg: 'bg-orange/10 border-orange/30', text: 'text-orange', dot: 'bg-orange' },
  medium: { label: 'MED', bg: 'bg-amber/10 border-amber/30', text: 'text-amber', dot: 'bg-amber' },
  low: { label: 'LOW', bg: 'bg-slate-500/10 border-slate-500/30', text: 'text-slate-400', dot: 'bg-slate-500' },
  info: { label: 'INFO', bg: 'bg-blue/10 border-blue/30', text: 'text-blue', dot: 'bg-blue' },
}

function sevCfg(s: string) {
  return SEV_CONFIG[s] ?? SEV_CONFIG.info
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

function toHHMMSS(iso: string): string {
  const d = new Date(iso)
  return d.toTimeString().slice(0, 8)
}

function durationStr(start: string, end?: string | null): string {
  const ms = new Date(end ?? new Date().toISOString()).getTime() - new Date(start).getTime()
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return `${m}m ${s % 60}s`
}

const MAX_EVENTS = 500

// ─── Event row ────────────────────────────────────────────────────────────────

function EventRow({ event }: { event: LiveEvent }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = sevCfg(event.severity)

  // Get first meaningful line from payload
  const payloadSummary = (() => {
    const p = event.payload
    if (!p || Object.keys(p).length === 0) return ''
    const msg = p.message ?? p.msg ?? p.description ?? p.title ?? p.event_data ?? p.raw
    if (msg) return String(msg).slice(0, 120)
    const firstVal = Object.values(p)[0]
    return firstVal ? String(firstVal).slice(0, 120) : ''
  })()

  return (
    <div className="border-b border-border/40 last:border-0">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-bg/50 transition-colors group"
      >
        {/* Expand chevron */}
        <span className="shrink-0 mt-0.5 text-muted/50 group-hover:text-muted transition-colors">
          {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        </span>

        {/* Timestamp */}
        <span className="shrink-0 font-mono text-[11px] text-muted w-[62px] pt-px">
          {toHHMMSS(event.created_at)}
        </span>

        {/* Severity badge */}
        <span
          className={cn(
            'shrink-0 inline-flex items-center rounded border px-1.5 py-0 font-mono text-[10px] font-bold leading-5',
            cfg.bg,
            cfg.text
          )}
        >
          {cfg.label}
        </span>

        {/* Source badge */}
        {event.source_type && (
          <span className="shrink-0 inline-flex items-center rounded bg-card border border-border px-1.5 py-0 text-[10px] font-mono text-muted leading-5">
            {event.source_type}
          </span>
        )}

        {/* Technique badge */}
        {event.technique_id && (
          <span className="shrink-0 inline-flex items-center rounded bg-primary/10 border border-primary/20 px-1.5 py-0 text-[10px] font-mono text-primary leading-5">
            {event.technique_id}
          </span>
        )}

        {/* Payload summary */}
        <span className="flex-1 min-w-0 text-[11px] text-text/70 font-mono truncate">
          {payloadSummary}
        </span>
      </button>

      {/* Expanded payload */}
      {expanded && (
        <div className="mx-3 mb-2 rounded-lg border border-border bg-bg overflow-hidden">
          <pre className="text-[11px] font-mono text-text/80 p-3 overflow-x-auto max-h-80 leading-relaxed">
            {JSON.stringify(event.payload, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

// ─── Stats panel ──────────────────────────────────────────────────────────────

function StatsPanel({ stats, session }: { stats: StatsState; session: Session | null }) {
  return (
    <div className="w-[220px] shrink-0 space-y-4">
      {/* Total */}
      <Card>
        <CardContent className="p-4 text-center">
          <div className="text-3xl font-bold font-mono text-text tabular-nums">
            {stats.total.toLocaleString()}
          </div>
          <div className="text-xs text-muted mt-1">Total Events</div>
        </CardContent>
      </Card>

      {/* By severity */}
      <Card>
        <CardContent className="p-3 space-y-2">
          <div className="text-[10px] font-medium text-muted uppercase tracking-wide">By Severity</div>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
            const count = stats.by_severity[sev] ?? 0
            if (!count && sev === 'info') return null
            const cfg = sevCfg(sev)
            return (
              <div key={sev} className="flex items-center gap-2">
                <span className={cn('h-2 w-2 rounded-full shrink-0', cfg.dot)} />
                <span className="text-xs text-muted capitalize flex-1">{sev}</span>
                <span className={cn('text-xs font-mono font-medium tabular-nums', cfg.text)}>
                  {count.toLocaleString()}
                </span>
              </div>
            )
          })}
          {Object.keys(stats.by_severity).length === 0 && (
            <p className="text-xs text-muted/60">No events yet</p>
          )}
        </CardContent>
      </Card>

      {/* Top sources */}
      <Card>
        <CardContent className="p-3 space-y-2">
          <div className="text-[10px] font-medium text-muted uppercase tracking-wide">Top Sources</div>
          {Object.entries(stats.by_source)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([src, cnt]) => (
              <div key={src} className="flex items-center gap-2">
                <span className="text-xs text-muted font-mono flex-1 truncate">{src || '—'}</span>
                <span className="text-xs font-mono text-text tabular-nums">{cnt}</span>
              </div>
            ))}
          {Object.keys(stats.by_source).length === 0 && (
            <p className="text-xs text-muted/60">No events yet</p>
          )}
        </CardContent>
      </Card>

      {/* Top techniques */}
      <Card>
        <CardContent className="p-3 space-y-2">
          <div className="text-[10px] font-medium text-muted uppercase tracking-wide">Top Techniques</div>
          {stats.top_techniques.slice(0, 5).map(({ technique_id, count }) => (
            <div key={technique_id} className="flex items-center gap-2">
              <span className="text-xs text-primary font-mono flex-1 truncate">{technique_id || '—'}</span>
              <span className="text-xs font-mono text-text tabular-nums">{count}</span>
            </div>
          ))}
          {stats.top_techniques.length === 0 && (
            <p className="text-xs text-muted/60">No events yet</p>
          )}
        </CardContent>
      </Card>

      {/* Session info */}
      {session && (
        <Card>
          <CardContent className="p-3 space-y-1.5">
            <div className="text-[10px] font-medium text-muted uppercase tracking-wide">Session</div>
            <div className="text-xs text-muted">
              Started: <span className="text-text">{timeAgo(session.created_at)}</span>
            </div>
            {session.status === 'running' && (
              <div className="text-xs text-muted">
                Duration: <span className="text-text font-mono">{durationStr(session.created_at)}</span>
              </div>
            )}
            <div className="text-xs text-muted">
              Errors: <span className={cn('font-mono', session.errors > 0 ? 'text-red' : 'text-text')}>{session.errors}</span>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SessionDetailPage() {
  const params = useParams()
  const router = useRouter()
  const sessionId = params.id as string

  const [session, setSession] = useState<Session | null>(null)
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [stats, setStats] = useState<StatsState>({
    total: 0,
    by_severity: {},
    by_source: {},
    top_techniques: [],
  })
  const [isLoading, setIsLoading] = useState(true)
  const [paused, setPaused] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)
  const [sourceFilter, setSourceFilter] = useState<string>('')
  const [techniqueFilter, setTechniqueFilter] = useState<string>('')
  const [isStopping, setIsStopping] = useState(false)

  const feedRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)
  const pausedRef = useRef(false)
  const pendingRef = useRef<LiveEvent[]>([])

  // Keep pausedRef in sync
  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  // ── Update stats from incoming events ───────────────────────────────────────
  function applyEventToStats(ev: LiveEvent) {
    setStats((prev) => {
      const bySev = { ...prev.by_severity }
      bySev[ev.severity] = (bySev[ev.severity] ?? 0) + 1

      const bySrc = { ...prev.by_source }
      bySrc[ev.source_type] = (bySrc[ev.source_type] ?? 0) + 1

      const techMap: Record<string, number> = {}
      prev.top_techniques.forEach(({ technique_id, count }) => {
        techMap[technique_id] = count
      })
      if (ev.technique_id) {
        techMap[ev.technique_id] = (techMap[ev.technique_id] ?? 0) + 1
      }
      const top_techniques = Object.entries(techMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([technique_id, count]) => ({ technique_id, count }))

      return {
        total: prev.total + 1,
        by_severity: bySev,
        by_source: bySrc,
        top_techniques,
      }
    })
  }

  // ── Append events ────────────────────────────────────────────────────────────
  function appendEvents(incoming: LiveEvent[]) {
    if (incoming.length === 0) return
    setEvents((prev) => {
      const combined = [...incoming, ...prev]
      return combined.length > MAX_EVENTS ? combined.slice(0, MAX_EVENTS) : combined
    })
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0
    }
  }

  // ── Flush pending events when unpaused ──────────────────────────────────────
  useEffect(() => {
    if (!paused && pendingRef.current.length > 0) {
      appendEvents(pendingRef.current)
      pendingRef.current = []
    }
  }, [paused]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Manual scroll disables auto-scroll ──────────────────────────────────────
  function handleFeedScroll() {
    if (!feedRef.current) return
    if (feedRef.current.scrollTop > 50) {
      setAutoScroll(false)
    }
  }

  // ── Fetch initial session + events ──────────────────────────────────────────
  const loadInitial = useCallback(async () => {
    setIsLoading(true)
    try {
      const [sessRes, eventsRes] = await Promise.all([
        authFetch(`${API_BASE}/api/v2/sessions/${sessionId}`),
        authFetch(`${API_BASE}/api/v2/sessions/${sessionId}/events?limit=100&skip=0`),
      ])
      if (!sessRes.ok) {
        router.push('/sessions')
        return
      }
      const sessData = (await sessRes.json()) as Session & { recent_events?: LiveEvent[] }
      setSession(sessData)

      let initialEvents: LiveEvent[] = []
      if (eventsRes.ok) {
        const evData = (await eventsRes.json()) as { events: Array<{
          id: string
          product_type: string
          title: string
          severity: string
          payload?: Record<string, unknown>
          created_at: string
        }>}
        // Remap product_type -> source_type, title -> technique_id
        initialEvents = evData.events.map((e) => ({
          id: e.id,
          source_type: e.product_type ?? '',
          technique_id: e.title ?? '',
          severity: (e.severity ?? 'info') as Severity,
          payload: e.payload ?? {},
          created_at: e.created_at,
        }))
        setEvents(initialEvents)

        // Build initial stats
        const bySev: Record<string, number> = {}
        const bySrc: Record<string, number> = {}
        const techMap: Record<string, number> = {}
        for (const ev of initialEvents) {
          bySev[ev.severity] = (bySev[ev.severity] ?? 0) + 1
          bySrc[ev.source_type] = (bySrc[ev.source_type] ?? 0) + 1
          if (ev.technique_id) {
            techMap[ev.technique_id] = (techMap[ev.technique_id] ?? 0) + 1
          }
        }
        const top_techniques = Object.entries(techMap)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 20)
          .map(([technique_id, count]) => ({ technique_id, count }))

        setStats({
          total: initialEvents.length,
          by_severity: bySev,
          by_source: bySrc,
          top_techniques,
        })
      }

      return { session: sessData, lastEventId: initialEvents[0]?.id ?? null }
    } catch {
      return null
    } finally {
      setIsLoading(false)
    }
  }, [sessionId, router])

  // ── SSE stream ───────────────────────────────────────────────────────────────
  const startStream = useCallback((sinceId: string | null) => {
    abortRef.current?.abort()
    const ctrl = new AbortController()
    abortRef.current = ctrl

    const token = getAccessToken()
    const url = `${API_BASE}/api/v2/sessions/${sessionId}/events/stream${sinceId ? `?since_id=${sinceId}` : ''}`

    void (async () => {
      try {
        const res = await fetch(url, {
          signal: ctrl.signal,
          headers: {
            Accept: 'text/event-stream',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        })
        if (!res.ok || !res.body) return

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buf = ''

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            const raw = line.slice(6).trim()
            if (!raw) continue
            try {
              const parsed = JSON.parse(raw) as Record<string, unknown>
              if (parsed.type === 'done') {
                // Session ended — refresh session record
                authFetch(`${API_BASE}/api/v2/sessions/${sessionId}`)
                  .then((r) => r.ok ? r.json() as Promise<Session> : null)
                  .then((s) => { if (s) setSession(s) })
                  .catch(() => {})
                return
              }
              const ev: LiveEvent = {
                id: String(parsed.id ?? ''),
                source_type: String(parsed.source_type ?? ''),
                technique_id: String(parsed.technique_id ?? ''),
                severity: (parsed.severity ?? 'info') as Severity,
                payload: (parsed.payload ?? {}) as Record<string, unknown>,
                created_at: String(parsed.created_at ?? new Date().toISOString()),
              }
              applyEventToStats(ev)
              if (pausedRef.current) {
                pendingRef.current.push(ev)
              } else {
                appendEvents([ev])
              }
            } catch {
              // skip malformed
            }
          }
        }
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') return
        // Stream died — don't retry automatically
      }
    })()
  }, [sessionId]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Init ─────────────────────────────────────────────────────────────────────
  useEffect(() => {
    void loadInitial().then((result) => {
      if (!result) return
      if (result.session.status === 'running') {
        startStream(result.lastEventId)
      }
    })
    return () => {
      abortRef.current?.abort()
    }
  }, [loadInitial, startStream])

  // ── Stop session ─────────────────────────────────────────────────────────────
  async function handleStop() {
    if (!session || isStopping) return
    setIsStopping(true)
    try {
      await authFetch(`${API_BASE}/api/v2/sessions/${session.id}/stop`, { method: 'POST' })
      abortRef.current?.abort()
      setSession((s) => s ? { ...s, status: 'stopped' } : s)
    } catch {
      // ignore
    } finally {
      setIsStopping(false)
    }
  }

  // ── Export ────────────────────────────────────────────────────────────────────
  function handleExport(format: 'json' | 'csv') {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `session-${sessionId}-events.json`
      a.click()
      URL.revokeObjectURL(url)
    } else {
      const headers = ['id', 'source_type', 'technique_id', 'severity', 'created_at', 'payload']
      const rows = events.map((e) =>
        [e.id, e.source_type, e.technique_id, e.severity, e.created_at, JSON.stringify(e.payload)]
          .map((v) => `"${String(v).replace(/"/g, '""')}"`)
          .join(',')
      )
      const csv = [headers.join(','), ...rows].join('\n')
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `session-${sessionId}-events.csv`
      a.click()
      URL.revokeObjectURL(url)
    }
  }

  // ── Filtered events ───────────────────────────────────────────────────────────
  const filteredEvents = events.filter((e) => {
    if (severityFilter && e.severity !== severityFilter) return false
    if (sourceFilter && !e.source_type.toLowerCase().includes(sourceFilter.toLowerCase())) return false
    if (techniqueFilter && !e.technique_id.toLowerCase().includes(techniqueFilter.toLowerCase())) return false
    return true
  })

  // ── Status display ────────────────────────────────────────────────────────────
  const statusCfg: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    running: { label: 'RUNNING', color: 'text-blue', icon: <Loader2 className="h-3 w-3 animate-spin" /> },
    stopped: { label: 'STOPPED', color: 'text-muted', icon: <Clock className="h-3 w-3" /> },
    completed: { label: 'COMPLETED', color: 'text-green', icon: <CheckCircle2 className="h-3 w-3" /> },
    failed: { label: 'FAILED', color: 'text-red', icon: <XCircle className="h-3 w-3" /> },
    paused: { label: 'PAUSED', color: 'text-amber', icon: <AlertTriangle className="h-3 w-3" /> },
  }
  const sCfg = statusCfg[session?.status ?? 'stopped'] ?? statusCfg.stopped

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="animate-pulse h-14 w-full rounded-lg bg-border/60" />
        <div className="flex gap-4">
          <div className="animate-pulse w-[220px] h-80 rounded-lg bg-border/60" />
          <div className="flex-1 animate-pulse h-80 rounded-lg bg-border/60" />
        </div>
      </div>
    )
  }

  if (!session) return null

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <Link
            href="/sessions"
            className="mt-1 flex items-center gap-1 text-xs text-muted hover:text-text transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Sessions
          </Link>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-bold text-text">{session.name}</h1>
              <span className={cn('flex items-center gap-1 text-xs font-mono font-semibold', sCfg.color)}>
                {sCfg.icon}
                {sCfg.label}
              </span>
            </div>
            <p className="text-xs text-muted mt-0.5">
              Started {timeAgo(session.created_at)}
              {session.status === 'running' && (
                <> &middot; {durationStr(session.created_at)} elapsed</>
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {session.status === 'running' && (
            <Button
              size="sm"
             
              onClick={() => void handleStop()}
              disabled={isStopping}
              className="text-red border-red/30 hover:bg-red/10 hover:text-red"
            >
              {isStopping ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Square className="h-3.5 w-3.5" />}
              Stop
            </Button>
          )}
          <div className="relative group">
            <Button size="sm">
              <Download className="h-3.5 w-3.5" />
              Export
            </Button>
            <div className="absolute right-0 top-full mt-1 hidden group-hover:flex flex-col z-10 bg-card border border-border rounded-lg shadow-lg overflow-hidden">
              <button
                onClick={() => handleExport('json')}
                className="px-4 py-2 text-xs text-left hover:bg-bg text-text whitespace-nowrap"
              >
                Export as JSON
              </button>
              <button
                onClick={() => handleExport('csv')}
                className="px-4 py-2 text-xs text-left hover:bg-bg text-text whitespace-nowrap"
              >
                Export as CSV
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main layout */}
      <div className="flex gap-4 flex-1 min-h-0">
        {/* Stats panel */}
        <StatsPanel stats={stats} session={session} />

        {/* Event feed */}
        <div className="flex-1 flex flex-col min-w-0">
          <Card className="flex-1 flex flex-col min-h-0">
            {/* Feed toolbar */}
            <div className="flex flex-wrap items-center gap-2 px-3 py-2.5 border-b border-border shrink-0">
              {/* Severity filters */}
              <div className="flex items-center gap-1">
                {[null, 'critical', 'high', 'medium', 'low'].map((sev) => (
                  <button
                    key={sev ?? 'all'}
                    onClick={() => setSeverityFilter(sev)}
                    className={cn(
                      'rounded px-2 py-0.5 text-[10px] font-medium transition-colors',
                      severityFilter === sev
                        ? sev
                          ? cn('border', sevCfg(sev).bg, sevCfg(sev).text)
                          : 'bg-primary/10 text-primary border border-primary/30'
                        : 'text-muted hover:text-text border border-transparent hover:border-border'
                    )}
                  >
                    {sev ?? 'All'}
                  </button>
                ))}
              </div>

              <div className="h-4 w-px bg-border" />

              {/* Source filter */}
              <input
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                placeholder="Source filter..."
                className="h-6 rounded border border-border bg-bg px-2 text-[11px] text-text placeholder:text-muted focus:outline-none focus:border-primary w-32"
              />

              {/* Technique filter */}
              <input
                value={techniqueFilter}
                onChange={(e) => setTechniqueFilter(e.target.value)}
                placeholder="Technique..."
                className="h-6 rounded border border-border bg-bg px-2 text-[11px] text-text placeholder:text-muted focus:outline-none focus:border-primary w-28"
              />

              <div className="flex-1" />

              {/* Pause/resume */}
              <button
                onClick={() => setPaused((v) => !v)}
                className={cn(
                  'flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium border transition-colors',
                  paused
                    ? 'bg-amber/10 border-amber/30 text-amber'
                    : 'border-border text-muted hover:text-text'
                )}
              >
                {paused ? (
                  <><Play className="h-2.5 w-2.5" /> Resume {pendingRef.current.length > 0 && `(+${pendingRef.current.length})`}</>
                ) : (
                  <><Pause className="h-2.5 w-2.5" /> Pause</>
                )}
              </button>

              {/* Clear */}
              <button
                onClick={() => setEvents([])}
                className="flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium border border-border text-muted hover:text-red hover:border-red/30 transition-colors"
              >
                <Trash2 className="h-2.5 w-2.5" />
                Clear
              </button>

              {/* Auto-scroll toggle */}
              <button
                onClick={() => setAutoScroll((v) => !v)}
                className={cn(
                  'flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-medium border transition-colors',
                  autoScroll
                    ? 'bg-green/10 border-green/30 text-green'
                    : 'border-border text-muted'
                )}
              >
                <Activity className="h-2.5 w-2.5" />
                Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
              </button>
            </div>

            {/* Count bar */}
            <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/50 bg-bg/30 shrink-0">
              <span className="text-[10px] text-muted">
                {filteredEvents.length.toLocaleString()} events
                {events.length !== filteredEvents.length && (
                  <> (filtered from {events.length.toLocaleString()})</>
                )}
              </span>
              {paused && (
                <Badge variant="warning" className="text-[9px] py-0 px-1.5 animate-pulse">
                  PAUSED
                </Badge>
              )}
              {session.status === 'running' && !paused && (
                <span className="relative flex h-1.5 w-1.5 ml-1">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue opacity-75" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue" />
                </span>
              )}
            </div>

            {/* Event list */}
            <div
              ref={feedRef}
              onScroll={handleFeedScroll}
              className="flex-1 overflow-y-auto font-mono text-sm min-h-0"
            >
              {filteredEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-32 text-muted">
                  <Activity className="h-8 w-8 mb-2 opacity-30" />
                  <p className="text-xs">
                    {session.status === 'running'
                      ? 'Waiting for events...'
                      : 'No events to display'}
                  </p>
                </div>
              ) : (
                filteredEvents.map((event) => <EventRow key={event.id} event={event} />)
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
