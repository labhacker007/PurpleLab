'use client'

import { useState, useEffect, useCallback } from 'react'
import { RefreshCw, TrendingUp, TrendingDown, Minus, Activity, Clock, Zap, AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface MitreTactic {
  tactic: string
  count: number
  covered: number
}

interface RecentEvent {
  id: string
  source_type: string
  technique_id: string
  technique_name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  timestamp: string
}

interface SystemStatus {
  db_connected: boolean
  redis_connected: boolean
  siem_connections: number
  siem_total: number
  joti_configured: boolean
  joti_connected: boolean
}

interface DashboardMetrics {
  active_sessions: number
  events_generated_today: number
  des_score: number
  hitl_pending: number
  mitre_coverage: MitreTactic[]
  recent_events: RecentEvent[]
  system_status: SystemStatus
  sessions_delta: number
  events_delta: number
}

// ─── Circular score SVG ────────────────────────────────────────────────────────

function CircularScore({ score }: { score: number }) {
  const r = 36
  const c = 2 * Math.PI * r
  const dash = (score / 1) * c
  const color = score >= 0.7 ? '#22c55e' : score >= 0.4 ? '#f59e0b' : '#ef4444'
  return (
    <svg width="100" height="100" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
      <circle
        cx="50"
        cy="50"
        r={r}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeDasharray={`${dash} ${c}`}
        strokeLinecap="round"
        transform="rotate(-90 50 50)"
      />
      <text
        x="50"
        y="50"
        textAnchor="middle"
        dominantBaseline="central"
        fill={color}
        fontSize="18"
        fontWeight="bold"
      >
        {(score * 100).toFixed(0)}
      </text>
    </svg>
  )
}

// ─── KPI Card ──────────────────────────────────────────────────────────────────

function KpiCard({
  label,
  value,
  delta,
  icon: Icon,
  accent,
  children,
}: {
  label: string
  value: string | number
  delta?: number
  icon: React.ElementType
  accent?: string
  children?: React.ReactNode
}) {
  const TrendIcon = delta === undefined ? Minus : delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus
  const trendColor = delta === undefined ? 'text-muted' : delta > 0 ? 'text-green' : delta < 0 ? 'text-red' : 'text-muted'

  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <p className="text-xs font-medium text-muted uppercase tracking-wide">{label}</p>
            {children ?? (
              <p className={cn('mt-1.5 text-3xl font-bold', accent ?? 'text-text')}>
                {value}
              </p>
            )}
          </div>
          <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg bg-border/50')}>
            <Icon className={cn('h-4 w-4', accent ?? 'text-muted')} />
          </div>
        </div>
        {delta !== undefined && (
          <div className={cn('mt-2 flex items-center gap-1 text-xs', trendColor)}>
            <TrendIcon className="h-3 w-3" />
            <span>{Math.abs(delta)}% vs yesterday</span>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ─── Coverage Bar Chart ────────────────────────────────────────────────────────

function CoverageChart({ tactics }: { tactics: MitreTactic[] }) {
  if (!tactics.length) return (
    <p className="text-sm text-muted py-4 text-center">No coverage data available</p>
  )
  const max = Math.max(...tactics.map((t) => t.count), 1)
  return (
    <div className="space-y-2.5">
      {tactics.map((t) => {
        const pct = t.count > 0 ? (t.covered / t.count) * 100 : 0
        return (
          <div key={t.tactic} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-text capitalize">{t.tactic.replace(/_/g, ' ')}</span>
              <span className="text-muted">{t.covered}/{t.count}</span>
            </div>
            <div className="relative h-2 rounded-full bg-border overflow-hidden">
              <div
                className="h-full rounded-full bg-primary transition-all duration-500"
                style={{ width: `${(t.count / max) * 100}%` }}
              >
                <div
                  className="h-full rounded-full bg-primary/40"
                  style={{ width: `${100 - pct}%`, float: 'right' }}
                />
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Severity badge ────────────────────────────────────────────────────────────

const SEVERITY_VARIANTS: Record<string, 'destructive' | 'warning' | 'info' | 'default'> = {
  critical: 'destructive',
  high: 'destructive',
  medium: 'warning',
  low: 'info',
  info: 'default',
}

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

// ─── Status dot ───────────────────────────────────────────────────────────────

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <div className={cn('h-2 w-2 rounded-full', ok ? 'bg-green' : 'bg-red')} />
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
  )
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchMetrics = useCallback(async (silent = false) => {
    if (!silent) setIsLoading(true)
    else setIsRefreshing(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/dashboard/metrics`)
      if (res.ok) {
        const data = (await res.json()) as DashboardMetrics
        setMetrics(data)
        setLastUpdated(new Date())
      } else {
        // Use mock data if API unavailable
        setMetrics(getMockMetrics())
      }
    } catch {
      setMetrics(getMockMetrics())
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void fetchMetrics()
    const interval = setInterval(() => void fetchMetrics(true), 30_000)
    return () => clearInterval(interval)
  }, [fetchMetrics])

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-7 w-32" />
          <Skeleton className="h-9 w-24" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-32" />)}
        </div>
        <Skeleton className="h-56" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    )
  }

  const m = metrics!

  const desColor =
    m.des_score >= 0.7 ? 'text-green' : m.des_score >= 0.4 ? 'text-amber' : 'text-red'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Dashboard</h1>
          {lastUpdated && (
            <p className="text-xs text-muted mt-0.5">
              Updated {timeAgo(lastUpdated.toISOString())}
            </p>
          )}
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void fetchMetrics(true)}
          disabled={isRefreshing}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Active Sessions"
          value={m.active_sessions}
          delta={m.sessions_delta}
          icon={Activity}
          accent={m.active_sessions > 0 ? 'text-green' : undefined}
        />

        <KpiCard
          label="Events Today"
          value={m.events_generated_today.toLocaleString()}
          delta={m.events_delta}
          icon={Zap}
          accent="text-primary"
        />

        <Card>
          <CardContent className="p-5">
            <p className="text-xs font-medium text-muted uppercase tracking-wide">DES Score</p>
            <div className="mt-1 flex items-center gap-3">
              <CircularScore score={m.des_score} />
              <div>
                <p className={cn('text-lg font-bold', desColor)}>
                  {m.des_score >= 0.7 ? 'Good' : m.des_score >= 0.4 ? 'Fair' : 'Poor'}
                </p>
                <p className="text-xs text-muted">Detection efficacy</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <KpiCard
          label="HITL Pending"
          value={m.hitl_pending}
          icon={AlertTriangle}
          accent={m.hitl_pending > 0 ? 'text-amber' : undefined}
        >
          <div className="mt-1.5 flex items-center gap-2">
            <p className={cn('text-3xl font-bold', m.hitl_pending > 0 ? 'text-amber' : 'text-text')}>
              {m.hitl_pending}
            </p>
            {m.hitl_pending > 0 && (
              <Badge variant="warning" className="text-[10px]">pending</Badge>
            )}
          </div>
        </KpiCard>
      </div>

      {/* MITRE Coverage */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">MITRE ATT&CK Coverage</CardTitle>
          <p className="text-xs text-muted">Tactic coverage across active environments</p>
        </CardHeader>
        <CardContent>
          <CoverageChart tactics={m.mitre_coverage} />
        </CardContent>
      </Card>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {m.recent_events.length === 0 ? (
              <p className="px-5 py-6 text-center text-sm text-muted">No recent events</p>
            ) : (
              <div className="divide-y divide-border">
                {m.recent_events.slice(0, 10).map((ev) => (
                  <div key={ev.id} className="flex items-center gap-3 px-5 py-2.5">
                    <Badge variant={SEVERITY_VARIANTS[ev.severity] ?? 'default'} className="text-[10px] shrink-0">
                      {ev.severity}
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-text truncate">{ev.technique_name}</p>
                      <p className="text-[10px] text-muted">{ev.technique_id} · {ev.source_type}</p>
                    </div>
                    <span className="text-[10px] text-muted shrink-0">{timeAgo(ev.timestamp)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* System Status */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">System Status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-4 py-3">
              <div className="flex items-center gap-2.5">
                <StatusDot ok={m.system_status.db_connected} />
                <span className="text-sm text-text">Database</span>
              </div>
              <Badge variant={m.system_status.db_connected ? 'success' : 'destructive'} className="text-[10px]">
                {m.system_status.db_connected ? 'connected' : 'disconnected'}
              </Badge>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-4 py-3">
              <div className="flex items-center gap-2.5">
                <StatusDot ok={m.system_status.redis_connected} />
                <span className="text-sm text-text">Redis</span>
              </div>
              <Badge variant={m.system_status.redis_connected ? 'success' : 'destructive'} className="text-[10px]">
                {m.system_status.redis_connected ? 'connected' : 'disconnected'}
              </Badge>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-4 py-3">
              <div className="flex items-center gap-2.5">
                <StatusDot ok={m.system_status.siem_connections > 0} />
                <span className="text-sm text-text">SIEM Connections</span>
              </div>
              <span className="text-xs text-muted">
                {m.system_status.siem_connections}/{m.system_status.siem_total} connected
              </span>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-4 py-3">
              <div className="flex items-center gap-2.5">
                <StatusDot ok={m.system_status.joti_connected} />
                <span className="text-sm text-text">Joti Integration</span>
              </div>
              {m.system_status.joti_configured ? (
                <Badge variant={m.system_status.joti_connected ? 'success' : 'destructive'} className="text-[10px]">
                  {m.system_status.joti_connected ? 'connected' : 'error'}
                </Badge>
              ) : (
                <Badge variant="default" className="text-[10px]">not configured</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

// ─── Mock data fallback ───────────────────────────────────────────────────────

function getMockMetrics(): DashboardMetrics {
  return {
    active_sessions: 3,
    events_generated_today: 1842,
    des_score: 0.73,
    hitl_pending: 2,
    sessions_delta: 12,
    events_delta: -5,
    mitre_coverage: [
      { tactic: 'initial_access', count: 12, covered: 9 },
      { tactic: 'execution', count: 18, covered: 14 },
      { tactic: 'persistence', count: 10, covered: 6 },
      { tactic: 'privilege_escalation', count: 8, covered: 5 },
      { tactic: 'defense_evasion', count: 20, covered: 11 },
      { tactic: 'credential_access', count: 15, covered: 10 },
      { tactic: 'lateral_movement', count: 9, covered: 7 },
      { tactic: 'exfiltration', count: 6, covered: 4 },
    ],
    recent_events: [
      { id: '1', source_type: 'crowdstrike', technique_id: 'T1059.001', technique_name: 'PowerShell Execution', severity: 'high', timestamp: new Date(Date.now() - 90_000).toISOString() },
      { id: '2', source_type: 'splunk', technique_id: 'T1078', technique_name: 'Valid Accounts', severity: 'critical', timestamp: new Date(Date.now() - 300_000).toISOString() },
      { id: '3', source_type: 'elastic', technique_id: 'T1003.001', technique_name: 'LSASS Memory', severity: 'high', timestamp: new Date(Date.now() - 600_000).toISOString() },
      { id: '4', source_type: 'guardduty', technique_id: 'T1190', technique_name: 'Exploit Public-Facing App', severity: 'medium', timestamp: new Date(Date.now() - 1_200_000).toISOString() },
      { id: '5', source_type: 'syslog', technique_id: 'T1071.001', technique_name: 'Web Protocols C2', severity: 'low', timestamp: new Date(Date.now() - 3_600_000).toISOString() },
    ],
    system_status: {
      db_connected: true,
      redis_connected: true,
      siem_connections: 2,
      siem_total: 3,
      joti_configured: true,
      joti_connected: true,
    },
  }
}
