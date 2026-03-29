'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  RefreshCw,
  Camera,
  TrendingUp,
  AlertTriangle,
  Zap,
  ExternalLink,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

interface DESScore {
  overall_score: number
  breadth: number
  depth: number
  freshness: number
  pass_rate: number
  signal: number
  rules_analyzed: number
  techniques_covered: number
  total_techniques: number
  computed_at: string
  interpretation: string
}

interface IHDSScore {
  ihds_score: number
  intel_score: number
  hunt_score: number
  detection_score: number
  joti_connected: boolean
  joti_hccs: { score: number; covered_techniques: number; total_techniques: number } | null
  computed_at: string
}

interface HistoryPoint {
  date: string
  des_score: number
  rules_count: number
  use_cases_passing: number
  use_cases_total: number
}

interface TacticBreakdown {
  tactic: string
  technique_count: number
  covered_count: number
  coverage_pct: number
  rules_count: number
  use_cases_passing: number
  use_cases_failing: number
  des_contribution: number
}

interface CriticalGap {
  technique_id: string
  name: string
  tactic: string
  threat_frequency: 'high' | 'medium' | 'low'
  use_case_count: number
}

interface QuickWin {
  technique_id: string
  name: string
  tactic: string
  existing_log_sources: string[]
  suggested_rule_type: string
}

interface GapAnalysis {
  total_techniques: number
  covered: number
  gap_count: number
  critical_gaps: CriticalGap[]
  quick_wins: QuickWin[]
  improvement_trajectory: {
    current_des: number
    projected_30d: number
    projected_90d: number
  }
}

interface LeaderboardEntry {
  use_case_id: string
  name: string
  technique_id: string
  total_runs: number
  pass_rate: number
  last_run_at: string | null
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

function scoreColor(score: number, asText = true): string {
  const prefix = asText ? 'text-' : 'stroke-'
  if (score >= 0.7) return prefix + (asText ? 'green' : '[#22c55e]')
  if (score >= 0.4) return prefix + (asText ? 'amber' : '[#f59e0b]')
  return prefix + (asText ? 'red' : '[#ef4444]')
}

function scoreHex(score: number): string {
  if (score >= 0.7) return '#22c55e'
  if (score >= 0.4) return '#f59e0b'
  return '#ef4444'
}

function coverageColor(pct: number): string {
  if (pct >= 70) return 'bg-green-500'
  if (pct >= 30) return 'bg-amber-500'
  return 'bg-red-500'
}

function coverageTextColor(pct: number): string {
  if (pct >= 70) return 'text-green-400'
  if (pct >= 30) return 'text-amber-400'
  return 'text-red-400'
}

function freqColor(freq: string): string {
  if (freq === 'high') return 'destructive'
  if (freq === 'medium') return 'warning'
  return 'default'
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── Large Circular Score Gauge ───────────────────────────────────────────────

function CircularGauge({
  score,
  size = 200,
  label,
}: {
  score: number
  size?: number
  label?: string
}) {
  const r = size * 0.38
  const cx = size / 2
  const cy = size / 2
  const circumference = 2 * Math.PI * r
  const dash = score * circumference
  const color = scoreHex(score)

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Track */}
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth={size * 0.06} />
        {/* Progress */}
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={size * 0.06}
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
        {/* Score text */}
        <text
          x={cx}
          y={cy - 8}
          textAnchor="middle"
          dominantBaseline="central"
          fill={color}
          fontSize={size * 0.18}
          fontWeight="bold"
        >
          {(score * 100).toFixed(0)}
        </text>
        {/* Sub label */}
        <text
          x={cx}
          y={cy + size * 0.14}
          textAnchor="middle"
          dominantBaseline="central"
          fill="#94a3b8"
          fontSize={size * 0.07}
        >
          DES Score
        </text>
      </svg>
      {label && <p className="text-xs text-muted text-center max-w-[180px]">{label}</p>}
    </div>
  )
}

// ─── IHDS Component Bars ──────────────────────────────────────────────────────

function IHDSBars({ ihds }: { ihds: IHDSScore }) {
  const components = [
    { label: 'D — Detection', value: ihds.detection_score, desc: 'Rule coverage efficacy' },
    { label: 'E — Efficacy', value: ihds.intel_score, desc: 'Intel-aligned detection' },
    { label: 'S — Simulation', value: ihds.hunt_score, desc: 'Hunt coverage completeness' },
  ]

  return (
    <div className="space-y-3">
      {components.map((c) => (
        <div key={c.label}>
          <div className="flex items-center justify-between mb-1">
            <div>
              <span className="text-sm font-medium text-text">{c.label}</span>
              <span className="ml-2 text-xs text-muted">{c.desc}</span>
            </div>
            <span className={cn('text-sm font-bold', scoreColor(c.value))}>
              {(c.value * 100).toFixed(1)}%
            </span>
          </div>
          <div className="h-2.5 rounded-full bg-border overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${c.value * 100}%`,
                backgroundColor: scoreHex(c.value),
              }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── SVG Trend Chart ──────────────────────────────────────────────────────────

function TrendChart({ data }: { data: HistoryPoint[] }) {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; point: HistoryPoint } | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  if (!data.length) {
    return <p className="text-sm text-muted py-8 text-center">No history data available</p>
  }

  const W = 800
  const H = 200
  const PAD = { top: 16, right: 24, bottom: 40, left: 48 }
  const chartW = W - PAD.left - PAD.right
  const chartH = H - PAD.top - PAD.bottom

  const scores = data.map((d) => d.des_score)
  const minScore = Math.max(0, Math.min(...scores) - 0.05)
  const maxScore = Math.min(1, Math.max(...scores) + 0.05)
  const scoreRange = maxScore - minScore || 0.1

  const xScale = (i: number) => PAD.left + (i / Math.max(data.length - 1, 1)) * chartW
  const yScale = (s: number) => PAD.top + chartH - ((s - minScore) / scoreRange) * chartH

  const points = data.map((d, i) => `${xScale(i)},${yScale(d.des_score)}`).join(' ')

  // Area fill path
  const areaPoints = [
    `${PAD.left},${PAD.top + chartH}`,
    ...data.map((d, i) => `${xScale(i)},${yScale(d.des_score)}`),
    `${xScale(data.length - 1)},${PAD.top + chartH}`,
  ].join(' ')

  // Y axis ticks
  const yTicks = [0, 0.25, 0.5, 0.75, 1.0].filter((t) => t >= minScore - 0.05 && t <= maxScore + 0.05)

  // X axis: show ~5 labels
  const xStep = Math.max(1, Math.floor(data.length / 5))
  const xLabels = data
    .map((d, i) => ({ i, label: d.date.slice(5) })) // MM-DD
    .filter((_, i) => i % xStep === 0 || i === data.length - 1)

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current
    if (!svg) return
    const rect = svg.getBoundingClientRect()
    const mx = ((e.clientX - rect.left) / rect.width) * W
    const relX = mx - PAD.left
    const idx = Math.round((relX / chartW) * (data.length - 1))
    const clampedIdx = Math.max(0, Math.min(data.length - 1, idx))
    const px = xScale(clampedIdx)
    const py = yScale(data[clampedIdx].des_score)
    setTooltip({ x: px, y: py, point: data[clampedIdx] })
  }

  return (
    <div className="relative w-full overflow-x-auto">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="w-full h-auto"
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setTooltip(null)}
      >
        <defs>
          <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {yTicks.map((t) => (
          <line
            key={t}
            x1={PAD.left}
            y1={yScale(t)}
            x2={PAD.left + chartW}
            y2={yScale(t)}
            stroke="#1e293b"
            strokeWidth="1"
          />
        ))}

        {/* Area fill */}
        <polygon points={areaPoints} fill="url(#areaGrad)" />

        {/* Line */}
        <polyline
          points={points}
          fill="none"
          stroke="#8b5cf6"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Y axis labels */}
        {yTicks.map((t) => (
          <text
            key={t}
            x={PAD.left - 6}
            y={yScale(t)}
            textAnchor="end"
            dominantBaseline="central"
            fill="#64748b"
            fontSize="11"
          >
            {(t * 100).toFixed(0)}
          </text>
        ))}

        {/* X axis labels */}
        {xLabels.map(({ i, label }) => (
          <text
            key={i}
            x={xScale(i)}
            y={PAD.top + chartH + 16}
            textAnchor="middle"
            fill="#64748b"
            fontSize="10"
          >
            {label}
          </text>
        ))}

        {/* Tooltip vertical line + circle */}
        {tooltip && (
          <>
            <line
              x1={tooltip.x}
              y1={PAD.top}
              x2={tooltip.x}
              y2={PAD.top + chartH}
              stroke="#8b5cf6"
              strokeWidth="1"
              strokeDasharray="4 2"
            />
            <circle cx={tooltip.x} cy={tooltip.y} r="5" fill="#8b5cf6" stroke="#0f172a" strokeWidth="2" />
            {/* Tooltip box */}
            <rect
              x={Math.min(tooltip.x + 8, W - 120)}
              y={Math.max(tooltip.y - 32, PAD.top)}
              width="110"
              height="40"
              rx="6"
              fill="#1e293b"
              stroke="#334155"
            />
            <text
              x={Math.min(tooltip.x + 13, W - 115)}
              y={Math.max(tooltip.y - 16, PAD.top + 12)}
              fill="#e2e8f0"
              fontSize="11"
              fontWeight="600"
            >
              {tooltip.point.date}
            </text>
            <text
              x={Math.min(tooltip.x + 13, W - 115)}
              y={Math.max(tooltip.y - 2, PAD.top + 26)}
              fill="#8b5cf6"
              fontSize="12"
              fontWeight="700"
            >
              DES {(tooltip.point.des_score * 100).toFixed(1)}
            </text>
          </>
        )}
      </svg>
    </div>
  )
}

// ─── Trajectory Mini-Chart ────────────────────────────────────────────────────

function TrajectoryChart({ trajectory }: { trajectory: GapAnalysis['improvement_trajectory'] }) {
  const points = [
    { label: 'Now', value: trajectory.current_des },
    { label: '30d', value: trajectory.projected_30d },
    { label: '90d', value: trajectory.projected_90d },
  ]

  const W = 280
  const H = 80
  const PAD = { top: 8, right: 16, bottom: 24, left: 40 }
  const chartW = W - PAD.left - PAD.right
  const chartH = H - PAD.top - PAD.bottom

  const minV = Math.max(0, Math.min(...points.map((p) => p.value)) - 0.05)
  const maxV = Math.min(1, Math.max(...points.map((p) => p.value)) + 0.05)
  const range = maxV - minV || 0.1

  const xScale = (i: number) => PAD.left + (i / (points.length - 1)) * chartW
  const yScale = (v: number) => PAD.top + chartH - ((v - minV) / range) * chartH

  const polyPoints = points.map((p, i) => `${xScale(i)},${yScale(p.value)}`).join(' ')

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto">
      <polyline
        points={polyPoints}
        fill="none"
        stroke="#22c55e"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="6 2"
      />
      {points.map((p, i) => (
        <g key={p.label}>
          <circle cx={xScale(i)} cy={yScale(p.value)} r="4" fill="#22c55e" />
          <text x={xScale(i)} y={H - 6} textAnchor="middle" fill="#64748b" fontSize="10">
            {p.label}
          </text>
          <text
            x={xScale(i)}
            y={yScale(p.value) - 8}
            textAnchor="middle"
            fill="#22c55e"
            fontSize="10"
            fontWeight="700"
          >
            {(p.value * 100).toFixed(0)}
          </text>
        </g>
      ))}
    </svg>
  )
}

// ─── Tactic name formatter ────────────────────────────────────────────────────

function tacticLabel(t: string): string {
  return t.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ScoringPage() {
  const router = useRouter()

  const [des, setDes] = useState<DESScore | null>(null)
  const [ihds, setIhds] = useState<IHDSScore | null>(null)
  const [history, setHistory] = useState<HistoryPoint[]>([])
  const [historyDays, setHistoryDays] = useState<7 | 30 | 90>(30)
  const [breakdown, setBreakdown] = useState<TacticBreakdown[]>([])
  const [gapAnalysis, setGapAnalysis] = useState<GapAnalysis | null>(null)
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [snapshotting, setSnapshotting] = useState(false)
  const [snapshotMsg, setSnapshotMsg] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)

    const [desRes, ihdsRes, breakdownRes, gapRes, leaderRes] = await Promise.allSettled([
      authFetch(`${API_BASE}/api/v2/scoring/des`),
      authFetch(`${API_BASE}/api/v2/scoring/ihds`),
      authFetch(`${API_BASE}/api/v2/scoring/breakdown`),
      authFetch(`${API_BASE}/api/v2/scoring/gap-analysis`),
      authFetch(`${API_BASE}/api/v2/scoring/leaderboard`),
    ])

    if (desRes.status === 'fulfilled' && desRes.value.ok) {
      setDes((await desRes.value.json()) as DESScore)
    }
    if (ihdsRes.status === 'fulfilled' && ihdsRes.value.ok) {
      setIhds((await ihdsRes.value.json()) as IHDSScore)
    }
    if (breakdownRes.status === 'fulfilled' && breakdownRes.value.ok) {
      setBreakdown((await breakdownRes.value.json()) as TacticBreakdown[])
    }
    if (gapRes.status === 'fulfilled' && gapRes.value.ok) {
      setGapAnalysis((await gapRes.value.json()) as GapAnalysis)
    }
    if (leaderRes.status === 'fulfilled' && leaderRes.value.ok) {
      setLeaderboard((await leaderRes.value.json()) as LeaderboardEntry[])
    }

    setLastUpdated(new Date())
    setLoading(false)
  }, [])

  const fetchHistory = useCallback(async (days: number) => {
    const res = await authFetch(`${API_BASE}/api/v2/scoring/history?days=${days}`)
    if (res.ok) {
      setHistory((await res.json()) as HistoryPoint[])
    }
  }, [])

  useEffect(() => {
    void fetchAll()
  }, [fetchAll])

  useEffect(() => {
    void fetchHistory(historyDays)
  }, [historyDays, fetchHistory])

  const handleSnapshot = async () => {
    setSnapshotting(true)
    setSnapshotMsg(null)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/scoring/snapshot`, { method: 'POST' })
      if (res.ok) {
        const data = (await res.json()) as { des_score: number; created_at: string }
        setSnapshotMsg(`Snapshot saved — DES ${(data.des_score * 100).toFixed(1)}`)
        void fetchHistory(historyDays)
      } else {
        setSnapshotMsg('Snapshot failed')
      }
    } catch {
      setSnapshotMsg('Snapshot failed')
    } finally {
      setSnapshotting(false)
      setTimeout(() => setSnapshotMsg(null), 4000)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-7 w-32" />
          <Skeleton className="h-9 w-32" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Skeleton className="h-72" />
          <Skeleton className="col-span-2 h-72" />
        </div>
        <Skeleton className="h-64" />
        <Skeleton className="h-96" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Skeleton className="h-80" />
          <Skeleton className="h-80" />
        </div>
        <Skeleton className="h-64" />
      </div>
    )
  }

  const desScore = des?.overall_score ?? 0
  const desLabel =
    desScore >= 0.7 ? 'Good' : desScore >= 0.4 ? 'Fair' : 'Poor'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-primary" />
            Scoring Analytics
          </h1>
          {lastUpdated && (
            <p className="text-xs text-muted mt-0.5">Updated {timeAgo(lastUpdated.toISOString())}</p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {snapshotMsg && (
            <span className="text-xs text-muted bg-card border border-border rounded px-2 py-1">
              {snapshotMsg}
            </span>
          )}
          <Button variant="outline" size="sm" onClick={handleSnapshot} disabled={snapshotting}>
            <Camera className={cn('h-3.5 w-3.5', snapshotting && 'animate-pulse')} />
            Take Snapshot
          </Button>
          <Button variant="outline" size="sm" onClick={() => void fetchAll(true)}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {/* ── Section 1: Score Overview ───────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* DES Gauge */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold">Detection Efficacy Score</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <CircularGauge score={desScore} size={200} />
            <div className="text-center">
              <p className={cn('text-lg font-bold', scoreColor(desScore))}>{desLabel}</p>
              <p className="text-xs text-muted mt-1 max-w-[240px]">{des?.interpretation}</p>
            </div>
            <div className="grid grid-cols-3 gap-3 w-full text-center">
              {[
                { label: 'Breadth', value: des?.breadth ?? 0 },
                { label: 'Depth', value: des?.depth ?? 0 },
                { label: 'Freshness', value: des?.freshness ?? 0 },
              ].map((m) => (
                <div key={m.label} className="rounded-lg bg-bg border border-border px-2 py-2">
                  <p className={cn('text-lg font-bold', scoreColor(m.value))}>
                    {(m.value * 100).toFixed(0)}
                  </p>
                  <p className="text-[10px] text-muted">{m.label}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* IHDS Breakdown */}
        <Card className="col-span-2">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold">IHDS Breakdown</CardTitle>
              {ihds?.joti_connected && ihds.joti_hccs && (
                <div className="flex items-center gap-2">
                  <Badge variant="success" className="text-[10px]">Joti HCCS</Badge>
                  <span className="text-sm font-bold text-primary">
                    {ihds.joti_hccs.score.toFixed(1)}
                  </span>
                  <span className="text-xs text-muted">
                    {ihds.joti_hccs.covered_techniques}/{ihds.joti_hccs.total_techniques} techniques
                  </span>
                </div>
              )}
            </div>
            <p className="text-xs text-muted">
              Intel-Hunt-Detection Score — {ihds ? (ihds.ihds_score * 100).toFixed(1) : '—'} overall
            </p>
          </CardHeader>
          <CardContent className="space-y-6">
            {ihds ? (
              <IHDSBars ihds={ihds} />
            ) : (
              <p className="text-sm text-muted">IHDS data unavailable</p>
            )}

            {/* Summary stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Rules', value: des?.rules_analyzed ?? 0 },
                { label: 'Covered', value: `${des?.techniques_covered ?? 0}/${des?.total_techniques ?? 0}` },
                { label: 'Pass Rate', value: `${((des?.pass_rate ?? 0) * 100).toFixed(0)}%` },
                { label: 'Signal', value: `${((des?.signal ?? 0) * 100).toFixed(0)}%` },
              ].map((s) => (
                <div key={s.label} className="rounded-lg bg-bg border border-border px-3 py-2.5 text-center">
                  <p className="text-xl font-bold text-text">{s.value}</p>
                  <p className="text-[10px] text-muted uppercase tracking-wide">{s.label}</p>
                </div>
              ))}
            </div>

            {/* Joti not connected notice */}
            {ihds && !ihds.joti_connected && (
              <div className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2 text-xs text-muted">
                <AlertTriangle className="h-3.5 w-3.5 text-amber shrink-0" />
                Joti integration not connected — HCCS badge unavailable. Configure in Settings.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Section 2: Trend Chart ──────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold">DES Score Trend</CardTitle>
              <p className="text-xs text-muted">Detection efficacy over time</p>
            </div>
            <div className="flex items-center gap-1">
              {([7, 30, 90] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => setHistoryDays(d)}
                  className={cn(
                    'px-2.5 py-1 text-xs rounded font-medium transition-colors',
                    historyDays === d
                      ? 'bg-primary/20 text-primary'
                      : 'text-muted hover:text-text hover:bg-bg'
                  )}
                >
                  {d}d
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <TrendChart data={history} />
        </CardContent>
      </Card>

      {/* ── Section 3: Tactic Breakdown Table ──────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Tactic Breakdown</CardTitle>
          <p className="text-xs text-muted">Sorted by coverage ascending — worst gaps first</p>
        </CardHeader>
        <CardContent className="p-0">
          {breakdown.length === 0 ? (
            <p className="px-5 py-6 text-center text-sm text-muted">No breakdown data</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Tactic</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Techniques</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide w-48">Coverage %</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Rules</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Use Cases</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">DES Contribution</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {breakdown.map((row) => (
                    <tr
                      key={row.tactic}
                      className="hover:bg-bg/50 cursor-pointer transition-colors"
                      onClick={() =>
                        router.push(`/mitre?tactic=${encodeURIComponent(row.tactic)}`)
                      }
                    >
                      <td className="px-4 py-3">
                        <span className="font-medium text-text">{tacticLabel(row.tactic)}</span>
                      </td>
                      <td className="px-4 py-3 text-muted">
                        {row.covered_count}/{row.technique_count}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 rounded-full bg-border overflow-hidden">
                            <div
                              className={cn('h-full rounded-full transition-all', coverageColor(row.coverage_pct))}
                              style={{ width: `${row.coverage_pct}%` }}
                            />
                          </div>
                          <span className={cn('text-xs font-medium w-10 text-right', coverageTextColor(row.coverage_pct))}>
                            {row.coverage_pct.toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-muted">{row.rules_count}</td>
                      <td className="px-4 py-3 text-muted">
                        {row.use_cases_passing > 0 || row.use_cases_failing > 0 ? (
                          <span>
                            <span className="text-green-400">{row.use_cases_passing}</span>
                            <span className="text-muted mx-1">/</span>
                            <span className="text-red-400">{row.use_cases_failing}</span>
                          </span>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono text-primary">
                          {(row.des_contribution * 100).toFixed(2)}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Section 4: Gap Analysis ─────────────────────────────────────── */}
      {gapAnalysis && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Critical Gaps */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                    Critical Gaps
                  </CardTitle>
                  <p className="text-xs text-muted">
                    {gapAnalysis.gap_count} uncovered of {gapAnalysis.total_techniques} techniques
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <TrajectoryChart trajectory={gapAnalysis.improvement_trajectory} />
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0 max-h-96 overflow-y-auto">
              {gapAnalysis.critical_gaps.length === 0 ? (
                <p className="px-5 py-6 text-center text-sm text-green-400">No critical gaps — full coverage!</p>
              ) : (
                <div className="divide-y divide-border">
                  {gapAnalysis.critical_gaps.map((gap) => (
                    <div key={gap.technique_id} className="flex items-center justify-between px-4 py-3 gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-mono text-primary">{gap.technique_id}</span>
                          <Badge
                            variant={freqColor(gap.threat_frequency) as 'destructive' | 'warning' | 'default'}
                            className="text-[10px]"
                          >
                            {gap.threat_frequency}
                          </Badge>
                          <Badge variant="default" className="text-[10px] bg-slate-800">
                            {tacticLabel(gap.tactic)}
                          </Badge>
                        </div>
                        <p className="text-xs text-text mt-0.5 truncate">{gap.name}</p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        className="shrink-0 text-xs h-7"
                        onClick={() =>
                          router.push(`/use-cases?technique=${gap.technique_id}`)
                        }
                      >
                        Create Use Case
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Quick Wins */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                Quick Wins
              </CardTitle>
              <p className="text-xs text-muted">Gaps with existing log sources — easy to rule</p>
            </CardHeader>
            <CardContent className="p-0 max-h-96 overflow-y-auto">
              {gapAnalysis.quick_wins.length === 0 ? (
                <p className="px-5 py-6 text-center text-sm text-muted">No quick wins available</p>
              ) : (
                <div className="divide-y divide-border">
                  {gapAnalysis.quick_wins.map((win) => (
                    <div key={win.technique_id} className="px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-mono text-primary">{win.technique_id}</span>
                            <Badge variant="default" className="text-[10px] bg-slate-800">
                              {tacticLabel(win.tactic)}
                            </Badge>
                          </div>
                          <p className="text-xs text-text mt-0.5 truncate">{win.name}</p>
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {win.existing_log_sources.map((src) => (
                              <span
                                key={src}
                                className="text-[10px] rounded px-1.5 py-0.5 bg-primary/10 text-primary"
                              >
                                {src}
                              </span>
                            ))}
                          </div>
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          className="shrink-0 text-xs h-7"
                          onClick={() =>
                            router.push(`/rules?search=${encodeURIComponent(win.technique_id)}`)
                          }
                        >
                          <ExternalLink className="h-3 w-3 mr-1" />
                          Generate Rule
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Section 5: Leaderboard ──────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-semibold">Use Case Leaderboard</CardTitle>
          <p className="text-xs text-muted">Top performing use cases by run count and pass rate</p>
        </CardHeader>
        <CardContent className="p-0">
          {leaderboard.length === 0 ? (
            <p className="px-5 py-6 text-center text-sm text-muted">
              No use case runs yet — run some use cases to see the leaderboard.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">#</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Use Case</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Technique</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Runs</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide w-48">Pass Rate</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Last Run</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {leaderboard.map((entry, idx) => (
                    <tr
                      key={entry.use_case_id}
                      className="hover:bg-bg/50 cursor-pointer transition-colors"
                      onClick={() => router.push(`/use-cases`)}
                    >
                      <td className="px-4 py-3">
                        <span className={cn(
                          'text-sm font-bold',
                          idx === 0 ? 'text-amber-400' :
                          idx === 1 ? 'text-slate-400' :
                          idx === 2 ? 'text-amber-700' : 'text-muted'
                        )}>
                          {idx + 1}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-medium text-text truncate max-w-[200px] block">{entry.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        {entry.technique_id ? (
                          <span className="text-xs font-mono text-primary">{entry.technique_id}</span>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted">{entry.total_runs}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 rounded-full bg-border overflow-hidden">
                            <div
                              className={cn('h-full rounded-full transition-all', coverageColor(entry.pass_rate * 100))}
                              style={{ width: `${entry.pass_rate * 100}%` }}
                            />
                          </div>
                          <span className={cn('text-xs font-medium w-10 text-right', coverageTextColor(entry.pass_rate * 100))}>
                            {(entry.pass_rate * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-muted text-xs">
                        {entry.last_run_at ? timeAgo(entry.last_run_at) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
