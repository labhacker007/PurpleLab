'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Target,
  Shield,
  AlertTriangle,
  Search,
  Grid3X3,
  X,
  ExternalLink,
  Download,
  RefreshCw,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface Tactic {
  id: string
  name: string
  slug: string
  description: string
  technique_count: number
  covered_count: number
  coverage_pct: number
}

interface Technique {
  technique_id: string
  name: string
  tactic: string
  description: string
  platforms: string[]
  detection_count: number
  use_case_count: number
  has_coverage: boolean
  is_subtechnique: boolean
}

interface TechniqueDetail extends Technique {
  data_sources: string[]
  detection_notes: string
  sub_techniques: Technique[]
  related_rules: { id: string; name: string; severity: string; language: string }[]
  related_use_cases: { id: string; name: string; severity: string; tactic: string }[]
}

interface HeatmapCell {
  technique_id: string
  name: string
  detection_count: number
  coverage_level: 0 | 1 | 2
}

interface HeatmapTactic {
  tactic_id: string
  tactic_name: string
  tactic_slug: string
  techniques: HeatmapCell[]
  total: number
  covered: number
  coverage_pct: number
}

interface CoverageMatrix {
  matrix: HeatmapTactic[]
  total_techniques: number
  total_covered: number
  overall_coverage_pct: number
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function coverageBadge(tech: Technique) {
  if (tech.has_coverage && tech.detection_count >= 2) {
    return <Badge className="text-[10px] bg-emerald-700/20 text-emerald-400 border-emerald-700/40">Covered</Badge>
  }
  if (tech.has_coverage && tech.detection_count < 2) {
    return <Badge className="text-[10px] bg-amber-700/20 text-amber-400 border-amber-700/40">Partial</Badge>
  }
  return <Badge className="text-[10px] bg-red-900/20 text-red-400 border-red-800/40">Gap</Badge>
}

function heatmapColor(level: 0 | 1 | 2) {
  if (level === 2) return 'bg-emerald-700 hover:bg-emerald-600'
  if (level === 1) return 'bg-amber-800 hover:bg-amber-700'
  return 'bg-slate-800 hover:bg-slate-700'
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-slate-800/60', className)} />
}

// ─── Tactic sidebar item ───────────────────────────────────────────────────────

function TacticPill({
  tactic,
  isActive,
  onClick,
}: {
  tactic: Tactic
  isActive: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-lg px-3 py-2.5 transition-colors group',
        isActive
          ? 'bg-violet-600/20 text-violet-300 border border-violet-600/40'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
      )}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-sm font-medium truncate">{tactic.name}</span>
        <span className={cn('text-[10px] shrink-0 ml-1', isActive ? 'text-violet-400' : 'text-slate-500')}>
          {tactic.technique_count}
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-700/80 overflow-hidden">
        <div
          className={cn(
            'h-full rounded-full transition-all duration-500',
            tactic.coverage_pct >= 70
              ? 'bg-emerald-500'
              : tactic.coverage_pct >= 30
              ? 'bg-amber-500'
              : 'bg-red-500'
          )}
          style={{ width: `${tactic.coverage_pct}%` }}
        />
      </div>
      <div className="mt-1 text-[10px] text-slate-500">{tactic.coverage_pct.toFixed(0)}% covered</div>
    </button>
  )
}

// ─── Technique card ────────────────────────────────────────────────────────────

function TechniqueCard({
  tech,
  onClick,
  isSelected,
}: {
  tech: Technique
  onClick: () => void
  isSelected: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-lg border p-3.5 transition-all hover:border-violet-600/40 hover:bg-slate-800/60',
        isSelected
          ? 'border-violet-600/60 bg-violet-600/10'
          : 'border-slate-700/60 bg-slate-900/40'
      )}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-[11px] font-mono text-violet-400">{tech.technique_id}</span>
        {coverageBadge(tech)}
      </div>
      <p className="text-sm font-medium text-slate-200 leading-snug line-clamp-2">{tech.name}</p>
      {(tech.detection_count > 0 || tech.use_case_count > 0) && (
        <div className="mt-2 flex items-center gap-2 text-[10px] text-slate-500">
          {tech.detection_count > 0 && (
            <span className="flex items-center gap-1">
              <Shield className="h-3 w-3 text-emerald-500" />
              {tech.detection_count} rule{tech.detection_count !== 1 ? 's' : ''}
            </span>
          )}
          {tech.use_case_count > 0 && (
            <span className="flex items-center gap-1">
              <Target className="h-3 w-3 text-blue-400" />
              {tech.use_case_count} UC
            </span>
          )}
        </div>
      )}
    </button>
  )
}

// ─── Detail panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  techniqueId,
  onClose,
}: {
  techniqueId: string
  onClose: () => void
}) {
  const [detail, setDetail] = useState<TechniqueDetail | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    setDetail(null)
    authFetch(`${API_BASE}/api/v2/threat-intel/mitre/techniques/${techniqueId}`)
      .then((r) => r.json())
      .then((d) => setDetail(d as TechniqueDetail))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false))
  }, [techniqueId])

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700/60 shrink-0">
        <div>
          <span className="text-xs font-mono text-violet-400">{techniqueId}</span>
          {detail && <h3 className="text-sm font-semibold text-slate-100 mt-0.5">{detail.name}</h3>}
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-700/60 transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
        {loading && (
          <div className="space-y-3">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        )}

        {!loading && !detail && (
          <p className="text-sm text-slate-500 py-4 text-center">Failed to load technique details.</p>
        )}

        {detail && (
          <>
            {/* Coverage badges */}
            <div className="flex flex-wrap gap-2">
              {coverageBadge(detail)}
              {detail.platforms?.map((p) => (
                <Badge key={p} className="text-[10px] text-slate-400 border-slate-600">
                  {p}
                </Badge>
              ))}
            </div>

            {/* Description */}
            {detail.description && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1.5">Description</h4>
                <p className="text-sm text-slate-300 leading-relaxed line-clamp-6">{detail.description}</p>
              </div>
            )}

            {/* Data sources */}
            {detail.data_sources?.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1.5">Data Sources</h4>
                <div className="flex flex-wrap gap-1.5">
                  {detail.data_sources.map((ds) => (
                    <span key={ds} className="text-[11px] rounded px-1.5 py-0.5 bg-slate-800 text-slate-300 border border-slate-700">
                      {ds}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Detection notes */}
            {detail.detection_notes && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1.5">Detection Notes</h4>
                <p className="text-sm text-slate-300 leading-relaxed line-clamp-4">{detail.detection_notes}</p>
              </div>
            )}

            {/* Related rules */}
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">
                Detection Rules ({detail.related_rules.length})
              </h4>
              {detail.related_rules.length === 0 ? (
                <p className="text-xs text-slate-500">No rules linked to this technique.</p>
              ) : (
                <div className="space-y-1.5">
                  {detail.related_rules.map((rule) => (
                    <a
                      key={rule.id}
                      href={`/rules?id=${rule.id}`}
                      className="flex items-center justify-between rounded-lg border border-slate-700/60 bg-slate-800/40 px-3 py-2 hover:border-slate-600 transition-colors group"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Shield className="h-3 w-3 text-emerald-500 shrink-0" />
                        <span className="text-xs text-slate-300 truncate">{rule.name}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-[10px] text-slate-500 font-mono">{rule.language}</span>
                        <ExternalLink className="h-3 w-3 text-slate-500 group-hover:text-slate-300 transition-colors" />
                      </div>
                    </a>
                  ))}
                </div>
              )}
            </div>

            {/* Related use cases */}
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">
                Use Cases ({detail.related_use_cases.length})
              </h4>
              {detail.related_use_cases.length === 0 ? (
                <p className="text-xs text-slate-500">No use cases linked to this technique.</p>
              ) : (
                <div className="space-y-1.5">
                  {detail.related_use_cases.map((uc) => (
                    <a
                      key={uc.id}
                      href={`/use-cases?id=${uc.id}`}
                      className="flex items-center justify-between rounded-lg border border-slate-700/60 bg-slate-800/40 px-3 py-2 hover:border-slate-600 transition-colors group"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Target className="h-3 w-3 text-blue-400 shrink-0" />
                        <span className="text-xs text-slate-300 truncate">{uc.name}</span>
                      </div>
                      <ExternalLink className="h-3 w-3 text-slate-500 group-hover:text-slate-300 transition-colors shrink-0" />
                    </a>
                  ))}
                </div>
              )}
            </div>

            {/* Create use case CTA */}
            <div className="pt-2">
              <a
                href={`/use-cases/new?technique=${detail.technique_id}`}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-violet-600/20 border border-violet-600/40 px-4 py-2.5 text-sm font-medium text-violet-300 hover:bg-violet-600/30 transition-colors"
              >
                <Target className="h-4 w-4" />
                Create Use Case for {detail.technique_id}
              </a>
            </div>

            {/* External link */}
            <div className="pb-2">
              <a
                href={`https://attack.mitre.org/techniques/${detail.technique_id.replace('.', '/')}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700/60 px-4 py-2 text-xs text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors"
              >
                View on MITRE ATT&CK
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// ─── Heatmap view ──────────────────────────────────────────────────────────────

function HeatmapView({
  matrix,
  onTechniqueClick,
}: {
  matrix: HeatmapTactic[]
  onTechniqueClick: (id: string) => void
}) {
  const [tooltip, setTooltip] = useState<{ tech: HeatmapCell; x: number; y: number } | null>(null)

  if (!matrix.length) {
    return <p className="text-sm text-slate-500 py-10 text-center">No heatmap data available.</p>
  }

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[900px]">
        {/* Tactic headers */}
        <div className="grid gap-1 mb-1" style={{ gridTemplateColumns: `repeat(${matrix.length}, minmax(0, 1fr))` }}>
          {matrix.map((t) => (
            <div key={t.tactic_id} className="text-center">
              <div className="text-[10px] font-semibold text-slate-300 truncate px-1">{t.tactic_name}</div>
              <div className="text-[9px] text-slate-500">{t.covered}/{t.total}</div>
            </div>
          ))}
        </div>

        {/* Technique rows — render column by column */}
        <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${matrix.length}, minmax(0, 1fr))` }}>
          {matrix.map((tactic) => (
            <div key={tactic.tactic_id} className="flex flex-col gap-0.5">
              {tactic.techniques.map((tech) => (
                <button
                  key={tech.technique_id}
                  onClick={() => onTechniqueClick(tech.technique_id)}
                  onMouseEnter={(e) => {
                    const rect = e.currentTarget.getBoundingClientRect()
                    setTooltip({ tech, x: rect.left, y: rect.top })
                  }}
                  onMouseLeave={() => setTooltip(null)}
                  className={cn(
                    'w-full h-4 rounded-sm text-[8px] text-transparent hover:text-white transition-colors cursor-pointer',
                    heatmapColor(tech.coverage_level)
                  )}
                  title={`${tech.technique_id}: ${tech.name} (${tech.detection_count} rules)`}
                />
              ))}
            </div>
          ))}
        </div>

        {/* Legend */}
        <div className="mt-4 flex items-center gap-4 text-xs text-slate-400">
          <span className="font-medium text-slate-300">Legend:</span>
          <div className="flex items-center gap-1.5">
            <div className="h-3 w-5 rounded-sm bg-slate-800 border border-slate-700" />
            <span>No coverage</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-3 w-5 rounded-sm bg-amber-800" />
            <span>Partial (1 rule)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-3 w-5 rounded-sm bg-emerald-700" />
            <span>Covered (2+ rules)</span>
          </div>
        </div>
      </div>

      {/* Tooltip — fixed position */}
      {tooltip && (
        <div
          className="fixed z-50 pointer-events-none bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-xs shadow-xl"
          style={{ left: tooltip.x + 20, top: tooltip.y - 10 }}
        >
          <div className="font-mono text-violet-400">{tooltip.tech.technique_id}</div>
          <div className="text-slate-200 font-medium mt-0.5">{tooltip.tech.name}</div>
          <div className="text-slate-400 mt-1">{tooltip.tech.detection_count} detection rule{tooltip.tech.detection_count !== 1 ? 's' : ''}</div>
        </div>
      )}
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function MITREPage() {
  const [tactics, setTactics] = useState<Tactic[]>([])
  const [techniques, setTechniques] = useState<Technique[]>([])
  const [heatmap, setHeatmap] = useState<CoverageMatrix | null>(null)
  const [selectedTacticId, setSelectedTacticId] = useState<string | null>(null) // null = All Tactics (heatmap)
  const [selectedTechId, setSelectedTechId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [coverageOnly, setCoverageOnly] = useState(false)
  const [gapsOnly, setGapsOnly] = useState(false)
  const [loadingTactics, setLoadingTactics] = useState(true)
  const [loadingTechniques, setLoadingTechniques] = useState(false)
  const [loadingHeatmap, setLoadingHeatmap] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const searchTimeout = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ── Load tactics on mount
  const loadTactics = useCallback(async (silent = false) => {
    if (!silent) setLoadingTactics(true)
    else setIsRefreshing(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/threat-intel/mitre/tactics`)
      if (res.ok) {
        const data = (await res.json()) as { tactics: Tactic[] }
        setTactics(data.tactics ?? [])
      }
    } catch {
      // ignore
    } finally {
      setLoadingTactics(false)
      setIsRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void loadTactics()
  }, [loadTactics])

  // ── Load heatmap on All Tactics view
  const loadHeatmap = useCallback(async () => {
    if (heatmap) return
    setLoadingHeatmap(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/threat-intel/mitre/coverage-matrix`)
      if (res.ok) {
        const data = (await res.json()) as CoverageMatrix
        setHeatmap(data)
      }
    } catch {
      // ignore
    } finally {
      setLoadingHeatmap(false)
    }
  }, [heatmap])

  useEffect(() => {
    if (selectedTacticId === null) {
      void loadHeatmap()
    }
  }, [selectedTacticId, loadHeatmap])

  // ── Load techniques for selected tactic
  const loadTechniques = useCallback(
    async (tacticId: string, searchQuery = '') => {
      setLoadingTechniques(true)
      setTechniques([])
      try {
        const tactic = tactics.find((t) => t.id === tacticId)
        const params = new URLSearchParams({ limit: '500' })
        if (tactic) params.set('tactic_id', tactic.slug)
        if (searchQuery) params.set('search', searchQuery)
        const res = await authFetch(`${API_BASE}/api/v2/threat-intel/mitre/techniques?${params}`)
        if (res.ok) {
          const data = (await res.json()) as { techniques: Technique[] }
          setTechniques(data.techniques ?? [])
        }
      } catch {
        // ignore
      } finally {
        setLoadingTechniques(false)
      }
    },
    [tactics]
  )

  useEffect(() => {
    if (selectedTacticId !== null && tactics.length > 0) {
      void loadTechniques(selectedTacticId, search)
    }
  }, [selectedTacticId, tactics, loadTechniques]) // search handled by debounce below

  // ── Debounced search
  const handleSearch = (val: string) => {
    setSearch(val)
    if (searchTimeout.current) clearTimeout(searchTimeout.current)
    if (selectedTacticId !== null) {
      searchTimeout.current = setTimeout(() => {
        void loadTechniques(selectedTacticId, val)
      }, 300)
    }
  }

  // ── Toggle helpers
  const handleCoverageOnly = () => {
    setCoverageOnly((v) => !v)
    if (!coverageOnly) setGapsOnly(false)
  }
  const handleGapsOnly = () => {
    setGapsOnly((v) => !v)
    if (!gapsOnly) setCoverageOnly(false)
  }

  // ── Filtered techniques
  const displayedTechniques = techniques.filter((t) => {
    if (coverageOnly && !t.has_coverage) return false
    if (gapsOnly && t.has_coverage) return false
    return true
  })

  // ── Export
  const handleExport = () => {
    const data = selectedTacticId === null ? heatmap : { techniques: displayedTechniques }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mitre-coverage-${selectedTacticId ?? 'all'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const selectedTactic = tactics.find((t) => t.id === selectedTacticId) ?? null

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* ── Left sidebar ─────────────────────────────────────────────────── */}
      <aside className="w-[280px] shrink-0 flex flex-col border-r border-slate-700/60 bg-slate-900/40 overflow-hidden">
        {/* Sidebar header */}
        <div className="px-4 py-3.5 border-b border-slate-700/60">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-violet-400" />
              <span className="text-sm font-semibold text-slate-200">ATT&CK Tactics</span>
            </div>
            <button
              onClick={() => void loadTactics(true)}
              disabled={isRefreshing}
              className="p-1 rounded text-slate-500 hover:text-slate-300 transition-colors"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
            </button>
          </div>
          {tactics.length > 0 && (
            <p className="text-[11px] text-slate-500 mt-1">
              {tactics.reduce((a, t) => a + t.covered_count, 0)}/
              {tactics.reduce((a, t) => a + t.technique_count, 0)} techniques covered
            </p>
          )}
        </div>

        {/* Tactic list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1">
          {/* All Tactics pill */}
          <button
            onClick={() => {
              setSelectedTacticId(null)
              setSelectedTechId(null)
              setSearch('')
            }}
            className={cn(
              'w-full text-left rounded-lg px-3 py-2.5 flex items-center gap-2 transition-colors border text-sm font-medium',
              selectedTacticId === null
                ? 'bg-violet-600/20 text-violet-300 border-violet-600/40'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border-transparent'
            )}
          >
            <Grid3X3 className="h-4 w-4 shrink-0" />
            All Tactics — Heatmap
          </button>

          {loadingTactics
            ? [...Array(8)].map((_, i) => <Skeleton key={i} className="h-16 w-full" />)
            : tactics.map((tactic) => (
                <TacticPill
                  key={tactic.id}
                  tactic={tactic}
                  isActive={selectedTacticId === tactic.id}
                  onClick={() => {
                    setSelectedTacticId(tactic.id)
                    setSelectedTechId(null)
                    setSearch('')
                  }}
                />
              ))}
        </div>
      </aside>

      {/* ── Main area ──────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-slate-700/60 bg-slate-900/20 shrink-0 flex-wrap">
          <div className="relative flex-1 min-w-[180px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search techniques…"
              value={search}
              onChange={(e) => handleSearch(e.target.value)}
              disabled={selectedTacticId === null}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/60 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-violet-600/60 disabled:opacity-40"
            />
          </div>

          <button
            onClick={handleCoverageOnly}
            disabled={selectedTacticId === null}
            className={cn(
              'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors disabled:opacity-40',
              coverageOnly
                ? 'bg-emerald-700/20 text-emerald-400 border-emerald-700/40'
                : 'text-slate-400 border-slate-700/60 hover:text-slate-200 hover:border-slate-600'
            )}
          >
            <Shield className="h-3.5 w-3.5" />
            Coverage Only
          </button>

          <button
            onClick={handleGapsOnly}
            disabled={selectedTacticId === null}
            className={cn(
              'flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors disabled:opacity-40',
              gapsOnly
                ? 'bg-red-900/20 text-red-400 border-red-800/40'
                : 'text-slate-400 border-slate-700/60 hover:text-slate-200 hover:border-slate-600'
            )}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            Gaps Only
          </button>

          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium text-slate-400 border border-slate-700/60 hover:text-slate-200 hover:border-slate-600 transition-colors"
          >
            <Download className="h-3.5 w-3.5" />
            Export
          </button>

          {/* Page title */}
          <div className="ml-auto flex items-center gap-2 text-slate-400 text-sm">
            <Target className="h-4 w-4 text-violet-400" />
            <span className="font-semibold text-slate-200">
              {selectedTactic ? selectedTactic.name : 'MITRE ATT&CK Navigator'}
            </span>
            {selectedTactic && (
              <span className="text-[11px] text-slate-500">
                {displayedTechniques.length} technique{displayedTechniques.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>

        {/* Content area */}
        <div className="flex-1 flex overflow-hidden">
          {/* Grid / Heatmap */}
          <div
            className={cn(
              'flex-1 overflow-y-auto p-5 transition-all',
              selectedTechId ? 'mr-0' : ''
            )}
          >
            {/* Heatmap view */}
            {selectedTacticId === null && (
              <div>
                {loadingHeatmap ? (
                  <div className="space-y-3">
                    <Skeleton className="h-6 w-48" />
                    <Skeleton className="h-64 w-full" />
                  </div>
                ) : heatmap ? (
                  <div>
                    {/* Summary stats */}
                    <div className="grid grid-cols-3 gap-4 mb-6">
                      <div className="rounded-lg border border-slate-700/60 bg-slate-800/30 px-4 py-3">
                        <p className="text-xs text-slate-500 uppercase tracking-wide">Total Techniques</p>
                        <p className="text-2xl font-bold text-slate-200 mt-1">{heatmap.total_techniques}</p>
                      </div>
                      <div className="rounded-lg border border-emerald-700/40 bg-emerald-900/10 px-4 py-3">
                        <p className="text-xs text-emerald-500 uppercase tracking-wide">Covered</p>
                        <p className="text-2xl font-bold text-emerald-400 mt-1">{heatmap.total_covered}</p>
                      </div>
                      <div className="rounded-lg border border-violet-600/40 bg-violet-900/10 px-4 py-3">
                        <p className="text-xs text-violet-400 uppercase tracking-wide">Overall Coverage</p>
                        <p className="text-2xl font-bold text-violet-300 mt-1">{heatmap.overall_coverage_pct.toFixed(1)}%</p>
                      </div>
                    </div>
                    <HeatmapView
                      matrix={heatmap.matrix}
                      onTechniqueClick={(id) => {
                        setSelectedTechId(id)
                        // Switch to appropriate tactic
                        const tech = heatmap.matrix
                          .flatMap((m) => m.techniques.map((t) => ({ ...t, tactic_id: m.tactic_id })))
                          .find((t) => t.technique_id === id)
                        if (tech) setSelectedTacticId(tech.tactic_id)
                      }}
                    />
                  </div>
                ) : (
                  <p className="text-sm text-slate-500 py-10 text-center">No heatmap data available. Seed MITRE data first.</p>
                )}
              </div>
            )}

            {/* Technique grid */}
            {selectedTacticId !== null && (
              <div>
                {loadingTechniques ? (
                  <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
                    {[...Array(12)].map((_, i) => <Skeleton key={i} className="h-28" />)}
                  </div>
                ) : displayedTechniques.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-20 text-center">
                    <Target className="h-10 w-10 text-slate-700 mb-3" />
                    <p className="text-sm text-slate-500">No techniques found.</p>
                    {(coverageOnly || gapsOnly || search) && (
                      <p className="text-xs text-slate-600 mt-1">Try clearing the filters.</p>
                    )}
                  </div>
                ) : (
                  <>
                    {/* Sub-technique separator */}
                    {displayedTechniques.some((t) => !t.is_subtechnique) && (
                      <>
                        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                          Techniques
                        </h3>
                        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3 mb-6">
                          {displayedTechniques
                            .filter((t) => !t.is_subtechnique)
                            .map((tech) => (
                              <TechniqueCard
                                key={tech.technique_id}
                                tech={tech}
                                isSelected={selectedTechId === tech.technique_id}
                                onClick={() =>
                                  setSelectedTechId(
                                    selectedTechId === tech.technique_id ? null : tech.technique_id
                                  )
                                }
                              />
                            ))}
                        </div>
                      </>
                    )}
                    {displayedTechniques.some((t) => t.is_subtechnique) && (
                      <>
                        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3 mt-2">
                          Sub-Techniques
                        </h3>
                        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
                          {displayedTechniques
                            .filter((t) => t.is_subtechnique)
                            .map((tech) => (
                              <TechniqueCard
                                key={tech.technique_id}
                                tech={tech}
                                isSelected={selectedTechId === tech.technique_id}
                                onClick={() =>
                                  setSelectedTechId(
                                    selectedTechId === tech.technique_id ? null : tech.technique_id
                                  )
                                }
                              />
                            ))}
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
            )}
          </div>

          {/* Detail panel — slide in from right */}
          {selectedTechId && (
            <div className="w-[360px] shrink-0 border-l border-slate-700/60 bg-slate-900/60 overflow-hidden flex flex-col">
              <DetailPanel
                techniqueId={selectedTechId}
                onClose={() => setSelectedTechId(null)}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
