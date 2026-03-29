'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import {
  Database,
  RefreshCw,
  Play,
  Plus,
  Eye,
  Trash2,
  TestTube2,
  X,
  Loader2,
  Zap,
  Check,
  AlertCircle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface Generator {
  id: string
  name: string
  category: string
  description: string
  supported_fields: string[]
  sample_event: Record<string, unknown> | null
}

interface LogSourceConfig {
  id: string
  name: string
  source_type: string
  schema_definition: Record<string, unknown>
  sample_event: Record<string, unknown>
  description: string
  created_at: string
}

interface AttackChain {
  id: string
  name: string
  description: string
  threat_actor: string | null
  stage_count: number
  mitre_techniques: string[]
}

// ─── Category config ───────────────────────────────────────────────────────────

const CATEGORY_META: Record<string, { label: string; color: string; accent: string }> = {
  siem:     { label: 'SIEM',     color: 'bg-violet-500/15 text-violet-400 border-violet-500/30', accent: 'bg-violet-500' },
  edr:      { label: 'EDR',      color: 'bg-red-500/15 text-red-400 border-red-500/30',          accent: 'bg-red-500' },
  cloud:    { label: 'Cloud',    color: 'bg-sky-500/15 text-sky-400 border-sky-500/30',           accent: 'bg-sky-500' },
  identity: { label: 'Identity', color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', accent: 'bg-emerald-500' },
  email:    { label: 'Email',    color: 'bg-amber-500/15 text-amber-400 border-amber-500/30',     accent: 'bg-amber-500' },
  itsm:     { label: 'ITSM',     color: 'bg-orange-500/15 text-orange-400 border-orange-500/30', accent: 'bg-orange-500' },
}

function CategoryBadge({ category }: { category: string }) {
  const meta = CATEGORY_META[category] ?? { label: category, color: 'bg-slate-700 text-slate-300 border-slate-600', accent: 'bg-slate-500' }
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide', meta.color)}>
      {meta.label}
    </span>
  )
}

function CategoryDot({ category }: { category: string }) {
  const meta = CATEGORY_META[category] ?? { accent: 'bg-slate-500' }
  return <div className={cn('h-2 w-2 rounded-full shrink-0', meta.accent)} />
}

// ─── JSON viewer ───────────────────────────────────────────────────────────────

function JsonBlock({ data }: { data: unknown }) {
  return (
    <pre className="text-xs font-mono text-slate-300 bg-slate-950 rounded-lg p-4 overflow-auto max-h-96 border border-slate-800 whitespace-pre-wrap break-all">
      {JSON.stringify(data, null, 2)}
    </pre>
  )
}

// ─── Modal wrapper ─────────────────────────────────────────────────────────────

function Modal({ open, onClose, title, children }: {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl mx-4 flex flex-col max-h-[85vh]">
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4 shrink-0">
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">
          {children}
        </div>
      </div>
    </div>
  )
}

// ─── Drawer wrapper ────────────────────────────────────────────────────────────

function Drawer({ open, onClose, title, children }: {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col h-full">
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-4 shrink-0">
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">
          {children}
        </div>
      </div>
    </div>
  )
}

// ─── Generator Card ────────────────────────────────────────────────────────────

function GeneratorCard({
  generator,
  selected,
  onToggle,
  onViewSample,
}: {
  generator: Generator
  selected: boolean
  onToggle: () => void
  onViewSample: () => void
}) {
  return (
    <div
      className={cn(
        'relative rounded-xl border p-4 cursor-pointer transition-all duration-150 group',
        selected
          ? 'border-violet-500 bg-violet-500/10 shadow-lg shadow-violet-500/10'
          : 'border-slate-700 bg-slate-800/50 hover:border-slate-600 hover:bg-slate-800'
      )}
      onClick={onToggle}
    >
      {/* Selection indicator */}
      {selected && (
        <div className="absolute top-3 right-3 flex h-5 w-5 items-center justify-center rounded-full bg-violet-500">
          <Check className="h-3 w-3 text-white" />
        </div>
      )}

      {/* Header */}
      <div className="flex items-start gap-3 mb-3">
        <div className={cn(
          'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-white text-[10px] font-bold',
          CATEGORY_META[generator.category]?.accent ?? 'bg-slate-600'
        )}>
          {generator.name.slice(0, 2).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-white truncate pr-5">{generator.name}</p>
          <CategoryBadge category={generator.category} />
        </div>
      </div>

      {/* Description */}
      <p className="text-xs text-slate-400 mb-3 line-clamp-2">{generator.description}</p>

      {/* Field count + sample button */}
      <div className="flex items-center justify-between">
        <span className="text-[10px] text-slate-500">
          {generator.supported_fields.length} fields
        </span>
        <button
          className="text-[10px] text-violet-400 hover:text-violet-300 transition-colors font-medium flex items-center gap-1"
          onClick={(e) => { e.stopPropagation(); onViewSample() }}
        >
          <Eye className="h-3 w-3" />
          View Sample
        </button>
      </div>
    </div>
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-slate-800', className)} />
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function LogSourcesPage() {
  const router = useRouter()

  // Data state
  const [generators, setGenerators] = useState<Generator[]>([])
  const [logSources, setLogSources] = useState<LogSourceConfig[]>([])
  const [attackChains, setAttackChains] = useState<AttackChain[]>([])
  const [loadingGenerators, setLoadingGenerators] = useState(true)
  const [loadingSources, setLoadingSources] = useState(true)

  // UI state
  const [selectedGenerators, setSelectedGenerators] = useState<Set<string>>(new Set())
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [sampleModal, setSampleModal] = useState<{ open: boolean; generator: Generator | null }>({ open: false, generator: null })
  const [testModal, setTestModal] = useState<{ open: boolean; sourceId: string | null; events: unknown[] | null; loading: boolean }>({
    open: false, sourceId: null, events: null, loading: false
  })
  const [simModal, setSimModal] = useState(false)
  const [addDrawer, setAddDrawer] = useState(false)

  // Simulation form state
  const [simTargetUrl, setSimTargetUrl] = useState('')
  const [simEventRate, setSimEventRate] = useState(5)
  const [simStarting, setSimStarting] = useState(false)
  const [simError, setSimError] = useState<string | null>(null)

  // Add source form state
  const [addForm, setAddForm] = useState({ name: '', source_type: '', description: '' })
  const [addSaving, setAddSaving] = useState(false)
  const [addError, setAddError] = useState<string | null>(null)

  // ── Fetch generators ────────────────────────────────────────────────────────

  const fetchGenerators = useCallback(async () => {
    setLoadingGenerators(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/log-sources/generators`)
      if (res.ok) {
        const data = (await res.json()) as { generators: Generator[] }
        setGenerators(data.generators)
      }
    } catch {
      // silently handle
    } finally {
      setLoadingGenerators(false)
    }
  }, [])

  // ── Fetch configured log sources ────────────────────────────────────────────

  const fetchLogSources = useCallback(async () => {
    setLoadingSources(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/log-sources`)
      if (res.ok) {
        const data = (await res.json()) as { log_sources: LogSourceConfig[] }
        setLogSources(data.log_sources)
      }
    } catch {
      // silently handle
    } finally {
      setLoadingSources(false)
    }
  }, [])

  // ── Fetch attack chains ─────────────────────────────────────────────────────

  const fetchAttackChains = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/v2/log-sources/attack-chains`)
      if (res.ok) {
        const data = (await res.json()) as { chains: AttackChain[] }
        setAttackChains(data.chains)
      }
    } catch {
      // silently handle
    }
  }, [])

  useEffect(() => {
    void fetchGenerators()
    void fetchLogSources()
    void fetchAttackChains()
  }, [fetchGenerators, fetchLogSources, fetchAttackChains])

  // ── Test a configured source ────────────────────────────────────────────────

  const handleTest = async (sourceId: string) => {
    setTestModal({ open: true, sourceId, events: null, loading: true })
    try {
      const res = await authFetch(`${API_BASE}/api/v2/log-sources/${sourceId}/test`, { method: 'PUT' })
      if (res.ok) {
        const data = (await res.json()) as { events: unknown[] }
        setTestModal(prev => ({ ...prev, events: data.events, loading: false }))
      } else {
        setTestModal(prev => ({ ...prev, events: [], loading: false }))
      }
    } catch {
      setTestModal(prev => ({ ...prev, events: [], loading: false }))
    }
  }

  // ── Delete a configured source ──────────────────────────────────────────────

  const handleDelete = async (sourceId: string) => {
    if (!window.confirm('Delete this log source configuration?')) return
    try {
      await authFetch(`${API_BASE}/api/v2/log-sources/${sourceId}`, { method: 'DELETE' })
      setLogSources(prev => prev.filter(s => s.id !== sourceId))
    } catch {
      // ignore
    }
  }

  // ── Add source ──────────────────────────────────────────────────────────────

  const handleAddSource = async () => {
    if (!addForm.name || !addForm.source_type) {
      setAddError('Name and source type are required.')
      return
    }
    setAddSaving(true)
    setAddError(null)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/log-sources`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: addForm.name,
          source_type: addForm.source_type,
          description: addForm.description,
          enabled: true,
        }),
      })
      if (res.ok) {
        const newSource = (await res.json()) as LogSourceConfig
        setLogSources(prev => [newSource, ...prev])
        setAddDrawer(false)
        setAddForm({ name: '', source_type: '', description: '' })
      } else {
        const err = (await res.json()) as { detail?: string }
        setAddError(err.detail ?? 'Failed to create log source.')
      }
    } catch (e: unknown) {
      setAddError(e instanceof Error ? e.message : 'Unexpected error')
    } finally {
      setAddSaving(false)
    }
  }

  // ── Start simulation ────────────────────────────────────────────────────────

  const handleStartSimulation = async () => {
    if (selectedGenerators.size === 0) {
      setSimError('Select at least one generator.')
      return
    }
    setSimStarting(true)
    setSimError(null)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: `Log Sources Simulation — ${new Date().toLocaleString()}`,
          config: {
            generators: Array.from(selectedGenerators),
            events_per_minute: simEventRate,
            target_url: simTargetUrl || undefined,
          },
        }),
      })
      if (res.ok) {
        const session = (await res.json()) as { id: string }
        router.push(`/sessions/${session.id}`)
      } else {
        const err = (await res.json()) as { detail?: string }
        setSimError(err.detail ?? 'Failed to create session.')
      }
    } catch (e: unknown) {
      setSimError(e instanceof Error ? e.message : 'Unexpected error')
    } finally {
      setSimStarting(false)
    }
  }

  // ── Filter generators ───────────────────────────────────────────────────────

  const categories = ['all', ...Array.from(new Set(generators.map(g => g.category))).sort()]
  const visibleGenerators = categoryFilter === 'all'
    ? generators
    : generators.filter(g => g.category === categoryFilter)

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Database className="h-5 w-5 text-violet-400" />
            Log Sources
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage generator catalog, configured sources, and simulation quick-start
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => { void fetchGenerators(); void fetchLogSources() }}
            className="gap-1.5"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
          <Button
            size="sm"
            className="gap-1.5 bg-violet-600 hover:bg-violet-500 text-white"
            disabled={selectedGenerators.size === 0}
            onClick={() => { setSimError(null); setSimModal(true) }}
          >
            <Zap className="h-3.5 w-3.5" />
            Start Simulation
            {selectedGenerators.size > 0 && (
              <span className="ml-1 rounded-full bg-white/20 px-1.5 py-0.5 text-[10px] font-bold">
                {selectedGenerators.size}
              </span>
            )}
          </Button>
        </div>
      </div>

      {/* ── Section 1: Generator Catalog ──────────────────────────────────── */}

      <Card className="bg-slate-900 border-slate-700">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold text-white">Generator Catalog</CardTitle>
              <p className="text-xs text-slate-400 mt-0.5">
                Select generators to include in a simulation. Click a card to toggle.
              </p>
            </div>
            {selectedGenerators.size > 0 && (
              <button
                className="text-xs text-slate-400 hover:text-white transition-colors"
                onClick={() => setSelectedGenerators(new Set())}
              >
                Clear selection
              </button>
            )}
          </div>

          {/* Category filter pills */}
          <div className="flex items-center gap-2 mt-3 flex-wrap">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={cn(
                  'rounded-full px-3 py-1 text-xs font-medium border transition-colors capitalize',
                  categoryFilter === cat
                    ? 'bg-violet-600 border-violet-500 text-white'
                    : 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-300 bg-slate-800/50'
                )}
              >
                {cat === 'all' ? 'All' : (CATEGORY_META[cat]?.label ?? cat)}
              </button>
            ))}
          </div>
        </CardHeader>

        <CardContent>
          {loadingGenerators ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-36" />)}
            </div>
          ) : visibleGenerators.length === 0 ? (
            <p className="text-sm text-slate-500 py-8 text-center">No generators available</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {visibleGenerators.map(gen => (
                <GeneratorCard
                  key={gen.id}
                  generator={gen}
                  selected={selectedGenerators.has(gen.id)}
                  onToggle={() => {
                    setSelectedGenerators(prev => {
                      const next = new Set(prev)
                      next.has(gen.id) ? next.delete(gen.id) : next.add(gen.id)
                      return next
                    })
                  }}
                  onViewSample={() => setSampleModal({ open: true, generator: gen })}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Section 2: Configured Log Sources ─────────────────────────────── */}

      <Card className="bg-slate-900 border-slate-700">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold text-white">Configured Log Sources</CardTitle>
              <p className="text-xs text-slate-400 mt-0.5">Saved log source schema configurations</p>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => { setAddError(null); setAddDrawer(true) }}
            >
              <Plus className="h-3.5 w-3.5" />
              Add Source
            </Button>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {loadingSources ? (
            <div className="p-5 space-y-2">
              {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-12" />)}
            </div>
          ) : logSources.length === 0 ? (
            <div className="py-12 text-center">
              <Database className="h-8 w-8 text-slate-600 mx-auto mb-3" />
              <p className="text-sm text-slate-400">No log sources configured yet</p>
              <p className="text-xs text-slate-500 mt-1">Click "Add Source" to create one</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-700/50">
              {/* Table header */}
              <div className="grid grid-cols-[1fr_120px_140px_120px] gap-4 px-5 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                <span>Name</span>
                <span>Type</span>
                <span>Created</span>
                <span className="text-right">Actions</span>
              </div>
              {logSources.map(source => (
                <div key={source.id} className="grid grid-cols-[1fr_120px_140px_120px] gap-4 items-center px-5 py-3 hover:bg-slate-800/30 transition-colors">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-white truncate">{source.name}</p>
                    {source.description && (
                      <p className="text-xs text-slate-500 truncate mt-0.5">{source.description}</p>
                    )}
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5">
                      <CategoryDot category={
                        CATEGORY_META[
                          Object.keys(CATEGORY_META).find(k =>
                            source.source_type.toLowerCase().includes(k)
                          ) ?? ''
                        ] ? Object.keys(CATEGORY_META).find(k => source.source_type.toLowerCase().includes(k)) ?? source.source_type : source.source_type
                      } />
                      <span className="text-xs text-slate-300 font-mono">{source.source_type}</span>
                    </div>
                  </div>
                  <span className="text-xs text-slate-400">
                    {source.created_at ? new Date(source.created_at).toLocaleDateString() : '—'}
                  </span>
                  <div className="flex items-center justify-end gap-1">
                    <button
                      title="Test — generates 3 sample events"
                      className="flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-emerald-400/10 transition-colors"
                      onClick={() => void handleTest(source.id)}
                    >
                      <TestTube2 className="h-3.5 w-3.5" />
                    </button>
                    <button
                      title="Delete"
                      className="flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-400/10 transition-colors"
                      onClick={() => void handleDelete(source.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── Attack Chains summary ──────────────────────────────────────────── */}

      {attackChains.length > 0 && (
        <Card className="bg-slate-900 border-slate-700">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold text-white">Available Attack Chains</CardTitle>
            <p className="text-xs text-slate-400">Pre-built multi-stage attack scenarios for simulation</p>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-slate-700/50">
              {attackChains.map(chain => (
                <div key={chain.id} className="flex items-center gap-4 px-5 py-3 hover:bg-slate-800/30 transition-colors">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-white">{chain.name}</p>
                      {chain.threat_actor && (
                        <Badge className="text-[10px] border border-slate-600 text-slate-400 py-0 bg-transparent">
                          {chain.threat_actor}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 truncate">{chain.description}</p>
                  </div>
                  <div className="flex items-center gap-4 shrink-0 text-xs text-slate-400">
                    <span>{chain.stage_count} stages</span>
                    <span>{chain.mitre_techniques.length} techniques</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Sample Event Modal ─────────────────────────────────────────────── */}

      <Modal
        open={sampleModal.open}
        onClose={() => setSampleModal({ open: false, generator: null })}
        title={sampleModal.generator ? `${sampleModal.generator.name} — Sample Event` : 'Sample Event'}
      >
        {sampleModal.generator && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className={cn(
                'flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-white text-[10px] font-bold',
                CATEGORY_META[sampleModal.generator.category]?.accent ?? 'bg-slate-600'
              )}>
                {sampleModal.generator.name.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <p className="text-sm font-semibold text-white">{sampleModal.generator.name}</p>
                <CategoryBadge category={sampleModal.generator.category} />
              </div>
            </div>

            {sampleModal.generator.supported_fields.length > 0 && (
              <div>
                <p className="text-xs font-medium text-slate-400 mb-2">Supported Fields</p>
                <div className="flex flex-wrap gap-1.5">
                  {sampleModal.generator.supported_fields.map(f => (
                    <span key={f} className="rounded-md bg-slate-800 border border-slate-700 px-2 py-0.5 text-[10px] font-mono text-slate-300">
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div>
              <p className="text-xs font-medium text-slate-400 mb-2">Live Sample Event</p>
              {sampleModal.generator.sample_event ? (
                <JsonBlock data={sampleModal.generator.sample_event} />
              ) : (
                <p className="text-xs text-slate-500 italic">No sample available</p>
              )}
            </div>
          </div>
        )}
      </Modal>

      {/* ── Test Events Modal ──────────────────────────────────────────────── */}

      <Modal
        open={testModal.open}
        onClose={() => setTestModal({ open: false, sourceId: null, events: null, loading: false })}
        title="Test Generation — 3 Sample Events"
      >
        {testModal.loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-violet-400" />
            <span className="ml-2 text-sm text-slate-400">Generating events…</span>
          </div>
        ) : testModal.events && testModal.events.length > 0 ? (
          <div className="space-y-4">
            {testModal.events.map((ev, i) => (
              <div key={i}>
                <p className="text-[10px] font-semibold text-slate-500 uppercase mb-1">Event {i + 1}</p>
                <JsonBlock data={ev} />
              </div>
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 gap-2">
            <AlertCircle className="h-6 w-6 text-slate-500" />
            <p className="text-sm text-slate-400">No events generated</p>
          </div>
        )}
      </Modal>

      {/* ── Simulation Quick-Start Modal ───────────────────────────────────── */}

      <Modal
        open={simModal}
        onClose={() => setSimModal(false)}
        title="Start Simulation"
      >
        <div className="space-y-5">
          {/* Selected generators list */}
          <div>
            <p className="text-xs font-medium text-slate-400 mb-2">
              Selected Generators ({selectedGenerators.size})
            </p>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {generators
                .filter(g => selectedGenerators.has(g.id))
                .map(g => (
                  <div key={g.id} className="flex items-center gap-2.5 rounded-lg bg-slate-800 border border-slate-700 px-3 py-2">
                    <div className={cn('h-5 w-5 rounded-md text-white flex items-center justify-center text-[8px] font-bold shrink-0', CATEGORY_META[g.category]?.accent ?? 'bg-slate-600')}>
                      {g.name.slice(0, 2).toUpperCase()}
                    </div>
                    <span className="text-xs text-white">{g.name}</span>
                    <CategoryBadge category={g.category} />
                    <button
                      className="ml-auto text-slate-500 hover:text-slate-300"
                      onClick={() => setSelectedGenerators(prev => { const n = new Set(prev); n.delete(g.id); return n })}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
            </div>
          </div>

          {/* Event rate slider */}
          <div>
            <label className="text-xs font-medium text-slate-400 block mb-2">
              Event Rate: <span className="text-white font-semibold">{simEventRate}</span> events/min
            </label>
            <input
              type="range"
              min={1}
              max={60}
              value={simEventRate}
              onChange={e => setSimEventRate(Number(e.target.value))}
              className="w-full accent-violet-500"
            />
            <div className="flex justify-between text-[10px] text-slate-500 mt-1">
              <span>1/min</span>
              <span>60/min</span>
            </div>
          </div>

          {/* Target URL */}
          <div>
            <label className="text-xs font-medium text-slate-400 block mb-1.5">
              Target URL <span className="text-slate-600">(optional — SIEM webhook)</span>
            </label>
            <Input
              placeholder="https://siem.corp.example.com/webhook/..."
              value={simTargetUrl}
              onChange={e => setSimTargetUrl(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-600 text-sm"
            />
          </div>

          {simError && (
            <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2">
              <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
              <p className="text-xs text-red-400">{simError}</p>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <Button
              variant="outline"
              className="flex-1"
              onClick={() => setSimModal(false)}
            >
              Cancel
            </Button>
            <Button
              className="flex-1 bg-violet-600 hover:bg-violet-500 text-white gap-1.5"
              disabled={simStarting || selectedGenerators.size === 0}
              onClick={() => void handleStartSimulation()}
            >
              {simStarting ? (
                <><Loader2 className="h-3.5 w-3.5 animate-spin" />Starting…</>
              ) : (
                <><Play className="h-3.5 w-3.5" />Launch Session</>
              )}
            </Button>
          </div>
        </div>
      </Modal>

      {/* ── Add Source Drawer ──────────────────────────────────────────────── */}

      <Drawer
        open={addDrawer}
        onClose={() => setAddDrawer(false)}
        title="Add Log Source"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Create a named log source configuration. Choose a source type matching one of the available generators.
          </p>

          <div>
            <label className="text-xs font-medium text-slate-400 block mb-1.5">Name <span className="text-red-400">*</span></label>
            <Input
              placeholder="e.g. Prod CrowdStrike Falcon"
              value={addForm.name}
              onChange={e => setAddForm(f => ({ ...f, name: e.target.value }))}
              className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-600 text-sm"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-400 block mb-1.5">Source Type <span className="text-red-400">*</span></label>
            <select
              value={addForm.source_type}
              onChange={e => setAddForm(f => ({ ...f, source_type: e.target.value }))}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 text-white text-sm px-3 py-2 focus:outline-none focus:ring-1 focus:ring-violet-500"
            >
              <option value="">Select a generator type…</option>
              {generators.map(g => (
                <option key={g.id} value={g.id}>{g.name} ({g.id})</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-400 block mb-1.5">Description</label>
            <textarea
              placeholder="Optional description…"
              value={addForm.description}
              onChange={e => setAddForm(f => ({ ...f, description: e.target.value }))}
              rows={3}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 text-white text-sm px-3 py-2 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-violet-500 resize-none"
            />
          </div>

          {addError && (
            <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2">
              <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
              <p className="text-xs text-red-400">{addError}</p>
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <Button
              variant="outline"
              className="flex-1"
              onClick={() => setAddDrawer(false)}
            >
              Cancel
            </Button>
            <Button
              className="flex-1 bg-violet-600 hover:bg-violet-500 text-white gap-1.5"
              disabled={addSaving}
              onClick={() => void handleAddSource()}
            >
              {addSaving ? (
                <><Loader2 className="h-3.5 w-3.5 animate-spin" />Saving…</>
              ) : (
                <><Plus className="h-3.5 w-3.5" />Create Source</>
              )}
            </Button>
          </div>
        </div>
      </Drawer>
    </div>
  )
}
