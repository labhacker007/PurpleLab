'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import {
  BookMarked,
  Play,
  Trash2,
  RefreshCw,
  Loader2,
  AlertCircle,
  Clock,
  ChevronRight,
  Shield,
  Target,
  Database,
  Search,
  Plus,
  Copy,
  ArrowRight,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

interface Scenario {
  id: string
  name: string
  description: string | null
  threat_actor_name: string | null
  technique_ids: string[]
  event_count: number
  use_count: number
  created_at: string
  updated_at: string
}

interface TTPTemplate {
  id: string
  technique_id: string
  tactic: string | null
  log_source: string
  severity: string
  title_template: string
  is_builtin: boolean
  hit_count: number
  created_at: string
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

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-amber-400 bg-amber-400/10 border-amber-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info: 'text-muted bg-border/40 border-border',
}

const TACTIC_COLOR: Record<string, string> = {
  'initial-access': 'bg-red-500/10 text-red-400 border-red-500/20',
  'execution': 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  'persistence': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  'privilege-escalation': 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  'defense-evasion': 'bg-lime-500/10 text-lime-400 border-lime-500/20',
  'credential-access': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  'discovery': 'bg-teal-500/10 text-teal-400 border-teal-500/20',
  'lateral-movement': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  'collection': 'bg-sky-500/10 text-sky-400 border-sky-500/20',
  'command-and-control': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  'exfiltration': 'bg-violet-500/10 text-violet-400 border-violet-500/20',
  'impact': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
}

function TacticBadge({ tactic }: { tactic: string | null }) {
  if (!tactic) return null
  const label = tactic.replace(/-/g, ' ')
  const color = TACTIC_COLOR[tactic] ?? 'bg-border/40 text-muted border-border'
  return (
    <span className={cn('inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide', color)}>
      {label}
    </span>
  )
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── Scenarios Tab ─────────────────────────────────────────────────────────────

function ScenariosTab() {
  const router = useRouter()
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [replaying, setReplaying] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/scenarios`)
      if (!res.ok) throw new Error('Failed to load scenarios')
      const data = (await res.json()) as { scenarios: Scenario[]; total: number }
      setScenarios(data.scenarios ?? [])
    } catch {
      setError('Failed to load scenarios')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleReplay(id: string) {
    setReplaying(id)
    setError(null)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/scenarios/${id}/replay`, { method: 'POST' })
      if (!res.ok) {
        const d = (await res.json()) as { detail?: string }
        throw new Error(d.detail ?? 'Replay failed')
      }
      const d = (await res.json()) as { session_id: string }
      router.push(`/sessions/${d.session_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Replay failed')
    } finally {
      setReplaying(null)
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this scenario? This cannot be undone.')) return
    setDeleting(id)
    try {
      await authFetch(`${API_BASE}/api/v2/scenarios/${id}`, { method: 'DELETE' })
      setScenarios((prev) => prev.filter((s) => s.id !== id))
    } catch {
      setError('Failed to delete scenario')
    } finally {
      setDeleting(null)
    }
  }

  const filtered = scenarios.filter((s) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      s.name.toLowerCase().includes(q) ||
      (s.threat_actor_name ?? '').toLowerCase().includes(q) ||
      s.technique_ids.some((t) => t.toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search scenarios…"
            className="pl-8 h-8 text-sm"
          />
        </div>
        <Button size="sm" variant="ghost" onClick={load} className="h-8 w-8 p-0">
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red/30 bg-red/10 px-3 py-2 text-sm text-red">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center gap-3">
          <BookMarked className="h-10 w-10 text-border" />
          <div>
            <p className="text-sm font-medium text-foreground">No saved scenarios</p>
            <p className="text-xs text-muted mt-1">
              Run a simulation session and click &quot;Save as Scenario&quot; to create replayable scenarios.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((s) => (
            <Card key={s.id} className="group border-border/60 hover:border-primary/40 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold text-foreground truncate">{s.name}</span>
                      {s.threat_actor_name && (
                        <span className="inline-flex items-center gap-1 text-[10px] rounded border border-border px-1.5 py-0.5 text-muted bg-border/20">
                          <Shield className="h-2.5 w-2.5" />
                          {s.threat_actor_name}
                        </span>
                      )}
                    </div>
                    {s.description && (
                      <p className="text-xs text-muted mt-0.5 truncate">{s.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2 flex-wrap">
                      <span className="flex items-center gap-1 text-[11px] text-muted">
                        <Target className="h-3 w-3" />
                        {s.technique_ids.length} techniques
                      </span>
                      <span className="flex items-center gap-1 text-[11px] text-muted">
                        <Database className="h-3 w-3" />
                        {s.event_count} events
                      </span>
                      <span className="flex items-center gap-1 text-[11px] text-muted">
                        <Copy className="h-3 w-3" />
                        {s.use_count}× replayed
                      </span>
                      <span className="flex items-center gap-1 text-[11px] text-muted">
                        <Clock className="h-3 w-3" />
                        {timeAgo(s.created_at)}
                      </span>
                    </div>
                    {s.technique_ids.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {s.technique_ids.slice(0, 8).map((t) => (
                          <span key={t} className="rounded bg-primary/10 border border-primary/20 px-1.5 py-0.5 text-[10px] font-mono text-primary">
                            {t}
                          </span>
                        ))}
                        {s.technique_ids.length > 8 && (
                          <span className="text-[10px] text-muted">+{s.technique_ids.length - 8}</span>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => handleReplay(s.id)}
                      disabled={replaying === s.id}
                      className="h-7 px-2.5 text-xs gap-1"
                    >
                      {replaying === s.id ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Play className="h-3 w-3" />
                      )}
                      Replay
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleDelete(s.id)}
                      disabled={deleting === s.id}
                      className="h-7 w-7 p-0 text-muted hover:text-red"
                    >
                      {deleting === s.id ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Trash2 className="h-3.5 w-3.5" />
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── TTP Library Tab ───────────────────────────────────────────────────────────

function TTPLibraryTab() {
  const [templates, setTemplates] = useState<TTPTemplate[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/ttp-library`)
      if (!res.ok) throw new Error('Failed to load library')
      const data = (await res.json()) as { templates: TTPTemplate[]; total: number }
      setTemplates(data.templates ?? [])
    } catch {
      setError('Failed to load TTP library')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleDelete(id: string) {
    if (!confirm('Delete this template?')) return
    setDeleting(id)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/ttp-library/${id}`, { method: 'DELETE' })
      if (!res.ok) {
        const d = (await res.json()) as { detail?: string }
        throw new Error(d.detail ?? 'Delete failed')
      }
      setTemplates((prev) => prev.filter((t) => t.id !== id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed')
    } finally {
      setDeleting(null)
    }
  }

  const tactics = [...new Set(templates.map((t) => t.tactic).filter(Boolean))] as string[]

  const filtered = templates.filter((t) => {
    if (tacticFilter && t.tactic !== tacticFilter) return false
    if (!search) return true
    const q = search.toLowerCase()
    return (
      t.technique_id.toLowerCase().includes(q) ||
      t.title_template.toLowerCase().includes(q) ||
      (t.tactic ?? '').toLowerCase().includes(q)
    )
  })

  // Group by technique
  const grouped: Record<string, TTPTemplate[]> = {}
  for (const t of filtered) {
    if (!grouped[t.technique_id]) grouped[t.technique_id] = []
    grouped[t.technique_id].push(t)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by technique, title…"
            className="pl-8 h-8 text-sm"
          />
        </div>
        <select
          value={tacticFilter}
          onChange={(e) => setTacticFilter(e.target.value)}
          className="h-8 rounded-md border border-border bg-card px-2 text-xs text-foreground"
        >
          <option value="">All Tactics</option>
          {tactics.map((t) => (
            <option key={t} value={t}>{t.replace(/-/g, ' ')}</option>
          ))}
        </select>
        <Button size="sm" variant="ghost" onClick={load} className="h-8 w-8 p-0">
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
        <span className="text-xs text-muted ml-auto">{templates.length} templates</span>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red/30 bg-red/10 px-3 py-2 text-sm text-red">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-14" />)}
        </div>
      ) : Object.keys(grouped).length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center gap-3">
          <Database className="h-10 w-10 text-border" />
          <div>
            <p className="text-sm font-medium text-foreground">TTP library is empty</p>
            <p className="text-xs text-muted mt-1">
              Run a simulation to seed 43 built-in templates, or the library auto-seeds on first use.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          {Object.entries(grouped).map(([techId, items]) => {
            const isOpen = expanded === techId
            const tactic = items[0]?.tactic
            return (
              <Card key={techId} className="border-border/60">
                <button
                  className="w-full text-left p-3 flex items-center gap-3 hover:bg-muted/30 transition-colors"
                  onClick={() => setExpanded(isOpen ? null : techId)}
                >
                  <span className="font-mono text-xs font-semibold text-primary w-20 shrink-0">{techId}</span>
                  <TacticBadge tactic={tactic} />
                  <span className="text-xs text-muted ml-auto">{items.length} template{items.length > 1 ? 's' : ''}</span>
                  <ChevronRight className={cn('h-4 w-4 text-muted transition-transform', isOpen && 'rotate-90')} />
                </button>
                {isOpen && (
                  <div className="border-t border-border/40">
                    {items.map((tmpl) => (
                      <div key={tmpl.id} className="px-4 py-2.5 flex items-start justify-between gap-3 border-b border-border/20 last:border-0 hover:bg-muted/20">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-foreground font-medium truncate">{tmpl.title_template}</p>
                          <div className="flex items-center gap-2 mt-1 flex-wrap">
                            <span className="text-[10px] text-muted">{tmpl.log_source}</span>
                            <span className={cn('rounded border px-1 py-0.5 text-[10px] font-medium', SEVERITY_COLOR[tmpl.severity] ?? SEVERITY_COLOR.info)}>
                              {tmpl.severity}
                            </span>
                            {tmpl.is_builtin ? (
                              <span className="text-[10px] text-muted bg-border/30 rounded px-1 py-0.5">built-in</span>
                            ) : (
                              <span className="text-[10px] text-primary bg-primary/10 rounded px-1 py-0.5">custom</span>
                            )}
                            <span className="text-[10px] text-muted">{tmpl.hit_count}× used</span>
                          </div>
                        </div>
                        {!tmpl.is_builtin && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDelete(tmpl.id)}
                            disabled={deleting === tmpl.id}
                            className="h-6 w-6 p-0 shrink-0 text-muted hover:text-red"
                          >
                            {deleting === tmpl.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Trash2 className="h-3 w-3" />
                            )}
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Page ──────────────────────────────────────────────────────────────────────

type Tab = 'scenarios' | 'library'

export default function ScenariosPage() {
  const [tab, setTab] = useState<Tab>('scenarios')

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground">Simulation Library</h1>
          <p className="text-xs text-muted mt-0.5">
            Saved scenarios for replay and the TTP behavior template cache
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="gap-1.5 text-xs"
          onClick={() => window.location.href = '/sessions'}
        >
          <Plus className="h-3.5 w-3.5" />
          New Session
          <ArrowRight className="h-3.5 w-3.5 ml-0.5" />
        </Button>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border/40">
        {(
          [
            { id: 'scenarios', label: 'Saved Scenarios', icon: BookMarked },
            { id: 'library', label: 'TTP Template Cache', icon: Database },
          ] as { id: Tab; label: string; icon: React.FC<{ className?: string }> }[]
        ).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
              tab === id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted hover:text-foreground'
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      {tab === 'scenarios' ? <ScenariosTab /> : <TTPLibraryTab />}
    </div>
  )
}
