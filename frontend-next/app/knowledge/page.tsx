'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  BookOpen,
  FileText,
  BookMarked,
  Wrench,
  Crosshair,
  Plus,
  Link2,
  Search,
  Trash2,
  RefreshCw,
  Save,
  X,
  Tag,
  ChevronRight,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

type EmbedStatus = 'pending' | 'indexed' | 'failed'
type DocType = 'procedure' | 'playbook' | 'runbook' | 'technique' | 'custom'

interface DocListItem {
  id: string
  title: string
  doc_type: DocType
  tags: string[]
  created_at: string
  embedding_status: EmbedStatus
}

interface DocDetail extends DocListItem {
  content: string
  source_url: string | null
  created_by: string | null
  updated_at: string
}

interface SemanticSearchResult {
  id: string
  title: string
  doc_type: string
  similarity_score: number
  excerpt: string
}

interface KnowledgeStats {
  total_docs: number
  indexed_docs: number
  pending_docs: number
  doc_types: Record<string, number>
}

// ─── Constants ─────────────────────────────────────────────────────────────────

const DOC_TYPES: { value: DocType | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'procedure', label: 'Procedure' },
  { value: 'playbook', label: 'Playbook' },
  { value: 'runbook', label: 'Runbook' },
  { value: 'technique', label: 'Technique' },
  { value: 'custom', label: 'Custom' },
]

const TYPE_ICON: Record<string, React.ElementType> = {
  procedure: FileText,
  playbook: BookMarked,
  runbook: Wrench,
  technique: Crosshair,
  custom: BookOpen,
}

const TYPE_COLOR: Record<string, string> = {
  procedure: 'text-blue-400',
  playbook: 'text-purple-400',
  runbook: 'text-orange-400',
  technique: 'text-red-400',
  custom: 'text-slate-400',
}

const STATUS_VARIANT: Record<EmbedStatus, 'success' | 'warning' | 'destructive'> = {
  indexed: 'success',
  pending: 'warning',
  failed: 'destructive',
}

// ─── Small helpers ─────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: KnowledgeStats | null }) {
  const cards = [
    { label: 'Total Docs', value: stats?.total_docs ?? '—' },
    { label: 'Indexed', value: stats?.indexed_docs ?? '—', accent: 'text-green-400' },
    { label: 'Pending', value: stats?.pending_docs ?? '—', accent: 'text-amber-400' },
    { label: 'Doc Types', value: stats ? Object.keys(stats.doc_types).length : '—' },
  ]
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {cards.map((c) => (
        <Card key={c.label}>
          <CardContent className="p-4">
            <p className="text-[10px] font-medium text-muted uppercase tracking-wide">{c.label}</p>
            <p className={cn('mt-1 text-2xl font-bold', c.accent ?? 'text-text')}>{c.value}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// ─── New Document Modal ────────────────────────────────────────────────────────

function NewDocModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (doc: DocDetail) => void
}) {
  const [title, setTitle] = useState('')
  const [docType, setDocType] = useState<DocType>('custom')
  const [content, setContent] = useState('')
  const [tags, setTags] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async () => {
    if (!title.trim()) { setError('Title is required'); return }
    if (!content.trim()) { setError('Content is required'); return }
    setSaving(true)
    setError('')
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: title.trim(),
          content: content.trim(),
          doc_type: docType,
          tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({})) as { detail?: string }
        throw new Error(data.detail ?? 'Failed to create document')
      }
      const doc = await res.json() as DocDetail
      onCreated(doc)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-text">New Document</h2>
          <button onClick={onClose} className="text-muted hover:text-text transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 p-5">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Title</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Document title..."
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Type</label>
            <select
              value={docType}
              onChange={(e) => setDocType(e.target.value as DocType)}
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text focus:outline-none focus:ring-1 focus:ring-primary"
            >
              {DOC_TYPES.filter((d) => d.value !== 'all').map((d) => (
                <option key={d.value} value={d.value}>{d.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Tags (comma-separated)</label>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="windows, credential, apt29..."
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Content</label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Document content..."
              rows={8}
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary resize-y"
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button size="sm" onClick={() => void handleSubmit()} disabled={saving}>
            {saving ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            Create
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Import URL Modal ──────────────────────────────────────────────────────────

function ImportURLModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (doc: DocDetail) => void
}) {
  const [url, setUrl] = useState('')
  const [title, setTitle] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const handleImport = async () => {
    if (!url.trim()) { setError('URL is required'); return }
    setSaving(true)
    setError('')
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/import-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), title: title.trim() || null }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({})) as { detail?: string }
        throw new Error(data.detail ?? 'Import failed')
      }
      const doc = await res.json() as DocDetail
      onCreated(doc)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-text">Import from URL</h2>
          <button onClick={onClose} className="text-muted hover:text-text transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-4 p-5">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">URL</label>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://attack.mitre.org/techniques/T1059/"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-muted">Title (optional)</label>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Leave blank to use URL as title"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button size="sm" onClick={() => void handleImport()} disabled={saving}>
            {saving ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Link2 className="h-3.5 w-3.5" />}
            Import
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Document Card ─────────────────────────────────────────────────────────────

function DocCard({
  doc,
  selected,
  similarityScore,
  onClick,
}: {
  doc: DocListItem
  selected: boolean
  similarityScore?: number
  onClick: () => void
}) {
  const Icon = TYPE_ICON[doc.doc_type] ?? BookOpen
  const iconColor = TYPE_COLOR[doc.doc_type] ?? 'text-slate-400'

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-lg border px-3 py-3 transition-colors',
        selected
          ? 'border-primary bg-primary/10'
          : 'border-border bg-card hover:bg-bg hover:border-border/80'
      )}
    >
      <div className="flex items-start gap-2.5">
        <Icon className={cn('mt-0.5 h-4 w-4 shrink-0', iconColor)} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-sm font-medium text-text">{doc.title}</p>
            {similarityScore !== undefined && (
              <span className="shrink-0 rounded bg-primary/20 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                {(similarityScore * 100).toFixed(0)}%
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <Badge variant={STATUS_VARIANT[doc.embedding_status]} className="text-[10px] shrink-0">
              {doc.embedding_status}
            </Badge>
            {doc.tags.slice(0, 3).map((t) => (
              <span key={t} className="rounded bg-border/60 px-1.5 py-0.5 text-[10px] text-muted">
                {t}
              </span>
            ))}
          </div>
          <p className="mt-1 text-[10px] text-muted">{fmtDate(doc.created_at)}</p>
        </div>
        <ChevronRight className={cn('mt-1 h-3.5 w-3.5 shrink-0 text-muted transition-opacity', selected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100')} />
      </div>
    </button>
  )
}

// ─── Document Editor panel ────────────────────────────────────────────────────

function DocEditor({
  doc,
  onUpdated,
  onDeleted,
}: {
  doc: DocDetail
  onUpdated: (d: DocDetail) => void
  onDeleted: (id: string) => void
}) {
  const [title, setTitle] = useState(doc.title)
  const [docType, setDocType] = useState<DocType>(doc.doc_type)
  const [tags, setTags] = useState(doc.tags.join(', '))
  const [content, setContent] = useState(doc.content)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [saveError, setSaveError] = useState('')

  // Reset when doc changes
  useEffect(() => {
    setTitle(doc.title)
    setDocType(doc.doc_type)
    setTags(doc.tags.join(', '))
    setContent(doc.content)
    setSaveError('')
    setConfirmDelete(false)
  }, [doc.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleSave = async () => {
    setSaving(true)
    setSaveError('')
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/${doc.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: title.trim(),
          content,
          doc_type: docType,
          tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({})) as { detail?: string }
        throw new Error(data.detail ?? 'Save failed')
      }
      const updated = await res.json() as DocDetail
      onUpdated(updated)
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  const handleReindex = async () => {
    setSaving(true)
    setSaveError('')
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/${doc.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: doc.content + ' ' }),
      })
      if (!res.ok) throw new Error('Re-index failed')
      const updated = await res.json() as DocDetail
      onUpdated(updated)
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Re-index failed')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!confirmDelete) { setConfirmDelete(true); return }
    setDeleting(true)
    try {
      await authFetch(`${API_BASE}/api/v2/knowledge/${doc.id}`, { method: 'DELETE' })
      onDeleted(doc.id)
    } catch {
      setSaveError('Delete failed')
    } finally {
      setDeleting(false)
      setConfirmDelete(false)
    }
  }

  const Icon = TYPE_ICON[docType] ?? BookOpen
  const iconColor = TYPE_COLOR[docType] ?? 'text-slate-400'

  return (
    <div className="flex h-full flex-col">
      {/* Title row */}
      <div className="flex items-center gap-3 border-b border-border px-5 py-4">
        <Icon className={cn('h-5 w-5 shrink-0', iconColor)} />
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="flex-1 bg-transparent text-base font-semibold text-text focus:outline-none"
          placeholder="Document title..."
        />
        <Badge variant={STATUS_VARIANT[doc.embedding_status]} className="shrink-0 text-[10px]">
          {doc.embedding_status}
        </Badge>
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted">Type</span>
          <select
            value={docType}
            onChange={(e) => setDocType(e.target.value as DocType)}
            className="rounded-md border border-border bg-bg px-2 py-1 text-xs text-text focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {DOC_TYPES.filter((d) => d.value !== 'all').map((d) => (
              <option key={d.value} value={d.value}>{d.label}</option>
            ))}
          </select>
        </div>
        <div className="flex flex-1 items-center gap-2 min-w-0">
          <Tag className="h-3.5 w-3.5 shrink-0 text-muted" />
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="tag1, tag2, tag3..."
            className="flex-1 bg-transparent text-xs text-text placeholder:text-muted focus:outline-none min-w-0"
          />
        </div>
      </div>

      {/* Content area */}
      <div className="flex-1 overflow-hidden p-5">
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          className="h-full w-full resize-none rounded-lg border border-border bg-bg p-3 font-mono text-xs text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
          rows={20}
          placeholder="Document content..."
        />
      </div>

      {/* Footer toolbar */}
      <div className="flex items-center justify-between border-t border-border px-5 py-3">
        <div className="flex items-center gap-2">
          {saveError && <span className="text-xs text-red-400">{saveError}</span>}
          {doc.source_url && (
            <a
              href={doc.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-[10px] text-muted hover:text-primary transition-colors"
            >
              <Link2 className="h-3 w-3" />
              Source
            </a>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void handleReindex()}
            disabled={saving}
            title="Reset embedding and re-index"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', saving && 'animate-spin')} />
            Re-index
          </Button>
          {confirmDelete ? (
            <>
              <span className="text-xs text-red-400">Confirm delete?</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setConfirmDelete(false)}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => void handleDelete()}
                disabled={deleting}
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </Button>
            </>
          ) : (
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleDelete()}
              className="text-red-400 hover:text-red-300 hover:border-red-400/50"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          )}
          <Button size="sm" onClick={() => void handleSave()} disabled={saving}>
            <Save className="h-3.5 w-3.5" />
            Save
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Knowledge Page ────────────────────────────────────────────────────────────

export default function KnowledgePage() {
  const [stats, setStats] = useState<KnowledgeStats | null>(null)
  const [docs, setDocs] = useState<DocListItem[]>([])
  const [selectedDoc, setSelectedDoc] = useState<DocDetail | null>(null)
  const [loadingDocs, setLoadingDocs] = useState(true)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeType, setActiveType] = useState<DocType | 'all'>('all')
  const [semanticResults, setSemanticResults] = useState<SemanticSearchResult[] | null>(null)
  const [showNewDoc, setShowNewDoc] = useState(false)
  const [showImportURL, setShowImportURL] = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const loadStats = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/stats`)
      if (res.ok) setStats(await res.json() as KnowledgeStats)
    } catch { /* silent */ }
  }, [])

  const loadDocs = useCallback(async (query = '', type: DocType | 'all' = 'all') => {
    setLoadingDocs(true)
    try {
      const params = new URLSearchParams()
      if (type !== 'all') params.set('doc_type', type)
      if (query) params.set('search', query)
      params.set('limit', '100')
      const res = await authFetch(`${API_BASE}/api/v2/knowledge?${params}`)
      if (res.ok) {
        setDocs(await res.json() as DocListItem[])
        setSemanticResults(null)
      }
    } catch { /* silent */ } finally {
      setLoadingDocs(false)
    }
  }, [])

  const doSemanticSearch = useCallback(async (query: string, type: DocType | 'all') => {
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          limit: 20,
          doc_type: type !== 'all' ? type : null,
        }),
      })
      if (res.ok) {
        const results = await res.json() as SemanticSearchResult[]
        setSemanticResults(results)
        // Build list items from semantic results for display
        setDocs(results.map((r) => ({
          id: r.id,
          title: r.title,
          doc_type: r.doc_type as DocType,
          tags: [],
          created_at: new Date().toISOString(),
          embedding_status: 'indexed' as EmbedStatus,
        })))
      }
    } catch { /* silent */ }
  }, [])

  // Initial load
  useEffect(() => {
    void loadStats()
    void loadDocs()
  }, [loadStats, loadDocs])

  // Debounced search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      if (searchQuery.trim().length >= 2) {
        void doSemanticSearch(searchQuery, activeType)
      } else {
        void loadDocs(searchQuery, activeType)
      }
    }, 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [searchQuery, activeType, doSemanticSearch, loadDocs])

  const handleSelectDoc = async (id: string) => {
    setLoadingDetail(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/knowledge/${id}`)
      if (res.ok) setSelectedDoc(await res.json() as DocDetail)
    } catch { /* silent */ } finally {
      setLoadingDetail(false)
    }
  }

  const handleDocUpdated = (updated: DocDetail) => {
    setSelectedDoc(updated)
    setDocs((prev) => prev.map((d) => d.id === updated.id ? {
      ...d,
      title: updated.title,
      doc_type: updated.doc_type,
      tags: updated.tags,
      embedding_status: updated.embedding_status,
    } : d))
    void loadStats()
  }

  const handleDocDeleted = (id: string) => {
    setDocs((prev) => prev.filter((d) => d.id !== id))
    setSelectedDoc(null)
    void loadStats()
  }

  const handleDocCreated = (doc: DocDetail) => {
    setShowNewDoc(false)
    setShowImportURL(false)
    void loadDocs(searchQuery, activeType)
    void loadStats()
    setSelectedDoc(doc)
  }

  const getSimilarityScore = (id: string) => {
    if (!semanticResults) return undefined
    return semanticResults.find((r) => r.id === id)?.similarity_score
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-hidden">
      {/* Stats */}
      <StatsBar stats={stats} />

      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-text">Knowledge Base</h1>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowImportURL(true)}>
            <Link2 className="h-3.5 w-3.5" />
            Import URL
          </Button>
          <Button size="sm" onClick={() => setShowNewDoc(true)}>
            <Plus className="h-3.5 w-3.5" />
            New Document
          </Button>
        </div>
      </div>

      {/* Main layout */}
      <div className="flex flex-1 gap-4 overflow-hidden min-h-0">
        {/* Left panel */}
        <div className="flex w-80 shrink-0 flex-col gap-3 overflow-hidden">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search documents..."
              className="w-full rounded-lg border border-border bg-card pl-9 pr-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Type filter pills */}
          <div className="flex flex-wrap gap-1.5">
            {DOC_TYPES.map((dt) => (
              <button
                key={dt.value}
                onClick={() => setActiveType(dt.value)}
                className={cn(
                  'rounded-full px-2.5 py-1 text-[11px] font-medium transition-colors',
                  activeType === dt.value
                    ? 'bg-primary text-white'
                    : 'bg-border/50 text-muted hover:text-text hover:bg-border'
                )}
              >
                {dt.label}
              </button>
            ))}
          </div>

          {/* Semantic search indicator */}
          {semanticResults !== null && (
            <div className="flex items-center gap-1.5 rounded-lg bg-primary/10 px-3 py-1.5">
              <Search className="h-3 w-3 text-primary" />
              <span className="text-[11px] text-primary">Semantic search — {docs.length} results</span>
            </div>
          )}

          {/* Doc list */}
          <div className="flex-1 overflow-y-auto space-y-1.5 pr-0.5">
            {loadingDocs ? (
              [...Array(5)].map((_, i) => <Skeleton key={i} className="h-20" />)
            ) : docs.length === 0 ? (
              <div className="py-12 text-center">
                <BookOpen className="mx-auto h-8 w-8 text-muted/40" />
                <p className="mt-2 text-sm text-muted">No documents found</p>
              </div>
            ) : (
              docs.map((doc) => (
                <DocCard
                  key={doc.id}
                  doc={doc}
                  selected={selectedDoc?.id === doc.id}
                  similarityScore={getSimilarityScore(doc.id)}
                  onClick={() => void handleSelectDoc(doc.id)}
                />
              ))
            )}
          </div>
        </div>

        {/* Right panel */}
        <div className="flex-1 overflow-hidden rounded-xl border border-border bg-card min-w-0">
          {loadingDetail ? (
            <div className="flex h-full items-center justify-center">
              <RefreshCw className="h-5 w-5 animate-spin text-muted" />
            </div>
          ) : selectedDoc ? (
            <DocEditor
              key={selectedDoc.id}
              doc={selectedDoc}
              onUpdated={handleDocUpdated}
              onDeleted={handleDocDeleted}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-3 text-center">
              <BookOpen className="h-10 w-10 text-muted/30" />
              <div>
                <p className="text-sm font-medium text-muted">No document selected</p>
                <p className="text-xs text-muted/60 mt-1">
                  Select a document from the list or create a new one
                </p>
              </div>
              <Button size="sm" variant="outline" onClick={() => setShowNewDoc(true)}>
                <Plus className="h-3.5 w-3.5" />
                New Document
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Modals */}
      {showNewDoc && (
        <NewDocModal
          onClose={() => setShowNewDoc(false)}
          onCreated={handleDocCreated}
        />
      )}
      {showImportURL && (
        <ImportURLModal
          onClose={() => setShowImportURL(false)}
          onCreated={handleDocCreated}
        />
      )}
    </div>
  )
}
