'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  Plus,
  BarChart3,
  CheckSquare,
  GitBranch,
  FileStack,
  X,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

type ReportType = 'coverage' | 'use_cases' | 'pipeline' | 'full'
type ReportFormat = 'json' | 'html'
type ReportStatus = 'generating' | 'ready' | 'failed'

interface Report {
  id: string
  name: string
  type: ReportType
  format: ReportFormat
  status: ReportStatus
  created_at: string | null
  created_by: string | null
  download_url: string | null
}

interface GenerateRequest {
  name: string
  type: ReportType
  format: ReportFormat
  date_range_days: number
}

// ─── Report type definitions ──────────────────────────────────────────────────

const REPORT_TYPES: {
  type: ReportType
  label: string
  description: string
  icon: React.ElementType
  accent: string
}[] = [
  {
    type: 'coverage',
    label: 'Coverage Report',
    description: 'DES score, per-tactic MITRE ATT&CK breakdown, and top uncovered techniques.',
    icon: BarChart3,
    accent: 'text-violet-400',
  },
  {
    type: 'use_cases',
    label: 'Use Case Report',
    description: 'Pass/fail/partial breakdown across all use cases, per-tactic stats, failing list.',
    icon: CheckSquare,
    accent: 'text-emerald-400',
  },
  {
    type: 'pipeline',
    label: 'Pipeline Report',
    description: 'Pipeline run history, average DES improvement per run, chain usage.',
    icon: GitBranch,
    accent: 'text-sky-400',
  },
  {
    type: 'full',
    label: 'Full Report',
    description: 'All sections combined — coverage, use cases, and pipeline in one document.',
    icon: FileStack,
    accent: 'text-amber-400',
  },
]

const DATE_RANGE_OPTIONS: { label: string; value: number }[] = [
  { label: '7 days', value: 7 },
  { label: '30 days', value: 30 },
  { label: '90 days', value: 90 },
  { label: 'Custom', value: 0 },
]

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: ReportStatus }) {
  if (status === 'generating') {
    return (
      <Badge variant="warning" className="animate-pulse text-[10px]">
        generating
      </Badge>
    )
  }
  if (status === 'ready') {
    return <Badge variant="success" className="text-[10px]">ready</Badge>
  }
  return <Badge variant="destructive" className="text-[10px]">failed</Badge>
}

// ─── Generate modal ───────────────────────────────────────────────────────────

function GenerateModal({
  initialType,
  onClose,
  onSubmit,
  isSubmitting,
}: {
  initialType: ReportType | null
  onClose: () => void
  onSubmit: (req: GenerateRequest) => Promise<void>
  isSubmitting: boolean
}) {
  const [selectedType, setSelectedType] = useState<ReportType>(initialType ?? 'coverage')
  const [name, setName] = useState('')
  const [format, setFormat] = useState<ReportFormat>('json')
  const [dateRangeDays, setDateRangeDays] = useState(30)
  const [customDays, setCustomDays] = useState(60)
  const [useCustom, setUseCustom] = useState(false)

  const effectiveDays = useCustom ? customDays : dateRangeDays

  const handleSubmit = async () => {
    const typeLabel = REPORT_TYPES.find((t) => t.type === selectedType)?.label ?? selectedType
    const resolvedName = name.trim() || `${typeLabel} — ${new Date().toLocaleDateString()}`
    await onSubmit({
      name: resolvedName,
      type: selectedType,
      format,
      date_range_days: effectiveDays,
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-border bg-slate-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold text-text">Generate Report</h2>
          </div>
          <button
            onClick={onClose}
            disabled={isSubmitting}
            className="rounded p-1 text-muted hover:text-text transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-5 p-5">
          {/* Report name */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted uppercase tracking-wide">
              Report Name <span className="normal-case text-muted/60">(optional)</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Auto-generated from type + date"
              className="w-full rounded-lg border border-border bg-slate-950 px-3 py-2 text-sm text-text placeholder:text-muted/50 focus:border-primary/50 focus:outline-none"
            />
          </div>

          {/* Report type */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted uppercase tracking-wide">
              Report Type
            </label>
            <div className="grid grid-cols-2 gap-2">
              {REPORT_TYPES.map(({ type, label, icon: Icon, accent }) => (
                <button
                  key={type}
                  onClick={() => setSelectedType(type)}
                  className={cn(
                    'flex items-center gap-2 rounded-lg border px-3 py-2.5 text-left text-sm transition-colors',
                    selectedType === type
                      ? 'border-primary bg-primary/10 text-text'
                      : 'border-border bg-slate-950 text-muted hover:border-border/80 hover:text-text'
                  )}
                >
                  <Icon className={cn('h-4 w-4 shrink-0', selectedType === type ? accent : '')} />
                  <span className="font-medium text-xs">{label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Date range */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted uppercase tracking-wide">
              Date Range
            </label>
            <div className="flex gap-2 flex-wrap">
              {DATE_RANGE_OPTIONS.map((opt) => (
                <button
                  key={opt.label}
                  onClick={() => {
                    if (opt.value === 0) {
                      setUseCustom(true)
                    } else {
                      setUseCustom(false)
                      setDateRangeDays(opt.value)
                    }
                  }}
                  className={cn(
                    'rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors',
                    (opt.value === 0 ? useCustom : !useCustom && dateRangeDays === opt.value)
                      ? 'border-primary bg-primary/10 text-text'
                      : 'border-border bg-slate-950 text-muted hover:text-text'
                  )}
                >
                  {opt.label}
                </button>
              ))}
            </div>
            {useCustom && (
              <div className="flex items-center gap-2 mt-2">
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={customDays}
                  onChange={(e) => setCustomDays(Math.max(1, Math.min(365, Number(e.target.value))))}
                  className="w-24 rounded-lg border border-border bg-slate-950 px-3 py-1.5 text-sm text-text focus:border-primary/50 focus:outline-none"
                />
                <span className="text-xs text-muted">days</span>
              </div>
            )}
          </div>

          {/* Format toggle */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted uppercase tracking-wide">
              Format
            </label>
            <div className="flex rounded-lg border border-border overflow-hidden w-fit">
              {(['json', 'html'] as ReportFormat[]).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setFormat(fmt)}
                  className={cn(
                    'px-4 py-1.5 text-xs font-medium transition-colors',
                    format === fmt
                      ? 'bg-primary text-white'
                      : 'bg-slate-950 text-muted hover:text-text'
                  )}
                >
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-muted">
              {format === 'html'
                ? 'Generates a clean, printable HTML document.'
                : 'Downloads structured JSON data.'}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-2 border-t border-border px-5 py-4">
          <Button variant="outline" size="sm" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button size="sm" onClick={() => void handleSubmit()} disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Generating…
              </>
            ) : (
              <>
                <Plus className="h-3.5 w-3.5" />
                Generate
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Reports list table ───────────────────────────────────────────────────────

function ReportsTable({
  reports,
  onDelete,
  onDownload,
  deleting,
  downloading,
}: {
  reports: Report[]
  onDelete: (id: string) => void
  onDownload: (report: Report) => void
  deleting: Set<string>
  downloading: Set<string>
}) {
  if (reports.length === 0) {
    return (
      <div className="py-16 text-center">
        <FileText className="h-10 w-10 text-muted mx-auto mb-3" />
        <p className="text-sm font-medium text-text">No reports yet</p>
        <p className="text-xs text-muted mt-1">
          Select a report type above and click Generate to create your first report.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border">
            <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">
              Name
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">
              Type
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">
              Format
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">
              Created
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">
              Status
            </th>
            <th className="px-4 py-3 text-right text-xs font-medium text-muted uppercase tracking-wide">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {reports.map((r) => {
            const typeDef = REPORT_TYPES.find((t) => t.type === r.type)
            const Icon = typeDef?.icon ?? FileText
            const isDeleting = deleting.has(r.id)
            const isDownloading = downloading.has(r.id)
            return (
              <tr key={r.id} className="hover:bg-slate-900/50 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-border/60">
                      <Icon className={cn('h-3.5 w-3.5', typeDef?.accent ?? 'text-muted')} />
                    </div>
                    <span className="font-medium text-text text-xs truncate max-w-[220px]" title={r.name}>
                      {r.name}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-muted capitalize">
                    {r.type.replace('_', ' ')}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-muted uppercase">{r.format}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-muted">
                    {r.created_at ? new Date(r.created_at).toLocaleString() : '—'}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-1.5">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onDownload(r)}
                      disabled={r.status !== 'ready' || isDownloading || isDeleting}
                      className="h-7 px-2 text-xs"
                      title="Download"
                    >
                      {isDownloading ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      <span className="hidden sm:inline ml-1">Download</span>
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onDelete(r.id)}
                      disabled={isDeleting || isDownloading}
                      className="h-7 px-2 text-xs text-red hover:text-red hover:bg-red/10"
                      title="Delete"
                    >
                      {isDeleting ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <Trash2 className="h-3.5 w-3.5" />
                      )}
                    </Button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ─── Reports page ─────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [modalInitialType, setModalInitialType] = useState<ReportType | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [deleting, setDeleting] = useState<Set<string>>(new Set())
  const [downloading, setDownloading] = useState<Set<string>>(new Set())
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // ── Fetch reports ────────────────────────────────────────────────────────────

  const fetchReports = useCallback(async (silent = false) => {
    if (!silent) setIsLoading(true)
    else setIsRefreshing(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/reports`)
      if (res.ok) {
        const data = (await res.json()) as { reports: Report[] }
        setReports(data.reports ?? [])
        setError(null)
      } else {
        setError('Failed to load reports.')
      }
    } catch {
      setError('Could not reach the server.')
    } finally {
      setIsLoading(false)
      setIsRefreshing(false)
    }
  }, [])

  // ── Initial load + auto-refresh while any report is generating ───────────────

  useEffect(() => {
    void fetchReports()
  }, [fetchReports])

  useEffect(() => {
    const hasGenerating = reports.some((r) => r.status === 'generating')
    if (hasGenerating && !pollRef.current) {
      pollRef.current = setInterval(() => void fetchReports(true), 5000)
    } else if (!hasGenerating && pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [reports, fetchReports])

  // ── Last generated lookup (per type) ────────────────────────────────────────

  const lastGenerated = (type: ReportType): string | null => {
    const match = reports
      .filter((r) => r.type === type && r.status === 'ready')
      .sort((a, b) => {
        const da = a.created_at ? new Date(a.created_at).getTime() : 0
        const db_ = b.created_at ? new Date(b.created_at).getTime() : 0
        return db_ - da
      })[0]
    return match?.created_at ?? null
  }

  // ── Handlers ─────────────────────────────────────────────────────────────────

  const openModal = (type: ReportType | null = null) => {
    setModalInitialType(type)
    setShowModal(true)
  }

  const handleGenerate = async (req: GenerateRequest) => {
    setIsSubmitting(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
      if (!res.ok) {
        const err = (await res.json().catch(() => ({}))) as { detail?: string }
        throw new Error(err.detail ?? `HTTP ${res.status}`)
      }
      setShowModal(false)
      // Optimistically add a placeholder so the user sees it immediately
      await fetchReports(true)
    } catch (e) {
      setError(`Failed to generate report: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleDelete = async (id: string) => {
    setDeleting((prev) => new Set(prev).add(id))
    try {
      const res = await authFetch(`${API_BASE}/api/v2/reports/${id}`, { method: 'DELETE' })
      if (res.ok) {
        setReports((prev) => prev.filter((r) => r.id !== id))
      } else {
        setError('Failed to delete report.')
      }
    } catch {
      setError('Could not reach the server.')
    } finally {
      setDeleting((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }
  }

  const handleDownload = async (report: Report) => {
    if (!report.download_url) return
    setDownloading((prev) => new Set(prev).add(report.id))
    try {
      const res = await authFetch(`${API_BASE}${report.download_url}`)
      if (!res.ok) {
        setError('Download failed.')
        return
      }
      const blob = await res.blob()
      const ext = report.format === 'html' ? 'html' : 'json'
      const safeN = report.name.replace(/[^a-zA-Z0-9 _-]/g, '_').trim().slice(0, 60) || 'report'
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeN}.${ext}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError('Download failed.')
    } finally {
      setDownloading((prev) => {
        const next = new Set(prev)
        next.delete(report.id)
        return next
      })
    }
  }

  // ── Skeleton ──────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <div className="h-5 w-28 animate-pulse rounded bg-border/60" />
            <div className="h-3.5 w-48 animate-pulse rounded bg-border/40" />
          </div>
          <div className="h-8 w-28 animate-pulse rounded-lg bg-border/60" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-28 animate-pulse rounded-xl bg-border/40" />
          ))}
        </div>
        <div className="h-64 animate-pulse rounded-xl bg-border/40" />
      </div>
    )
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Reports</h1>
          <p className="text-xs text-muted mt-0.5">
            Generate, download, and manage purple team reports.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void fetchReports(true)}
            disabled={isRefreshing}
          >
            <RefreshCw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
            Refresh
          </Button>
          <Button size="sm" onClick={() => openModal()}>
            <Plus className="h-3.5 w-3.5" />
            New Report
          </Button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red/30 bg-red/10 px-4 py-3">
          <AlertCircle className="h-4 w-4 text-red shrink-0" />
          <p className="text-sm text-red">{error}</p>
          <button
            onClick={() => setError(null)}
            className="ml-auto text-red/70 hover:text-red"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Report type selector cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {REPORT_TYPES.map(({ type, label, description, icon: Icon, accent }) => {
          const last = lastGenerated(type)
          return (
            <Card
              key={type}
              className="cursor-pointer hover:border-primary/50 transition-all group"
              onClick={() => openModal(type)}
            >
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg bg-border/60 group-hover:bg-primary/10 transition-colors')}>
                    <Icon className={cn('h-4 w-4', accent)} />
                  </div>
                  <Plus className="h-3.5 w-3.5 text-muted group-hover:text-primary transition-colors mt-0.5" />
                </div>
                <p className="mt-3 text-sm font-semibold text-text">{label}</p>
                <p className="mt-1 text-xs text-muted leading-relaxed">{description}</p>
                {last ? (
                  <p className="mt-2.5 text-[10px] text-muted/60">
                    Last: {new Date(last).toLocaleDateString()}
                  </p>
                ) : (
                  <p className="mt-2.5 text-[10px] text-muted/40">Never generated</p>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Reports list */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold">
              Saved Reports
              {reports.length > 0 && (
                <span className="ml-2 text-xs font-normal text-muted">({reports.length})</span>
              )}
            </CardTitle>
            {reports.some((r) => r.status === 'generating') && (
              <div className="flex items-center gap-1.5 text-xs text-amber-400">
                <Loader2 className="h-3 w-3 animate-spin" />
                <span>Generating…</span>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ReportsTable
            reports={reports}
            onDelete={(id) => void handleDelete(id)}
            onDownload={(r) => void handleDownload(r)}
            deleting={deleting}
            downloading={downloading}
          />
        </CardContent>
      </Card>

      {/* Generate modal */}
      {showModal && (
        <GenerateModal
          initialType={modalInitialType}
          onClose={() => setShowModal(false)}
          onSubmit={handleGenerate}
          isSubmitting={isSubmitting}
        />
      )}
    </div>
  )
}
