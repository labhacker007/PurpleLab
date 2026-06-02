'use client'

import { useState, useRef, useCallback, useEffect, DragEvent, ChangeEvent } from 'react'
import { useRouter } from 'next/navigation'
import {
  Users,
  Monitor,
  Cloud,
  Package,
  ShieldAlert,
  AlertTriangle,
  Upload,
  Download,
  RefreshCw,
  CheckCircle2,
  XCircle,
  FileText,
  ChevronRight,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { useAuthStore } from '../../../stores/auth'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

type EntityKey = 'people' | 'hardware_assets' | 'cloud_accounts' | 'products' | 'vulnerabilities' | 'cspm_findings'
type InputMode = 'file' | 'paste'
type DataFormat = 'csv' | 'json'

interface ImportError {
  row: number
  field: string
  message: string
}

interface ImportResult {
  entity: string
  total_rows: number
  imported: number
  updated: number
  skipped: number
  errors: ImportError[]
}

interface SessionSummary {
  entity: string
  label: string
  imported: number
  updated: number
  skipped: number
  errorCount: number
  timestamp: string
}

// ─── Entity config ──────────────────────────────────────────────────────────────

const ENTITIES: { key: EntityKey; label: string; icon: React.ElementType; exampleFields: string[] }[] = [
  {
    key: 'people',
    label: 'Employees',
    icon: Users,
    exampleFields: ['email', 'full_name', 'department', 'title', 'manager_email', 'location'],
  },
  {
    key: 'hardware_assets',
    label: 'Hardware Assets',
    icon: Monitor,
    exampleFields: ['asset_tag', 'hostname', 'serial_number', 'manufacturer', 'model', 'owner_email', 'location'],
  },
  {
    key: 'cloud_accounts',
    label: 'Cloud Accounts',
    icon: Cloud,
    exampleFields: ['account_id', 'account_name', 'provider', 'region', 'environment', 'owner_email'],
  },
  {
    key: 'products',
    label: 'Products',
    icon: Package,
    exampleFields: ['name', 'version', 'vendor', 'category', 'cpe', 'eol_date'],
  },
  {
    key: 'vulnerabilities',
    label: 'Vulnerabilities',
    icon: ShieldAlert,
    exampleFields: ['cve_id', 'title', 'cvss_score', 'severity', 'asset_id', 'status', 'discovered_at'],
  },
  {
    key: 'cspm_findings',
    label: 'CSPM Findings',
    icon: AlertTriangle,
    exampleFields: ['finding_id', 'rule_id', 'severity', 'resource_id', 'cloud_account_id', 'region', 'status', 'detected_at'],
  },
]

const MAX_FILE_BYTES = 10 * 1024 * 1024 // 10 MB

// ─── CSV parser ────────────────────────────────────────────────────────────────

function parseCsv(text: string): { rows: Record<string, string>[]; error: string | null } {
  const lines = text.trim().split('\n').map(l => l.trim()).filter(Boolean)
  if (lines.length < 2) {
    return { rows: [], error: 'CSV must have a header row and at least one data row.' }
  }
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''))
  const rows: Record<string, string>[] = []
  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map(v => v.trim().replace(/^"|"$/g, ''))
    const row: Record<string, string> = {}
    headers.forEach((h, idx) => { row[h] = values[idx] ?? '' })
    rows.push(row)
  }
  return { rows, error: null }
}

// ─── Example JSON placeholder ──────────────────────────────────────────────────

function buildJsonPlaceholder(entity: EntityKey): string {
  const cfg = ENTITIES.find(e => e.key === entity)!
  const exampleObj: Record<string, string> = {}
  cfg.exampleFields.forEach(f => { exampleObj[f] = `<${f}>` })
  return `[\n  ${JSON.stringify(exampleObj, null, 2).replace(/\n/g, '\n  ')}\n]`
}

// ─── Access denied ─────────────────────────────────────────────────────────────

function AccessDenied() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="w-full max-w-sm bg-card border-border">
        <CardContent className="flex flex-col items-center gap-4 p-8">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-red-500/10">
            <XCircle className="h-7 w-7 text-red-400" />
          </div>
          <div className="text-center">
            <h2 className="text-base font-semibold text-text">Access Denied</h2>
            <p className="mt-1 text-sm text-muted">
              This page requires admin or engineer role.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export default function ImportPage() {
  const user = useAuthStore(s => s.user)
  const router = useRouter()

  const [activeEntity, setActiveEntity] = useState<EntityKey>('people')
  const [inputMode, setInputMode] = useState<InputMode>('file')
  const [dataFormat, setDataFormat] = useState<DataFormat>('csv')

  // File upload state
  const fileRef = useRef<HTMLInputElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [isDragOver, setIsDragOver] = useState(false)

  // Paste state
  const [pasteText, setPasteText] = useState('')
  const [pasteError, setPasteError] = useState<string | null>(null)

  // Parsed row count (preview)
  const [parsedCount, setParsedCount] = useState<number | null>(null)

  // Import state
  const [importing, setImporting] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)

  // Session history (last import per entity)
  const [sessionHistory, setSessionHistory] = useState<SessionSummary[]>([])

  // Redirect viewers/analysts
  useEffect(() => {
    if (user && user.role !== 'admin' && user.role !== 'engineer') {
      router.replace('/dashboard')
    }
  }, [user, router])

  // Reset parse state when entity or mode changes
  useEffect(() => {
    setParsedCount(null)
    setPasteError(null)
    setFileError(null)
    setSelectedFile(null)
    setPasteText('')
    setResult(null)
  }, [activeEntity, inputMode])

  // ── File handling ────────────────────────────────────────────────────────────

  const handleFileSelect = useCallback((file: File) => {
    setFileError(null)
    setParsedCount(null)
    setResult(null)

    if (file.size > MAX_FILE_BYTES) {
      setFileError('File exceeds 10MB limit.')
      setSelectedFile(null)
      return
    }

    const ext = file.name.split('.').pop()?.toLowerCase()
    if (ext !== 'csv' && ext !== 'json') {
      setFileError('Only .csv and .json files are supported.')
      setSelectedFile(null)
      return
    }

    setSelectedFile(file)

    // Count rows for preview
    const reader = new FileReader()
    reader.onload = e => {
      const text = (e.target?.result as string) ?? ''
      if (ext === 'csv') {
        const { rows, error } = parseCsv(text)
        if (error) { setFileError(error); setParsedCount(null) }
        else setParsedCount(rows.length)
      } else {
        try {
          const parsed = JSON.parse(text)
          if (!Array.isArray(parsed)) {
            setFileError('JSON must be an array of objects.')
            setParsedCount(null)
          } else {
            setParsedCount(parsed.length)
          }
        } catch {
          setFileError('Invalid JSON — could not parse file.')
          setParsedCount(null)
        }
      }
    }
    reader.readAsText(file)
  }, [])

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFileSelect(file)
  }, [handleFileSelect])

  const handleFileInputChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFileSelect(file)
  }, [handleFileSelect])

  // ── Paste handling ───────────────────────────────────────────────────────────

  const handlePasteChange = useCallback((text: string) => {
    setPasteText(text)
    setPasteError(null)
    setParsedCount(null)
    setResult(null)

    if (!text.trim()) return

    try {
      const parsed = JSON.parse(text)
      if (!Array.isArray(parsed)) {
        setPasteError('Must be a JSON array: [{...}, ...]')
        return
      }
      setParsedCount(parsed.length)
    } catch {
      setPasteError('Invalid JSON — check syntax and try again.')
    }
  }, [])

  // ── Template download ────────────────────────────────────────────────────────

  const handleDownloadTemplate = useCallback(async () => {
    try {
      const res = await authFetch(
        `${API_BASE}/api/v2/import/template/${activeEntity}?format=${dataFormat}`
      )
      if (!res.ok) return
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${activeEntity}_template.${dataFormat}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silent — network failure
    }
  }, [activeEntity, dataFormat])

  // ── Import ───────────────────────────────────────────────────────────────────

  const canImport = (() => {
    if (importing) return false
    if (inputMode === 'file') return selectedFile !== null && !fileError && parsedCount !== null && parsedCount > 0
    return pasteText.trim().length > 0 && !pasteError && parsedCount !== null && parsedCount > 0
  })()

  const handleImport = useCallback(async () => {
    setImporting(true)
    setResult(null)

    try {
      let res: Response

      if (inputMode === 'file' && selectedFile) {
        const ext = selectedFile.name.split('.').pop()?.toLowerCase()

        if (ext === 'json') {
          // Read JSON file and POST as JSON body
          const text = await selectedFile.text()
          const rows = JSON.parse(text)
          res = await authFetch(`${API_BASE}/api/v2/import/${activeEntity}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rows }),
          })
        } else {
          // CSV → multipart
          const form = new FormData()
          form.append('file', selectedFile)
          res = await authFetch(`${API_BASE}/api/v2/import/${activeEntity}`, {
            method: 'POST',
            body: form,
          })
        }
      } else {
        // Paste mode — always JSON array
        const rows = JSON.parse(pasteText)
        res = await authFetch(`${API_BASE}/api/v2/import/${activeEntity}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rows }),
        })
      }

      if (res.ok) {
        const data = (await res.json()) as ImportResult
        setResult(data)

        // Update session history
        const entityCfg = ENTITIES.find(e => e.key === activeEntity)!
        const summary: SessionSummary = {
          entity: activeEntity,
          label: entityCfg.label,
          imported: data.imported,
          updated: data.updated,
          skipped: data.skipped,
          errorCount: data.errors?.length ?? 0,
          timestamp: new Date().toLocaleTimeString(),
        }
        setSessionHistory(prev => {
          const next = prev.filter(s => s.entity !== activeEntity)
          return [summary, ...next]
        })
      } else {
        const text = await res.text().catch(() => 'Unknown error')
        setResult({
          entity: activeEntity,
          total_rows: 0,
          imported: 0,
          updated: 0,
          skipped: 0,
          errors: [{ row: 0, field: '', message: `Server error (${res.status}): ${text}` }],
        })
      }
    } catch (err) {
      setResult({
        entity: activeEntity,
        total_rows: 0,
        imported: 0,
        updated: 0,
        skipped: 0,
        errors: [{ row: 0, field: '', message: err instanceof Error ? err.message : 'Network error' }],
      })
    } finally {
      setImporting(false)
    }
  }, [activeEntity, inputMode, selectedFile, pasteText])

  const handleReset = useCallback(() => {
    setResult(null)
    setSelectedFile(null)
    setPasteText('')
    setParsedCount(null)
    setFileError(null)
    setPasteError(null)
    if (fileRef.current) fileRef.current.value = ''
  }, [])

  // ── Guard ────────────────────────────────────────────────────────────────────

  if (user && user.role !== 'admin' && user.role !== 'engineer') {
    return <AccessDenied />
  }

  const activeEntityCfg = ENTITIES.find(e => e.key === activeEntity)!

  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Enterprise Data Import</h1>
          <p className="text-xs text-muted mt-0.5">
            Import employees, assets, products and security data via JSON or CSV
          </p>
        </div>
        <Badge className="bg-violet-500/10 text-violet-400 border border-violet-500/30 text-xs">
          {user?.role === 'admin' ? 'Admin' : 'Engineer'}
        </Badge>
      </div>

      {/* ── Session history bar ── */}
      {sessionHistory.length > 0 && (
        <Card className="bg-card border-border">
          <CardContent className="py-3 px-4">
            <p className="text-xs font-medium text-muted uppercase tracking-wide mb-2">This session — last import per entity</p>
            <div className="flex flex-wrap gap-3">
              {sessionHistory.map(s => (
                <div
                  key={s.entity}
                  className="flex items-center gap-2 rounded-lg border border-border bg-bg/50 px-3 py-1.5 text-xs"
                >
                  <span className="font-medium text-text">{s.label}</span>
                  <span className="text-green-400">+{s.imported}</span>
                  {s.updated > 0 && <span className="text-blue-400">~{s.updated}</span>}
                  {s.skipped > 0 && <span className="text-muted">skip {s.skipped}</span>}
                  {s.errorCount > 0 && <span className="text-amber-400">{s.errorCount} err</span>}
                  <span className="text-muted/60">{s.timestamp}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Entity selector ── */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <p className="text-xs font-medium text-muted uppercase tracking-wide mb-3">Select entity type</p>
          <div className="flex flex-wrap gap-2">
            {ENTITIES.map(e => {
              const Icon = e.icon
              const active = activeEntity === e.key
              return (
                <button
                  key={e.key}
                  onClick={() => setActiveEntity(e.key)}
                  className={cn(
                    'flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors border',
                    active
                      ? 'bg-violet-500/10 text-violet-400 border-violet-500/30'
                      : 'text-muted hover:text-text hover:bg-bg/50 border-transparent'
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {e.label}
                </button>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* ── Import card ── */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <activeEntityCfg.icon className="h-4 w-4 text-muted" />
              Import {activeEntityCfg.label}
            </CardTitle>

            {/* Format toggle + template download */}
            <div className="flex items-center gap-2">
              {/* CSV / JSON radio toggle */}
              <div className="flex items-center rounded-lg border border-border overflow-hidden">
                {(['csv', 'json'] as DataFormat[]).map(fmt => (
                  <button
                    key={fmt}
                    onClick={() => setDataFormat(fmt)}
                    className={cn(
                      'px-3 py-1.5 text-xs font-medium transition-colors uppercase',
                      dataFormat === fmt
                        ? 'bg-violet-500/10 text-violet-400'
                        : 'text-muted hover:text-text hover:bg-bg/50'
                    )}
                  >
                    {fmt}
                  </button>
                ))}
              </div>

              <Button
                size="sm"
                onClick={() => void handleDownloadTemplate()}
              >
                <Download className="h-3.5 w-3.5" />
                Download Template
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">

          {/* ── Input mode tabs ── */}
          <div className="flex items-center gap-1 rounded-lg border border-border bg-bg/40 p-1 w-fit">
            {(['file', 'paste'] as InputMode[]).map(mode => (
              <button
                key={mode}
                onClick={() => setInputMode(mode)}
                className={cn(
                  'px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize',
                  inputMode === mode
                    ? 'bg-violet-500/10 text-violet-400 border border-violet-500/30'
                    : 'text-muted hover:text-text hover:bg-bg/50 border border-transparent'
                )}
              >
                {mode === 'file' ? 'File Upload' : 'Paste JSON'}
              </button>
            ))}
          </div>

          {/* ── File upload tab ── */}
          {inputMode === 'file' && (
            <div className="space-y-3">
              {/* Drag-and-drop zone */}
              <div
                onDrop={handleDrop}
                onDragOver={e => { e.preventDefault(); setIsDragOver(true) }}
                onDragLeave={() => setIsDragOver(false)}
                onClick={() => fileRef.current?.click()}
                className={cn(
                  'flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-10 cursor-pointer transition-colors select-none',
                  isDragOver
                    ? 'border-violet-500 bg-violet-500/10'
                    : selectedFile
                    ? 'border-green-500/40 bg-green-500/5'
                    : 'border-border hover:border-violet-500/50 hover:bg-violet-500/5'
                )}
              >
                {selectedFile ? (
                  <>
                    <FileText className="h-8 w-8 text-green-400" />
                    <div className="text-center">
                      <p className="text-sm font-medium text-text">{selectedFile.name}</p>
                      <p className="text-xs text-muted mt-0.5">
                        {(selectedFile.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                  </>
                ) : (
                  <>
                    <Upload className={cn('h-8 w-8', isDragOver ? 'text-violet-400' : 'text-muted')} />
                    <div className="text-center">
                      <p className="text-sm font-medium text-text">Drop CSV or JSON file or click to browse</p>
                      <p className="text-xs text-muted mt-0.5">Accepts .csv, .json · Max 10 MB</p>
                    </div>
                  </>
                )}
              </div>

              <input
                ref={fileRef}
                type="file"
                accept=".csv,.json"
                className="hidden"
                onChange={handleFileInputChange}
              />

              {/* File error */}
              {fileError && (
                <p className="flex items-center gap-1.5 text-xs text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  {fileError}
                </p>
              )}

              {/* Row count preview */}
              {parsedCount !== null && !fileError && (
                <p className="flex items-center gap-1.5 text-xs text-green-400">
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                  Ready to import: {parsedCount.toLocaleString()} row{parsedCount !== 1 ? 's' : ''}
                </p>
              )}
            </div>
          )}

          {/* ── Paste JSON tab ── */}
          {inputMode === 'paste' && (
            <div className="space-y-3">
              <textarea
                value={pasteText}
                onChange={e => handlePasteChange(e.target.value)}
                rows={10}
                placeholder={buildJsonPlaceholder(activeEntity)}
                className="w-full rounded-lg border border-border bg-bg px-3 py-2.5 text-xs font-mono text-text placeholder:text-muted/50 focus:border-violet-500 focus:outline-none focus:ring-1 focus:ring-violet-500 resize-y"
              />

              {/* Paste error */}
              {pasteError && (
                <p className="flex items-center gap-1.5 text-xs text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  {pasteError}
                </p>
              )}

              {/* Row count preview */}
              {parsedCount !== null && !pasteError && (
                <p className="flex items-center gap-1.5 text-xs text-green-400">
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                  Ready to import: {parsedCount.toLocaleString()} row{parsedCount !== 1 ? 's' : ''}
                </p>
              )}
            </div>
          )}

          {/* ── Import button ── */}
          {!result && (
            <div className="flex justify-end pt-1">
              <Button
                onClick={() => void handleImport()}
                disabled={!canImport}
                className={cn(!canImport && 'opacity-50 cursor-not-allowed')}
              >
                {importing ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Upload className="h-4 w-4" />
                )}
                {importing ? 'Importing…' : 'Import Data'}
              </Button>
            </div>
          )}

          {/* ── Results panel ── */}
          {result && (
            <div className="rounded-xl border border-border bg-bg/50 p-4 space-y-4">
              {/* Success stats */}
              <div className="flex items-center gap-2 flex-wrap">
                <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />
                <span className="text-sm font-medium text-green-400">
                  {result.imported.toLocaleString()} row{result.imported !== 1 ? 's' : ''} imported
                </span>
                {result.updated > 0 && (
                  <>
                    <ChevronRight className="h-3.5 w-3.5 text-muted" />
                    <span className="text-sm text-blue-400">{result.updated.toLocaleString()} updated</span>
                  </>
                )}
                {result.skipped > 0 && (
                  <>
                    <ChevronRight className="h-3.5 w-3.5 text-muted" />
                    <span className="text-sm text-muted">{result.skipped.toLocaleString()} skipped</span>
                  </>
                )}
                {result.total_rows > 0 && (
                  <>
                    <ChevronRight className="h-3.5 w-3.5 text-muted" />
                    <span className="text-xs text-muted">{result.total_rows.toLocaleString()} total rows processed</span>
                  </>
                )}
              </div>

              {/* Errors section */}
              {result.errors && result.errors.length > 0 && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
                  <p className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {result.errors.length} error{result.errors.length !== 1 ? 's' : ''} encountered
                    {result.errors.length > 10 && ' (showing first 10)'}
                  </p>
                  <table className="w-full text-xs font-mono">
                    <thead>
                      <tr className="border-b border-amber-500/20">
                        <th className="text-left py-1 pr-3 text-amber-400/70 font-medium w-16">Row</th>
                        <th className="text-left py-1 pr-3 text-amber-400/70 font-medium w-32">Field</th>
                        <th className="text-left py-1 text-amber-400/70 font-medium">Message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.errors.slice(0, 10).map((err, i) => (
                        <tr key={i} className="border-b border-amber-500/10 last:border-0">
                          <td className="py-1 pr-3 text-amber-400">{err.row > 0 ? `Row ${err.row}` : '—'}</td>
                          <td className="py-1 pr-3 text-amber-400/80">{err.field || '—'}</td>
                          <td className="py-1 text-amber-400/70 break-all">{err.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Reset button */}
              <div className="flex justify-end">
                <Button size="sm" onClick={handleReset}>
                  Import another
                </Button>
              </div>
            </div>
          )}

        </CardContent>
      </Card>
    </div>
  )
}
