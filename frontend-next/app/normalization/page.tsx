'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Plus,
  X,
  Check,
  Loader2,
  AlertCircle,
  RefreshCw,
  Trash2,
  Edit2,
  Upload,
  ChevronDown,
  History,
  RotateCcw,
  GitCompare,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost, apiPut, apiDelete } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

interface NormalizationField {
  name: string
  siem_name: string
  type: string
  description: string
  example?: string
}

interface NormalizationSchema {
  id: string
  name: string
  version_label: string
  siem_platform: string
  description: string
  fields: NormalizationField[]
  datasets: string[]
  data_models: unknown[]
  ai_parsed: boolean
  ai_parse_notes?: string
  source_file_name?: string
  created_by?: string
  created_at: string
  updated_at: string
}

interface SchemaVersion {
  id: string
  version_num: number
  version_label: string
  fields_snapshot: NormalizationField[]
  datasets_snapshot: string[]
  change_summary?: string
  created_at: string
}

// ─── Seed data ────────────────────────────────────────────────────────────────

const SEED_SCHEMAS: NormalizationSchema[] = [
  {
    id: 'ns-1', name: 'Windows Security Event Log', version_label: 'v2.1', siem_platform: 'splunk',
    description: 'Standard Windows Security Event Log field normalization for Splunk ES.', fields: [
      { name: 'event_id', siem_name: 'EventCode', type: 'number', description: 'Windows Event ID' },
      { name: 'user', siem_name: 'Account_Name', type: 'text', description: 'User account name' },
      { name: 'src_ip', siem_name: 'IpAddress', type: 'ip', description: 'Source IP address' },
      { name: 'timestamp', siem_name: '_time', type: 'timestamp', description: 'Event timestamp' },
    ],
    datasets: ['wineventlog', 'XmlWinEventLog'], data_models: [], ai_parsed: false,
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-02-15T00:00:00Z',
  },
  {
    id: 'ns-2', name: 'AWS CloudTrail Events', version_label: 'v1.0', siem_platform: 'elastic',
    description: 'AWS CloudTrail event normalization for Elastic SIEM.', fields: [
      { name: 'event_name', siem_name: 'event.action', type: 'text', description: 'CloudTrail event name' },
      { name: 'source_ip', siem_name: 'source.ip', type: 'ip', description: 'Source IP of request' },
      { name: 'user_arn', siem_name: 'aws.cloudtrail.user_identity.arn', type: 'text', description: 'IAM ARN' },
    ],
    datasets: ['logs-aws.cloudtrail-*'], data_models: [], ai_parsed: true, ai_parse_notes: 'Parsed from AWS documentation PDF',
    created_at: '2026-01-10T00:00:00Z', updated_at: '2026-01-10T00:00:00Z',
  },
  {
    id: 'ns-3', name: 'Azure Activity Log', version_label: 'v1.2', siem_platform: 'sentinel',
    description: 'Azure Activity Log schema normalization for Microsoft Sentinel.', fields: [
      { name: 'operation', siem_name: 'OperationName', type: 'text', description: 'Azure operation performed' },
      { name: 'caller', siem_name: 'Caller', type: 'text', description: 'User or service that initiated' },
      { name: 'resource', siem_name: 'ResourceId', type: 'text', description: 'Azure resource ID' },
      { name: 'status', siem_name: 'ActivityStatusValue', type: 'text', description: 'Activity status' },
    ],
    datasets: ['AzureActivity'], data_models: [], ai_parsed: false,
    created_at: '2026-01-20T00:00:00Z', updated_at: '2026-03-01T00:00:00Z',
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SIEM_PLATFORM_CONFIG: Record<string, { label: string; color: string }> = {
  splunk: { label: 'Splunk', color: 'bg-green-500/15 text-green-400 border-green-500/30' },
  elastic: { label: 'Elastic', color: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
  sentinel: { label: 'Sentinel', color: 'bg-violet-500/15 text-violet-400 border-violet-500/30' },
  qradar: { label: 'QRadar', color: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
  sumo: { label: 'Sumo Logic', color: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' },
  custom: { label: 'Custom', color: 'bg-muted text-muted-foreground border-border' },
}

function SiemBadge({ platform }: { platform: string }) {
  const cfg = SIEM_PLATFORM_CONFIG[platform] ?? SIEM_PLATFORM_CONFIG.custom
  return <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-medium', cfg.color)}>{cfg.label}</span>
}

const FIELD_TYPES = ['text', 'number', 'boolean', 'timestamp', 'ip', 'hash']

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`
  return `${Math.floor(ms / 86400000)}d ago`
}

// ─── Schema Detail View ───────────────────────────────────────────────────────

function SchemaDetailView({ schema, onClose, onUpdate }: { schema: NormalizationSchema; onClose: () => void; onUpdate: () => void }) {
  const [versions, setVersions] = useState<SchemaVersion[]>([])
  const [loadingVersions, setLoadingVersions] = useState(true)
  const [restoringId, setRestoringId] = useState<string | null>(null)

  useEffect(() => {
    setLoadingVersions(true)
    apiGet<SchemaVersion[]>(`/api/v2/normalization/${schema.id}/versions`)
      .then(setVersions)
      .catch(() => {
        setVersions([
          { id: 'v1', version_num: 1, version_label: 'v1.0', fields_snapshot: schema.fields.slice(0, 2), datasets_snapshot: [], change_summary: 'Initial version', created_at: schema.created_at },
          { id: 'v2', version_num: 2, version_label: schema.version_label, fields_snapshot: schema.fields, datasets_snapshot: schema.datasets, change_summary: 'Added fields', created_at: schema.updated_at },
        ])
      })
      .finally(() => setLoadingVersions(false))
  }, [schema])

  async function handleRestore(version: SchemaVersion) {
    setRestoringId(version.id)
    try {
      await apiPut(`/api/v2/normalization/${schema.id}`, {
        fields: version.fields_snapshot,
        datasets: version.datasets_snapshot,
        version_label: `${version.version_label} (restored)`,
      })
      onUpdate()
      onClose()
    } catch { /* continue */ } finally {
      setRestoringId(null)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-3xl rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between border-b border-border px-5 py-4 shrink-0">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-semibold text-foreground">{schema.name}</h3>
            <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{schema.version_label}</span>
            <SiemBadge platform={schema.siem_platform} />
          </div>
          <button onClick={onClose} className="rounded-lg p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto flex-1 space-y-6">
          {/* Fields table */}
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">Fields ({schema.fields.length})</h4>
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-muted/60 text-muted-foreground border-b border-border">
                  <tr>
                    <th className="text-left px-3 py-2 font-medium">Field Name</th>
                    <th className="text-left px-3 py-2 font-medium">SIEM Name</th>
                    <th className="text-left px-3 py-2 font-medium w-24">Type</th>
                    <th className="text-left px-3 py-2 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {schema.fields.map((field, i) => (
                    <tr key={i} className="border-b border-border last:border-0">
                      <td className="px-3 py-2 font-mono text-foreground">{field.name}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{field.siem_name}</td>
                      <td className="px-3 py-2">
                        <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{field.type}</span>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">{field.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Datasets */}
          {schema.datasets.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Datasets</h4>
              <div className="flex flex-wrap gap-2">
                {schema.datasets.map((ds) => (
                  <span key={ds} className="rounded border border-border bg-muted px-2 py-1 text-xs font-mono text-foreground">{ds}</span>
                ))}
              </div>
            </div>
          )}

          {/* Version history */}
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
              <History className="h-3.5 w-3.5" />
              Version History
            </h4>
            {loadingVersions ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />Loading…</div>
            ) : (
              <div className="space-y-2">
                {versions.map((v, idx) => (
                  <div key={v.id} className="flex items-center gap-3 rounded-lg border border-border bg-muted/40 p-3">
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[10px] font-bold text-primary">
                      {v.version_num}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-foreground">{v.version_label}</span>
                        <span className="text-[10px] text-muted-foreground">{relativeDate(v.created_at)}</span>
                        {idx === versions.length - 1 && <span className="rounded border border-green-500/30 bg-green-500/10 px-1.5 py-0.5 text-[10px] text-green-400">current</span>}
                      </div>
                      <div className="flex gap-3 mt-0.5">
                        <span className="text-[10px] text-muted-foreground">{v.fields_snapshot.length} fields</span>
                        {v.change_summary && <span className="text-[10px] text-muted-foreground truncate">{v.change_summary}</span>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {/* Compare */}
                      {versions.length >= 2 && idx < versions.length - 1 && (
                        <button
                          title={`${v.fields_snapshot.length} fields vs ${versions[versions.length - 1].fields_snapshot.length} fields`}
                          className="flex items-center gap-1 rounded border border-border bg-muted/40 px-2 py-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                        >
                          <GitCompare className="h-3 w-3" />
                          {Math.abs(v.fields_snapshot.length - versions[versions.length - 1].fields_snapshot.length)} field diff
                        </button>
                      )}
                      {/* Restore */}
                      {idx < versions.length - 1 && (
                        <button
                          onClick={() => void handleRestore(v)}
                          disabled={restoringId === v.id}
                          className="flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
                        >
                          {restoringId === v.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />}
                          Restore
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Create / Edit Modal ──────────────────────────────────────────────────────

interface SchemaModalProps {
  initial?: NormalizationSchema
  onClose: () => void
  onSaved: () => void
}

function SchemaModal({ initial, onClose, onSaved }: SchemaModalProps) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [name, setName] = useState(initial?.name ?? '')
  const [versionLabel, setVersionLabel] = useState(initial?.version_label ?? 'v1.0')
  const [siemPlatform, setSiemPlatform] = useState(initial?.siem_platform ?? 'splunk')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [fields, setFields] = useState<NormalizationField[]>(initial?.fields ?? [{ name: '', siem_name: '', type: 'text', description: '' }])
  const [datasets, setDatasets] = useState<string[]>(initial?.datasets ?? [])
  const [datasetInput, setDatasetInput] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [aiParsing, setAiParsing] = useState(false)
  const [uploadedContent, setUploadedContent] = useState<string | null>(null)
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null)
  const [uploadFormat, setUploadFormat] = useState('JSON')

  function addField() {
    setFields((prev) => [...prev, { name: '', siem_name: '', type: 'text', description: '' }])
  }

  function removeField(index: number) {
    setFields((prev) => prev.filter((_, i) => i !== index))
  }

  function updateField(index: number, key: keyof NormalizationField, value: string) {
    setFields((prev) => prev.map((f, i) => i === index ? { ...f, [key]: value } : f))
  }

  function handleDatasetKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      const val = datasetInput.trim()
      if (val && !datasets.includes(val)) setDatasets((prev) => [...prev, val])
      setDatasetInput('')
    }
  }

  function handleFileUpload(file: File) {
    setUploadedFileName(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => setUploadedContent(ev.target?.result as string)
    reader.readAsText(file)
  }

  async function handleAiParse() {
    if (!uploadedContent) return
    setAiParsing(true)
    try {
      const res = await apiPost<{ fields: NormalizationField[] }>('/api/v2/normalization/parse-ai', {
        content: uploadedContent,
        format: uploadFormat,
        file_name: uploadedFileName,
      })
      setFields(res.fields)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI parse failed')
    } finally {
      setAiParsing(false)
    }
  }

  async function handleSubmit() {
    if (!name.trim()) return
    setSubmitting(true)
    setError(null)
    const payload = { name: name.trim(), version_label: versionLabel, siem_platform: siemPlatform, description, fields: fields.filter((f) => f.name.trim()), datasets }
    try {
      if (initial) {
        await apiPut(`/api/v2/normalization/${initial.id}`, payload)
      } else {
        await apiPost('/api/v2/normalization', payload)
      }
      onSaved()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-2xl rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between border-b border-border px-5 py-4 shrink-0">
          <h3 className="text-sm font-semibold text-foreground">{initial ? 'Edit Schema' : 'New Normalization Schema'}</h3>
          <button onClick={onClose} className="rounded-lg p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 overflow-y-auto flex-1 space-y-5">
          {/* Section 1: Basic info */}
          <div>
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium mb-3">1. Basic Information</p>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">Schema Name</label>
                  <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Windows Security Events" className="field px-3 py-2 text-sm w-full" />
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] text-muted-foreground">Version Label</label>
                  <input value={versionLabel} onChange={(e) => setVersionLabel(e.target.value)} placeholder="v1.0" className="field px-3 py-2 text-sm w-full" />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-[11px] text-muted-foreground">SIEM Platform</label>
                <div className="relative">
                  <select value={siemPlatform} onChange={(e) => setSiemPlatform(e.target.value)} className="field px-3 py-2 text-sm w-full pr-8">
                    {Object.entries(SIEM_PLATFORM_CONFIG).map(([key, { label }]) => <option key={key} value={key}>{label}</option>)}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-[11px] text-muted-foreground">Description</label>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="What does this schema normalize?" className="field px-3 py-2 text-sm w-full resize-none" />
              </div>
            </div>
          </div>

          {/* Section 2: Upload + AI parse */}
          <div>
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium mb-3">2. Upload Source (Optional)</p>
            <div className="space-y-3">
              <div className="flex gap-2">
                <select value={uploadFormat} onChange={(e) => setUploadFormat(e.target.value)} className="field px-3 py-2 text-sm">
                  {['JSON', 'CSV', 'TSV', 'PDF'].map((f) => <option key={f}>{f}</option>)}
                </select>
                <button
                  onClick={() => fileRef.current?.click()}
                  className="flex items-center gap-1.5 rounded border border-border bg-muted/40 hover:bg-muted px-3 py-2 text-xs text-foreground transition-colors"
                >
                  <Upload className="h-3.5 w-3.5" />
                  Choose File
                </button>
                <input ref={fileRef} type="file" accept=".json,.csv,.tsv,.pdf" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFileUpload(f) }} />
                <button
                  onClick={() => void handleAiParse()}
                  disabled={!uploadedContent || aiParsing}
                  className="flex items-center gap-1.5 rounded bg-amber-500/20 border border-amber-500/30 px-3 py-2 text-xs text-amber-400 hover:bg-amber-500/30 disabled:opacity-50 transition-colors"
                >
                  {aiParsing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <span className="text-xs">✦</span>}
                  Parse with AI
                </button>
              </div>
              {uploadedFileName && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Upload className="h-3.5 w-3.5 text-primary" />
                  <span>{uploadedFileName} uploaded</span>
                  {fields.length > 0 && <span className="text-green-400">— {fields.length} fields ready</span>}
                </div>
              )}
            </div>
          </div>

          {/* Section 3: Fields editor */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">3. Fields ({fields.length})</p>
              <button onClick={addField} className="flex items-center gap-1 rounded border border-border bg-muted/40 hover:bg-muted px-2 py-1 text-[11px] text-foreground transition-colors">
                <Plus className="h-3 w-3" /> Add Field
              </button>
            </div>
            <div className="space-y-2">
              {fields.map((field, i) => (
                <div key={i} className="grid grid-cols-[1fr_1fr_6rem_1fr_1.5rem] gap-2 items-center">
                  <input value={field.name} onChange={(e) => updateField(i, 'name', e.target.value)} placeholder="field_name" className="field px-2 py-1.5 text-xs font-mono" />
                  <input value={field.siem_name} onChange={(e) => updateField(i, 'siem_name', e.target.value)} placeholder="SiemFieldName" className="field px-2 py-1.5 text-xs font-mono" />
                  <select value={field.type} onChange={(e) => updateField(i, 'type', e.target.value)} className="field px-2 py-1.5 text-xs">
                    {FIELD_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <input value={field.description} onChange={(e) => updateField(i, 'description', e.target.value)} placeholder="Description" className="field px-2 py-1.5 text-xs" />
                  <button onClick={() => removeField(i)} className="rounded p-1 text-muted-foreground hover:text-red-400 transition-colors">
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              {fields.length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-3">No fields added. Use "Add Field" or Parse with AI.</p>
              )}
            </div>
          </div>

          {/* Section 4: Datasets */}
          <div>
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium mb-3">4. Datasets / Indexes</p>
            <input
              value={datasetInput}
              onChange={(e) => setDatasetInput(e.target.value)}
              onKeyDown={handleDatasetKey}
              placeholder="Type dataset name and press Enter…"
              className="field px-3 py-2 text-sm w-full font-mono"
            />
            {datasets.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-2">
                {datasets.map((ds) => (
                  <span key={ds} className="inline-flex items-center gap-1 rounded border border-border bg-muted px-2 py-0.5 text-xs font-mono text-foreground">
                    {ds}
                    <button onClick={() => setDatasets((prev) => prev.filter((d) => d !== ds))} className="text-muted-foreground hover:text-foreground">
                      <X className="h-2.5 w-2.5" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
              <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              {error}
            </div>
          )}
        </div>

        <div className="flex gap-2 border-t border-border px-5 py-4 shrink-0">
          <button onClick={onClose} className="flex-1 rounded border border-border bg-muted/40 hover:bg-muted px-3 py-2 text-xs text-foreground transition-colors">Cancel</button>
          <button onClick={() => void handleSubmit()} disabled={!name.trim() || submitting} className="flex-1 flex items-center justify-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
            {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            {submitting ? 'Saving…' : initial ? 'Save Changes' : 'Create Schema'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function NormalizationPage() {
  const [schemas, setSchemas] = useState<NormalizationSchema[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editSchema, setEditSchema] = useState<NormalizationSchema | null>(null)
  const [detailSchema, setDetailSchema] = useState<NormalizationSchema | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<NormalizationSchema[]>('/api/v2/normalization')
      setSchemas(data)
    } catch {
      setSchemas(SEED_SCHEMAS)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleDelete(id: string) {
    if (!window.confirm('Delete this schema? This action cannot be undone.')) return
    setDeleting(id)
    try {
      await apiDelete(`/api/v2/normalization/${id}`)
      setSchemas((prev) => prev.filter((s) => s.id !== id))
    } catch { /* continue */ } finally {
      setDeleting(null)
    }
  }

  return (
    <>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-lg font-semibold text-foreground">Data Normalization Schemas</h1>
            <p className="text-sm text-muted-foreground mt-0.5">Manage SIEM field mappings, datasets, and data models with AI parsing</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => void load()} className="rounded border border-border bg-muted/40 hover:bg-muted p-2 text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
            <button onClick={() => setShowModal(true)} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 transition-colors">
              <Plus className="h-3.5 w-3.5" />
              New Schema
            </button>
          </div>
        </div>

        {/* Table */}
        {loading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading schemas…
          </div>
        ) : schemas.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3 text-sm text-muted-foreground rounded-lg border border-dashed border-border">
            <GitCompare className="h-8 w-8 opacity-30" />
            <p>No normalization schemas yet.</p>
            <button onClick={() => setShowModal(true)} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 transition-colors">
              <Plus className="h-3.5 w-3.5" />
              Create First Schema
            </button>
          </div>
        ) : (
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted/60 text-muted-foreground border-b border-border">
                <tr>
                  <th className="text-left px-4 py-2.5 font-medium">Schema Name</th>
                  <th className="text-left px-4 py-2.5 font-medium w-20">Version</th>
                  <th className="text-left px-4 py-2.5 font-medium w-24">Platform</th>
                  <th className="text-left px-4 py-2.5 font-medium w-20">Fields</th>
                  <th className="text-left px-4 py-2.5 font-medium w-24">Updated</th>
                  <th className="text-right px-4 py-2.5 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {schemas.map((schema) => (
                  <tr key={schema.id} className="border-b border-border hover:bg-muted/40 transition-colors">
                    <td className="px-4 py-3">
                      <div>
                        <button
                          onClick={() => setDetailSchema(schema)}
                          className="font-medium text-foreground hover:text-primary transition-colors text-left"
                        >
                          {schema.name}
                        </button>
                        {schema.description && <p className="text-muted-foreground mt-0.5 truncate max-w-xs">{schema.description}</p>}
                        <div className="flex gap-2 mt-1">
                          {schema.ai_parsed && <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400">AI parsed</span>}
                          {schema.source_file_name && <span className="text-[10px] text-muted-foreground truncate">{schema.source_file_name}</span>}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{schema.version_label}</span>
                    </td>
                    <td className="px-4 py-3"><SiemBadge platform={schema.siem_platform} /></td>
                    <td className="px-4 py-3 text-muted-foreground">{schema.fields.length}</td>
                    <td className="px-4 py-3 text-muted-foreground">{relativeDate(schema.updated_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 justify-end">
                        <button
                          onClick={() => setDetailSchema(schema)}
                          className="rounded border border-border bg-muted/40 hover:bg-muted px-2 py-1 text-[11px] text-foreground transition-colors flex items-center gap-1"
                        >
                          <History className="h-3 w-3" />
                          History
                        </button>
                        <button
                          onClick={() => setEditSchema(schema)}
                          className="rounded p-1.5 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
                          title="Edit"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => void handleDelete(schema.id)}
                          disabled={deleting === schema.id}
                          className="rounded p-1.5 text-muted-foreground hover:text-red-400 transition-colors disabled:opacity-50"
                          title="Delete"
                        >
                          {deleting === schema.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create modal */}
      {showModal && <SchemaModal onClose={() => setShowModal(false)} onSaved={() => { void load(); setShowModal(false) }} />}

      {/* Edit modal */}
      {editSchema && <SchemaModal initial={editSchema} onClose={() => setEditSchema(null)} onSaved={() => { void load(); setEditSchema(null) }} />}

      {/* Detail view */}
      {detailSchema && <SchemaDetailView schema={detailSchema} onClose={() => setDetailSchema(null)} onUpdate={() => { void load(); setDetailSchema(null) }} />}
    </>
  )
}
