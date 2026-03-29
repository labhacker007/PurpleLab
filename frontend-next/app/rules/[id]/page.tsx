'use client'

import { use, useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import {
  ArrowLeft,
  Play,
  Loader2,
  Check,
  X,
  AlertCircle,
  Pencil,
  Save,
  Tag,
  ExternalLink,
  Clock,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface DetectionRule {
  id: string
  name: string
  language: string
  severity: Severity
  description?: string
  raw_text?: string
  mitre_techniques?: string[]
  tags?: string[]
  enabled?: boolean
  created_at?: string
  has_filter?: boolean
  has_aggregation?: boolean
  referenced_fields?: string[]
  data_sources?: string[]
}

interface SingleTestResult {
  matched: boolean
  match_count: number
  details: string
  evaluation_time_ms: number
}

// ─── Severity / language styles ───────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 border border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
}

const LANG_STYLES: Record<string, string> = {
  sigma: 'bg-purple-500/15 text-purple-300 border border-purple-500/30',
  spl: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  kql: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  esql: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  yara_l: 'bg-pink-500/15 text-pink-300 border border-pink-500/30',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium capitalize', SEVERITY_STYLES[severity])}>
      {severity}
    </span>
  )
}

function LangBadge({ lang }: { lang: string }) {
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-mono font-medium uppercase', LANG_STYLES[lang] ?? 'bg-slate-500/15 text-slate-300 border border-slate-500/30')}>
      {lang}
    </span>
  )
}

/** Simple line-numbered code display without an external library. */
function CodeView({ content, language }: { content: string; language: string }) {
  const lines = content.split('\n')
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-950 overflow-hidden">
      {/* Language label */}
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2">
        <span className="text-[11px] font-mono text-slate-500">{language}</span>
        <span className="text-[11px] text-slate-600">{lines.length} lines</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[12px] font-mono leading-relaxed">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                <td className="select-none text-right pr-4 pl-3 py-0 text-slate-600 w-10 shrink-0 border-r border-slate-800/50 tabular-nums">
                  {i + 1}
                </td>
                <td className="pl-4 pr-4 py-0 text-slate-300 whitespace-pre">
                  {line || ' '}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Editable textarea that mirrors the line-number style. */
function CodeEditor({
  value,
  onChange,
}: {
  value: string
  onChange: (v: string) => void
}) {
  return (
    <div className="rounded-lg border border-cyan-500/40 bg-slate-950 overflow-hidden">
      <div className="border-b border-slate-800 px-4 py-2">
        <span className="text-[11px] font-mono text-cyan-400">editing</span>
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        className="w-full bg-transparent px-4 py-3 text-[12px] font-mono text-slate-200 leading-relaxed resize-none focus:outline-none min-h-[300px]"
        style={{ tabSize: 2 }}
      />
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function RuleDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)

  const [rule, setRule] = useState<DetectionRule | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  // Edit mode
  const [editMode, setEditMode] = useState(false)
  const [editContent, setEditContent] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Test panel
  const [eventJson, setEventJson] = useState('')
  const [eventJsonError, setEventJsonError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<SingleTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)

  // Load rule
  const loadRule = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<DetectionRule>(`/api/v2/rules/${id}`)
      setRule(data)
      setEditContent(data.raw_text ?? '')
    } catch {
      setNotFound(true)
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    void loadRule()
  }, [loadRule])

  // Save edited content (re-import over the same id via PUT)
  async function handleSave() {
    if (!rule) return
    setSaving(true)
    setSaveError(null)
    try {
      const updated = await apiPost<DetectionRule>(`/api/v2/rules/${rule.id}`, {
        raw_text: editContent,
      })
      setRule(updated)
      setEditMode(false)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  // Test single event
  async function handleTest() {
    setEventJsonError(null)
    setTestError(null)
    let eventObj: Record<string, unknown>
    try {
      eventObj = JSON.parse(eventJson || '{}') as Record<string, unknown>
    } catch {
      setEventJsonError('Invalid JSON')
      return
    }
    setTesting(true)
    setTestResult(null)
    try {
      const result = await apiPost<SingleTestResult>(`/api/v2/rules/${id}/test`, { event: eventObj })
      setTestResult(result)
    } catch (err) {
      setTestError(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setTesting(false)
    }
  }

  // ── Render states ──────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 gap-2 text-sm text-slate-500">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading rule…
      </div>
    )
  }

  if (notFound || !rule) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4 text-sm text-slate-500">
        <AlertCircle className="h-8 w-8 text-slate-600" />
        <p>Rule not found.</p>
        <Link
          href="/rules"
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Rules
        </Link>
      </div>
    )
  }

  const mitreTechs = rule.mitre_techniques ?? []
  const rawContent = rule.raw_text ?? ''

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-16">
      {/* ── Breadcrumb / header ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Link
            href="/rules"
            className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Rules
          </Link>
          <ChevronRight className="h-3 w-3 text-slate-700" />
          <span className="text-xs text-slate-400 max-w-xs truncate">{rule.name}</span>
        </div>

        <div className="flex items-center gap-2">
          {editMode ? (
            <>
              <button
                onClick={() => { setEditMode(false); setEditContent(rule.raw_text ?? '') }}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
              >
                <X className="h-3.5 w-3.5" />
                Cancel
              </button>
              <button
                onClick={() => void handleSave()}
                disabled={saving}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-medium text-white hover:bg-cyan-500 disabled:opacity-50 transition-colors"
              >
                {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                {saving ? 'Saving…' : 'Save Changes'}
              </button>
            </>
          ) : (
            <button
              onClick={() => { setEditMode(true); setEditContent(rawContent) }}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <Pencil className="h-3.5 w-3.5" />
              Edit Rule
            </button>
          )}
        </div>
      </div>

      {/* Rule name + badges */}
      <div className="space-y-3">
        <h1 className="text-2xl font-bold text-slate-100 leading-tight">{rule.name}</h1>
        <div className="flex items-center gap-2 flex-wrap">
          <LangBadge lang={rule.language} />
          <SeverityBadge severity={rule.severity} />
          {rule.enabled !== undefined && (
            <span className={cn('rounded-md px-2 py-0.5 text-xs font-medium border', rule.enabled ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' : 'bg-slate-500/15 text-slate-400 border-slate-600/30')}>
              {rule.enabled ? 'Enabled' : 'Disabled'}
            </span>
          )}
          {rule.created_at && (
            <span className="flex items-center gap-1 text-[11px] text-slate-600">
              <Clock className="h-3 w-3" />
              {new Date(rule.created_at).toLocaleDateString()}
            </span>
          )}
        </div>
        {rule.description && (
          <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">{rule.description}</p>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Left column: rule content (2/3 wide) ── */}
        <div className="lg:col-span-2 space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Rule Content</h2>
            </div>
            {editMode ? (
              <CodeEditor value={editContent} onChange={setEditContent} />
            ) : (
              <CodeView content={rawContent} language={rule.language} />
            )}
            {saveError && (
              <p className="mt-2 text-xs text-red-400 flex items-center gap-1">
                <AlertCircle className="h-3 w-3" /> {saveError}
              </p>
            )}
          </div>

          {/* Test Rule panel */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Test Rule</h2>
              <button
                onClick={() => void handleTest()}
                disabled={testing}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600/20 border border-cyan-500/40 px-3 py-1.5 text-xs text-cyan-300 hover:bg-cyan-600/30 disabled:opacity-50 transition-colors"
              >
                {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                {testing ? 'Running…' : 'Run Test'}
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <label className="text-[11px] text-slate-500 font-medium block mb-1.5">
                  Paste a sample event JSON
                </label>
                <textarea
                  value={eventJson}
                  onChange={(e) => { setEventJson(e.target.value); setEventJsonError(null) }}
                  placeholder={'{\n  "CommandLine": "-EncodedCommand abc",\n  "Image": "powershell.exe",\n  "ParentImage": "explorer.exe"\n}'}
                  rows={6}
                  className={cn(
                    'w-full rounded-lg border bg-slate-950 px-3 py-2 text-[12px] font-mono text-slate-200 placeholder:text-slate-700 focus:outline-none resize-none',
                    eventJsonError ? 'border-red-500/50' : 'border-slate-700 focus:border-cyan-500'
                  )}
                />
                {eventJsonError && (
                  <p className="mt-1 text-[11px] text-red-400">{eventJsonError}</p>
                )}
              </div>

              {testError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300 flex items-center gap-2">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" />
                  {testError}
                </div>
              )}

              {testResult && (
                <div className={cn('rounded-lg border p-4 space-y-3', testResult.matched ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-slate-700 bg-slate-800/50')}>
                  <div className="flex items-center gap-2">
                    {testResult.matched ? (
                      <Check className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <X className="h-4 w-4 text-slate-400" />
                    )}
                    <span className={cn('text-sm font-semibold', testResult.matched ? 'text-emerald-300' : 'text-slate-300')}>
                      {testResult.matched ? 'Rule Matched' : 'No Match'}
                    </span>
                    <span className="ml-auto text-xs text-slate-600">
                      {Math.round(testResult.evaluation_time_ms)}ms
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-slate-400">
                    <span>
                      Match count:{' '}
                      <span className="text-slate-200 font-medium">{testResult.match_count}</span>
                    </span>
                  </div>
                  {testResult.details && (
                    <p className="text-[11px] text-slate-400 leading-relaxed">{testResult.details}</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Right column: metadata ── */}
        <div className="space-y-4">
          {/* MITRE Techniques */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">MITRE ATT&amp;CK</h2>
            {mitreTechs.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {mitreTechs.map((tid) => (
                  <Link
                    key={tid}
                    href={`/mitre?technique=${tid}`}
                    className="group flex items-center gap-1 rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-1 text-[11px] font-mono text-purple-300 hover:bg-purple-500/25 transition-colors"
                  >
                    {tid}
                    <ExternalLink className="h-2.5 w-2.5 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </Link>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-600">No MITRE tags</p>
            )}
          </div>

          {/* Tags */}
          {(rule.tags ?? []).length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
              <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tags</h2>
              <div className="flex flex-wrap gap-1">
                {(rule.tags ?? []).map((tag) => (
                  <span
                    key={tag}
                    className="flex items-center gap-1 rounded bg-slate-700/60 border border-slate-600/40 px-2 py-0.5 text-[10px] text-slate-400"
                  >
                    <Tag className="h-2.5 w-2.5" />
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Rule metadata */}
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Metadata</h2>
            <dl className="space-y-2 text-xs">
              {rule.data_sources && rule.data_sources.length > 0 && (
                <div>
                  <dt className="text-slate-500 mb-0.5">Data Sources</dt>
                  {rule.data_sources.map((ds) => (
                    <dd key={ds} className="text-slate-300 font-mono">{ds}</dd>
                  ))}
                </div>
              )}
              {rule.referenced_fields && rule.referenced_fields.length > 0 && (
                <div>
                  <dt className="text-slate-500 mb-0.5">Referenced Fields</dt>
                  <dd className="flex flex-wrap gap-1">
                    {rule.referenced_fields.map((f) => (
                      <span key={f} className="rounded bg-slate-800 border border-slate-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{f}</span>
                    ))}
                  </dd>
                </div>
              )}
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Filter</dt>
                <dd className={cn('font-medium', rule.has_filter ? 'text-emerald-400' : 'text-slate-600')}>
                  {rule.has_filter ? 'Yes' : 'None'}
                </dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-slate-500">Aggregation</dt>
                <dd className={cn('font-medium', rule.has_aggregation ? 'text-cyan-400' : 'text-slate-600')}>
                  {rule.has_aggregation ? 'Yes' : 'None'}
                </dd>
              </div>
              {rule.created_at && (
                <div className="flex items-center justify-between">
                  <dt className="text-slate-500">Created</dt>
                  <dd className="text-slate-300">{new Date(rule.created_at).toLocaleString()}</dd>
                </div>
              )}
            </dl>
          </div>

          {/* Version history placeholder */}
          <div className="rounded-xl border border-dashed border-slate-800 p-4 space-y-1">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Version History</h2>
            <p className="text-[11px] text-slate-600">Coming soon — rule version tracking will appear here.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
