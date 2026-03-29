'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Upload,
  Search,
  ChevronDown,
  ChevronRight,
  Check,
  Trash2,
  PlayCircle,
  Grid3X3,
  AlertCircle,
  Loader2,
  FileText,
  RefreshCw,
  X,
  Link,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Drawer } from '@/components/ui/Drawer'
import { apiGet, apiPost, apiDelete } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

type RuleLanguage = 'sigma' | 'spl' | 'kql' | 'esql'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface MitreTechnique {
  id: string
  name: string
  tactic: string
}

interface DetectionRule {
  id: string
  name: string
  language: RuleLanguage
  severity: Severity
  techniques: MitreTechnique[]
  enabled: boolean
  source: string
  description?: string
  created_at: string
  updated_at: string
}

interface TestResult {
  passed: boolean
  matched_events: number
  false_positives: number
  error?: string
  duration_ms: number
}

interface CoverageCell {
  tactic: string
  technique_id: string
  technique_name: string
  coverage: number // 0–100
}

// ─── Constants ────────────────────────────────────────────────────────────────

const LANGUAGE_STYLES: Record<RuleLanguage, string> = {
  sigma: 'bg-purple-500/15 text-purple-300 border border-purple-500/30',
  spl: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  kql: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  esql: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 border border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const LANGUAGES: RuleLanguage[] = ['sigma', 'spl', 'kql', 'esql']

const PAGE_SIZE = 20

// ─── Seed data (dev fallback) ─────────────────────────────────────────────────

const SEED_RULES: DetectionRule[] = [
  {
    id: '1',
    name: 'Mimikatz LSASS Access',
    language: 'sigma',
    severity: 'critical',
    techniques: [{ id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' }],
    enabled: true,
    source: 'title: Mimikatz\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|contains: lsass.exe',
    description: 'Detects Mimikatz credential dumping via LSASS process access',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '2',
    name: 'PowerShell Encoded Command',
    language: 'sigma',
    severity: 'high',
    techniques: [
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
      { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion' },
    ],
    enabled: true,
    source: "title: PS Encoded\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'",
    description: 'Detects PowerShell with encoded command line arguments',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '3',
    name: 'Splunk - Lateral Movement RDP',
    language: 'spl',
    severity: 'high',
    techniques: [{ id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' }],
    enabled: false,
    source: 'index=wineventlog EventCode=4624 Logon_Type=10\n| stats count by src_ip, dest_ip, user',
    description: 'Detects RDP lateral movement via Windows Event 4624',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '4',
    name: 'Sentinel - DNS Tunneling',
    language: 'kql',
    severity: 'medium',
    techniques: [{ id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' }],
    enabled: true,
    source: 'DnsEvents\n| where QueryType == "TXT"\n| where strlen(Name) > 50\n| summarize count() by Name, ClientIP',
    description: 'Detects potential DNS tunneling via long TXT record queries',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: '5',
    name: 'Elastic - Ransomware File Rename',
    language: 'esql',
    severity: 'critical',
    techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' }],
    enabled: true,
    source: 'FROM logs-endpoint*\n| WHERE event.type == "file" AND file.extension IN ("locked","encrypted","ransom")\n| STATS count = COUNT() BY host.name',
    description: 'Detects mass file rename indicative of ransomware encryption',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
]

// ─── Utility components ───────────────────────────────────────────────────────

function LangBadge({ lang }: { lang: RuleLanguage }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-mono font-medium uppercase',
        LANGUAGE_STYLES[lang]
      )}
    >
      {lang}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium capitalize',
        SEVERITY_STYLES[severity]
      )}
    >
      {severity}
    </span>
  )
}

function Toggle({
  checked,
  onChange,
}: {
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500',
        checked ? 'bg-cyan-600' : 'bg-slate-700'
      )}
    >
      <span
        className={cn(
          'inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform',
          checked ? 'translate-x-[18px]' : 'translate-x-1'
        )}
      />
    </button>
  )
}

// ─── Coverage heatmap ─────────────────────────────────────────────────────────

function CoverageHeatmap({ cells }: { cells: CoverageCell[] }) {
  const tactics = [...new Set(cells.map((c) => c.tactic))]

  function coverageColor(pct: number): string {
    if (pct === 0) return 'bg-slate-800'
    if (pct < 25) return 'bg-cyan-900/60'
    if (pct < 50) return 'bg-cyan-700/60'
    if (pct < 75) return 'bg-cyan-600/70'
    return 'bg-cyan-500/80'
  }

  return (
    <div className="space-y-3 overflow-x-auto">
      {tactics.map((tactic) => {
        const tacticCells = cells.filter((c) => c.tactic === tactic)
        return (
          <div key={tactic}>
            <p className="text-xs font-medium text-slate-400 mb-1.5">{tactic}</p>
            <div className="flex flex-wrap gap-1">
              {tacticCells.map((cell) => (
                <div
                  key={cell.technique_id}
                  title={`${cell.technique_id} — ${cell.technique_name} (${cell.coverage}%)`}
                  className={cn(
                    'flex items-center justify-center rounded text-[9px] font-mono text-white/80 cursor-default transition-colors hover:brightness-110',
                    coverageColor(cell.coverage),
                    'h-8 w-16 shrink-0'
                  )}
                >
                  {cell.technique_id}
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Import drawer content ────────────────────────────────────────────────────

type ImportSource = 'paste' | 'file' | 'siem'

interface ImportDrawerProps {
  onClose: () => void
  onImported: () => void
}

function ImportDrawerContent({ onClose, onImported }: ImportDrawerProps) {
  const [source, setSource] = useState<ImportSource>('paste')
  const [text, setText] = useState('')
  const [detectedLang, setDetectedLang] = useState<RuleLanguage | null>(null)
  const [detecting, setDetecting] = useState(false)
  const [preview, setPreview] = useState<Partial<DetectionRule> | null>(null)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  async function detectLanguage(content: string) {
    if (!content.trim()) return
    setDetecting(true)
    try {
      const res = await apiPost<{ language: RuleLanguage; preview: Partial<DetectionRule> }>(
        '/api/v2/rules/detect-language',
        { content }
      )
      setDetectedLang(res.language)
      setPreview(res.preview)
    } catch {
      // Heuristic fallback
      if (content.includes('title:') && content.includes('detection:')) {
        setDetectedLang('sigma')
      } else if (content.toLowerCase().includes('index=') || content.toLowerCase().includes('sourcetype')) {
        setDetectedLang('spl')
      } else if (content.includes('| where') || content.includes('summarize')) {
        setDetectedLang('kql')
      } else if (content.toUpperCase().includes('FROM ') && content.includes('|')) {
        setDetectedLang('esql')
      }
    } finally {
      setDetecting(false)
    }
  }

  function handleTextChange(v: string) {
    setText(v)
    if (v.length > 20) {
      const timeout = setTimeout(() => void detectLanguage(v), 600)
      return () => clearTimeout(timeout)
    }
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const content = ev.target?.result as string
      setText(content)
      void detectLanguage(content)
    }
    reader.readAsText(file)
  }

  async function handleImport() {
    if (!text.trim()) return
    setImporting(true)
    setError(null)
    try {
      await apiPost('/api/v2/rules/import', {
        content: text,
        language: detectedLang,
      })
      onImported()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="p-5 space-y-5">
      {/* Source tabs */}
      <div className="flex rounded-lg border border-slate-700 overflow-hidden">
        {(
          [
            { key: 'paste', label: 'Paste Text', icon: FileText },
            { key: 'file', label: 'Upload File', icon: Upload },
            { key: 'siem', label: 'From SIEM', icon: Link },
          ] as const
        ).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setSource(key)}
            className={cn(
              'flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors',
              source === key
                ? 'bg-cyan-600/20 text-cyan-400 border-b-2 border-cyan-500'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Paste text */}
      {source === 'paste' && (
        <div className="space-y-2">
          <label className="text-xs font-medium text-slate-400">Rule Content</label>
          <textarea
            value={text}
            onChange={(e) => handleTextChange(e.target.value)}
            placeholder="Paste your Sigma, SPL, KQL, or ES|QL rule here…"
            rows={10}
            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
          />
        </div>
      )}

      {/* Upload file */}
      {source === 'file' && (
        <div
          className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-700 p-8 cursor-pointer hover:border-cyan-500/50 transition-colors"
          onClick={() => fileRef.current?.click()}
        >
          <Upload className="h-8 w-8 text-slate-500 mb-2" />
          <p className="text-sm text-slate-400">Drop a rule file or click to browse</p>
          <p className="text-xs text-slate-600 mt-1">.yml, .yaml, .spl, .kql, .esql</p>
          <input
            ref={fileRef}
            type="file"
            accept=".yml,.yaml,.spl,.kql,.esql,.txt"
            onChange={handleFile}
            className="hidden"
          />
          {text && (
            <div className="mt-3 text-xs text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" />
              File loaded ({text.length} chars)
            </div>
          )}
        </div>
      )}

      {/* SIEM connection */}
      {source === 'siem' && (
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4 text-sm text-slate-400 text-center">
          <p>SIEM connection import is configured in</p>
          <p className="text-cyan-400 mt-1">Settings → Integrations</p>
        </div>
      )}

      {/* Language detection result */}
      {(detecting || detectedLang) && (
        <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2">
          {detecting ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" />
          ) : (
            <Check className="h-3.5 w-3.5 text-emerald-400" />
          )}
          <span className="text-xs text-slate-400">
            {detecting ? 'Detecting language…' : 'Detected:'}
          </span>
          {detectedLang && !detecting && <LangBadge lang={detectedLang} />}
        </div>
      )}

      {/* Preview */}
      {preview && (
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4 space-y-2">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Preview</p>
          {preview.name && (
            <p className="text-sm font-medium text-slate-200">{preview.name}</p>
          )}
          {preview.severity && <SeverityBadge severity={preview.severity} />}
          {preview.techniques && preview.techniques.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {preview.techniques.map((t) => (
                <span
                  key={t.id}
                  className="rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-[11px] font-mono text-purple-300"
                >
                  {t.id}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
          <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
          {error}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-2 pt-1">
        <button
          onClick={onClose}
          className="flex-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => void handleImport()}
          disabled={!text.trim() || importing}
          className="flex-1 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        >
          {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
          {importing ? 'Importing…' : 'Import Rule'}
        </button>
      </div>
    </div>
  )
}

// ─── Rule detail drawer ───────────────────────────────────────────────────────

interface RuleDetailProps {
  rule: DetectionRule
  onClose: () => void
  onToggle: (id: string, enabled: boolean) => void
  onDelete: (id: string) => void
}

function RuleDetailContent({ rule, onClose, onToggle, onDelete }: RuleDetailProps) {
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<TestResult | null>(null)

  async function runTest() {
    setTesting(true)
    setTestResult(null)
    try {
      const result = await apiPost<TestResult>('/api/v2/rules/test', { rule_id: rule.id })
      setTestResult(result)
    } catch (err) {
      setTestResult({
        passed: false,
        matched_events: 0,
        false_positives: 0,
        error: err instanceof Error ? err.message : 'Test failed',
        duration_ms: 0,
      })
    } finally {
      setTesting(false)
    }
  }

  return (
    <div className="p-5 space-y-5">
      {/* Header info */}
      <div className="space-y-2">
        <div className="flex items-start gap-2 flex-wrap">
          <LangBadge lang={rule.language} />
          <SeverityBadge severity={rule.severity} />
        </div>
        <h3 className="text-base font-semibold text-slate-100">{rule.name}</h3>
        {rule.description && (
          <p className="text-xs text-slate-400 leading-relaxed">{rule.description}</p>
        )}
      </div>

      {/* MITRE techniques */}
      {rule.techniques.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">
            MITRE Techniques
          </p>
          <div className="flex flex-wrap gap-1.5">
            {rule.techniques.map((t) => (
              <a
                key={t.id}
                href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center gap-1 rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-1 text-[11px] font-mono text-purple-300 hover:bg-purple-500/25 transition-colors"
              >
                <span className="font-semibold">{t.id}</span>
                <span className="text-purple-400/60">·</span>
                <span className="text-purple-300/80">{t.name}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Source */}
      <div className="space-y-2">
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Source</p>
        <pre className="rounded-lg border border-slate-700 bg-slate-900 p-3 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
          {rule.source}
        </pre>
      </div>

      {/* Test */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Test Rule</p>
          <button
            onClick={() => void runTest()}
            disabled={testing}
            className="flex items-center gap-1.5 rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-50 transition-colors"
          >
            {testing ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <PlayCircle className="h-3 w-3" />
            )}
            {testing ? 'Testing…' : 'Run Test'}
          </button>
        </div>

        {testResult && (
          <div
            className={cn(
              'rounded-lg border p-3 space-y-2',
              testResult.passed
                ? 'border-emerald-500/30 bg-emerald-500/10'
                : 'border-red-500/30 bg-red-500/10'
            )}
          >
            <div className="flex items-center gap-2">
              {testResult.passed ? (
                <Check className="h-4 w-4 text-emerald-400" />
              ) : (
                <X className="h-4 w-4 text-red-400" />
              )}
              <span
                className={cn(
                  'text-sm font-medium',
                  testResult.passed ? 'text-emerald-300' : 'text-red-300'
                )}
              >
                {testResult.passed ? 'Test Passed' : 'Test Failed'}
              </span>
              <span className="ml-auto text-xs text-slate-500">{testResult.duration_ms}ms</span>
            </div>
            {!testResult.error && (
              <div className="flex gap-4 text-xs text-slate-400">
                <span>
                  Matched events:{' '}
                  <span className="text-slate-200 font-medium">{testResult.matched_events}</span>
                </span>
                <span>
                  False positives:{' '}
                  <span className="text-slate-200 font-medium">{testResult.false_positives}</span>
                </span>
              </div>
            )}
            {testResult.error && (
              <p className="text-xs text-red-300">{testResult.error}</p>
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-1 border-t border-slate-800">
        <Toggle
          checked={rule.enabled}
          onChange={(v) => onToggle(rule.id, v)}
        />
        <span className="text-xs text-slate-400 self-center">
          {rule.enabled ? 'Enabled' : 'Disabled'}
        </span>
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => {
              onDelete(rule.id)
              onClose()
            }}
            className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/20 transition-colors"
          >
            <Trash2 className="h-3 w-3" />
            Delete
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function RulesPage() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [search, setSearch] = useState('')
  const [langFilter, setLangFilter] = useState<RuleLanguage | ''>('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')

  // Pagination
  const [page, setPage] = useState(0)

  // Selection (bulk actions)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Drawers
  const [importDrawerOpen, setImportDrawerOpen] = useState(false)
  const [detailRule, setDetailRule] = useState<DetectionRule | null>(null)

  // Coverage
  const [coverageOpen, setCoverageOpen] = useState(false)
  const [coverageCells, setCoverageCells] = useState<CoverageCell[]>([])
  const [loadingCoverage, setLoadingCoverage] = useState(false)

  // Bulk testing
  const [bulkTesting, setBulkTesting] = useState(false)

  // ── Load rules ────────────────────────────────────────────────────────────

  const loadRules = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiGet<DetectionRule[]>('/api/v2/rules')
      setRules(data)
    } catch {
      setRules(SEED_RULES)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadRules()
  }, [loadRules])

  // ── Filter + paginate ─────────────────────────────────────────────────────

  const filtered = rules.filter((r) => {
    if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false
    if (langFilter && r.language !== langFilter) return false
    if (severityFilter && r.severity !== severityFilter) return false
    return true
  })

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageRules = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  // ── Toggle rule enabled ───────────────────────────────────────────────────

  function toggleRule(id: string, enabled: boolean) {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled } : r)))
  }

  // ── Delete rule ────────────────────────────────────────────────────────────

  async function deleteRule(id: string) {
    try {
      await apiDelete(`/api/v2/rules/${id}`)
    } catch {
      // ignore API errors, remove locally
    }
    setRules((prev) => prev.filter((r) => r.id !== id))
    setSelected((prev) => {
      const next = new Set(prev)
      next.delete(id)
      return next
    })
  }

  // ── Bulk actions ───────────────────────────────────────────────────────────

  async function bulkTest() {
    if (selected.size === 0) return
    setBulkTesting(true)
    try {
      await apiPost('/api/v2/rules/test', { rule_ids: [...selected] })
    } catch {
      // ignore
    } finally {
      setBulkTesting(false)
    }
  }

  async function bulkDelete() {
    if (!window.confirm(`Delete ${selected.size} rules?`)) return
    for (const id of selected) {
      await deleteRule(id)
    }
    setSelected(new Set())
  }

  // ── Coverage ───────────────────────────────────────────────────────────────

  async function loadCoverage() {
    setLoadingCoverage(true)
    try {
      const data = await apiGet<CoverageCell[]>('/api/v2/rules/coverage')
      setCoverageCells(data)
    } catch {
      // mock coverage
      setCoverageCells([
        { tactic: 'Initial Access', technique_id: 'T1566', technique_name: 'Phishing', coverage: 80 },
        { tactic: 'Initial Access', technique_id: 'T1190', technique_name: 'Exploit Public', coverage: 40 },
        { tactic: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', coverage: 90 },
        { tactic: 'Execution', technique_id: 'T1059.003', technique_name: 'Cmd', coverage: 60 },
        { tactic: 'Persistence', technique_id: 'T1547', technique_name: 'Boot Autostart', coverage: 30 },
        { tactic: 'Credential Access', technique_id: 'T1003.001', technique_name: 'LSASS', coverage: 100 },
        { tactic: 'Lateral Movement', technique_id: 'T1021.001', technique_name: 'RDP', coverage: 70 },
        { tactic: 'Command and Control', technique_id: 'T1071.004', technique_name: 'DNS', coverage: 50 },
        { tactic: 'Impact', technique_id: 'T1486', technique_name: 'Ransomware', coverage: 85 },
      ])
    } finally {
      setLoadingCoverage(false)
    }
    setCoverageOpen(true)
  }

  // ── Selection helpers ──────────────────────────────────────────────────────

  const allSelected = pageRules.length > 0 && pageRules.every((r) => selected.has(r.id))

  function toggleSelectAll() {
    if (allSelected) {
      setSelected((prev) => {
        const next = new Set(prev)
        pageRules.forEach((r) => next.delete(r.id))
        return next
      })
    } else {
      setSelected((prev) => {
        const next = new Set(prev)
        pageRules.forEach((r) => next.add(r.id))
        return next
      })
    }
  }

  return (
    <>
      <div className="space-y-4">
        {/* Page header */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Detection Rules</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              {rules.length} rules across {LANGUAGES.length} languages
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadCoverage()}
              disabled={loadingCoverage}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              {loadingCoverage ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Grid3X3 className="h-3.5 w-3.5" />
              )}
              Coverage Matrix
            </button>
            <button
              onClick={() => void loadRules()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
            <button
              onClick={() => setImportDrawerOpen(true)}
              className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-2 text-xs font-medium text-white hover:bg-cyan-500 transition-colors"
            >
              <Upload className="h-3.5 w-3.5" />
              Import Rules
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
              placeholder="Search rules…"
              className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <select
            value={langFilter}
            onChange={(e) => {
              setLangFilter(e.target.value as RuleLanguage | '')
              setPage(0)
            }}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Languages</option>
            {LANGUAGES.map((l) => (
              <option key={l} value={l}>
                {l.toUpperCase()}
              </option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value as Severity | '')
              setPage(0)
            }}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>

        {/* Bulk actions bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2">
            <span className="text-xs text-cyan-300 font-medium">{selected.size} selected</span>
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => void bulkTest()}
                disabled={bulkTesting}
                className="flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors disabled:opacity-50"
              >
                {bulkTesting ? <Loader2 className="h-3 w-3 animate-spin" /> : <PlayCircle className="h-3 w-3" />}
                Test Selected
              </button>
              <button
                onClick={() => void bulkDelete()}
                className="flex items-center gap-1.5 rounded-md bg-red-500/10 border border-red-500/30 px-2.5 py-1.5 text-xs text-red-300 hover:bg-red-500/20 transition-colors"
              >
                <Trash2 className="h-3 w-3" />
                Delete Selected
              </button>
              <button
                onClick={() => setSelected(new Set())}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            {error}
          </div>
        )}

        {/* Table */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden">
          {/* Header */}
          <div className="grid grid-cols-[2rem_2fr_5rem_6rem_1fr_6rem_4rem] gap-3 border-b border-slate-800 px-4 py-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={toggleSelectAll}
                className="rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500"
              />
            </label>
            <span>Rule Name</span>
            <span>Language</span>
            <span>Severity</span>
            <span>MITRE Techniques</span>
            <span className="text-center">Enabled</span>
            <span className="text-center">Actions</span>
          </div>

          {/* Rows */}
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading rules…
            </div>
          ) : pageRules.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-2 text-sm text-slate-500">
              <FileText className="h-8 w-8 text-slate-700" />
              No rules found
            </div>
          ) : (
            <div className="divide-y divide-slate-800">
              {pageRules.map((rule) => (
                <div
                  key={rule.id}
                  className="grid grid-cols-[2rem_2fr_5rem_6rem_1fr_6rem_4rem] gap-3 items-center px-4 py-3 hover:bg-slate-800/50 transition-colors group"
                >
                  <label
                    className="flex items-center cursor-pointer"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(rule.id)}
                      onChange={(e) => {
                        const next = new Set(selected)
                        if (e.target.checked) next.add(rule.id)
                        else next.delete(rule.id)
                        setSelected(next)
                      }}
                      className="rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500"
                    />
                  </label>

                  <button
                    onClick={() => setDetailRule(rule)}
                    className="text-left min-w-0 group/name"
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm font-medium text-slate-200 truncate group-hover/name:text-cyan-400 transition-colors">
                        {rule.name}
                      </span>
                      <ChevronRight className="h-3 w-3 text-slate-600 opacity-0 group-hover/name:opacity-100 shrink-0 transition-opacity" />
                    </div>
                  </button>

                  <LangBadge lang={rule.language} />
                  <SeverityBadge severity={rule.severity} />

                  <div className="flex flex-wrap gap-1 min-w-0">
                    {rule.techniques.slice(0, 3).map((t) => (
                      <span
                        key={t.id}
                        title={t.name}
                        className="rounded bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 text-[10px] font-mono text-purple-400"
                      >
                        {t.id}
                      </span>
                    ))}
                    {rule.techniques.length > 3 && (
                      <span className="text-[10px] text-slate-500">
                        +{rule.techniques.length - 3}
                      </span>
                    )}
                  </div>

                  <div className="flex justify-center">
                    <Toggle
                      checked={rule.enabled}
                      onChange={(v) => toggleRule(rule.id, v)}
                    />
                  </div>

                  <div className="flex justify-center gap-1">
                    <button
                      onClick={() => setDetailRule(rule)}
                      className="rounded p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 transition-colors"
                      title="View details"
                    >
                      <ChevronDown className="h-3.5 w-3.5" />
                    </button>
                    <button
                      onClick={() => void deleteRule(rule.id)}
                      className="rounded p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                      title="Delete rule"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of{' '}
              {filtered.length} rules
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="rounded-md border border-slate-700 px-2.5 py-1 hover:bg-slate-800 disabled:opacity-30 transition-colors"
              >
                Prev
              </button>
              {Array.from({ length: totalPages }, (_, i) => (
                <button
                  key={i}
                  onClick={() => setPage(i)}
                  className={cn(
                    'rounded-md border border-slate-700 px-2.5 py-1 transition-colors',
                    i === page ? 'bg-cyan-600 border-cyan-600 text-white' : 'hover:bg-slate-800'
                  )}
                >
                  {i + 1}
                </button>
              ))}
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="rounded-md border border-slate-700 px-2.5 py-1 hover:bg-slate-800 disabled:opacity-30 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Import drawer */}
      <Drawer
        open={importDrawerOpen}
        onClose={() => setImportDrawerOpen(false)}
        title="Import Detection Rules"
      >
        <ImportDrawerContent
          onClose={() => setImportDrawerOpen(false)}
          onImported={() => void loadRules()}
        />
      </Drawer>

      {/* Rule detail drawer */}
      <Drawer
        open={detailRule !== null}
        onClose={() => setDetailRule(null)}
        title={detailRule?.name ?? 'Rule Details'}
      >
        {detailRule && (
          <RuleDetailContent
            rule={detailRule}
            onClose={() => setDetailRule(null)}
            onToggle={toggleRule}
            onDelete={(id) => void deleteRule(id)}
          />
        )}
      </Drawer>

      {/* Coverage matrix drawer */}
      <Drawer
        open={coverageOpen}
        onClose={() => setCoverageOpen(false)}
        title="MITRE ATT&CK Coverage Matrix"
      >
        <div className="p-5">
          {coverageCells.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
              Loading coverage…
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 mb-4 text-xs text-slate-500">
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-slate-800" /> 0%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-cyan-900/60" /> 1–25%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-cyan-700/60" /> 26–50%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-cyan-600/70" /> 51–75%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-cyan-500/80" /> 76–100%
                </div>
              </div>
              <CoverageHeatmap cells={coverageCells} />
            </>
          )}
        </div>
      </Drawer>
    </>
  )
}
