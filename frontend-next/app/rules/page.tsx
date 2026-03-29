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
  Download,
  ShieldCheck,
  Tag,
  BookOpen,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Drawer } from '@/components/ui/Drawer'
import { apiGet, apiPost, apiDelete, API_BASE } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

type RuleLanguage = 'sigma' | 'spl' | 'kql' | 'esql' | 'yara_l'
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
  mitre_techniques?: string[]
  tags?: string[]
  enabled: boolean
  source?: string
  raw_text?: string
  description?: string
  created_at: string
  updated_at?: string
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

interface ValidateResult {
  results: Array<{
    rule_id?: string
    index?: number
    name?: string
    valid: boolean
    errors: string[]
    warnings: string[]
  }>
  valid: number
  invalid: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const LANGUAGE_STYLES: Record<string, string> = {
  sigma: 'bg-purple-500/15 text-purple-300 border border-purple-500/30',
  spl: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  kql: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  esql: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  yara_l: 'bg-pink-500/15 text-pink-300 border border-pink-500/30',
}

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-300 border border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const LANGUAGES: RuleLanguage[] = ['sigma', 'spl', 'kql', 'esql', 'yara_l']

const PAGE_SIZE = 20

// ─── Sigma Library starters ───────────────────────────────────────────────────

const SIGMA_LIBRARY = [
  {
    key: 'mimikatz',
    label: 'Mimikatz LSASS Access',
    severity: 'critical',
    technique: 'T1003.001',
    content: `title: Mimikatz LSASS Memory Access
status: stable
description: Detects Mimikatz credential dumping via LSASS process access
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1038'
      - '0x40'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001`,
  },
  {
    key: 'psexec',
    label: 'PsExec Remote Execution',
    severity: 'high',
    technique: 'T1569.002',
    content: `title: PsExec Remote Execution
status: stable
description: Detects PsExec usage for remote execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\PSEXESVC.exe'
  selection2:
    CommandLine|contains: 'psexec'
  condition: selection or selection2
level: high
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1569.002`,
  },
  {
    key: 'cred_dump',
    label: 'Credential Dumping via Registry',
    severity: 'critical',
    technique: 'T1003.002',
    content: `title: Credential Dumping via Registry Hive Extraction
status: stable
description: Detects extraction of SAM/SYSTEM/SECURITY registry hives
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'reg save'
      - 'reg export'
    CommandLine|contains:
      - 'sam'
      - 'system'
      - 'security'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.002`,
  },
  {
    key: 'lateral_wmi',
    label: 'Lateral Movement via WMI',
    severity: 'high',
    technique: 'T1021.006',
    content: `title: Lateral Movement via WMI
status: stable
description: Detects lateral movement using Windows Management Instrumentation
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\\WmiPrvSE.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\wscript.exe'
  condition: selection
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.006`,
  },
  {
    key: 'ps_encoded',
    label: 'PowerShell Encoded Command',
    severity: 'high',
    technique: 'T1059.001',
    content: `title: PowerShell Encoded Command Execution
status: stable
description: Detects PowerShell executing base64 encoded commands
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
  condition: selection
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001`,
  },
  {
    key: 'rdp_brute',
    label: 'RDP Brute Force',
    severity: 'medium',
    technique: 'T1110.001',
    content: `title: RDP Brute Force Attempt
status: stable
description: Detects repeated RDP authentication failures indicative of brute force
logsource:
  category: authentication
  product: windows
detection:
  selection:
    EventID: 4625
    LogonType: 10
  condition: selection | count() by IpAddress > 10
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001`,
  },
  {
    key: 'dns_tunnel',
    label: 'DNS Tunneling Detection',
    severity: 'medium',
    technique: 'T1071.004',
    content: `title: DNS Tunneling via Long Subdomain Queries
status: experimental
description: Detects potential DNS tunneling via unusually long DNS queries
logsource:
  category: dns
  product: windows
detection:
  selection:
    QueryName|re: '.{50,}'
    QueryType: 'A'
  condition: selection
level: medium
tags:
  - attack.command_and_control
  - attack.t1071.004`,
  },
  {
    key: 'ransomware',
    label: 'Ransomware Mass File Modification',
    severity: 'critical',
    technique: 'T1486',
    content: `title: Ransomware Mass File Modification
status: stable
description: Detects mass file renames or encryption typical of ransomware
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith:
      - '.locked'
      - '.encrypted'
      - '.crypted'
      - '.enc'
      - '.ransom'
  condition: selection | count() by ComputerName > 20
level: critical
tags:
  - attack.impact
  - attack.t1486`,
  },
]

// ─── Seed data (dev fallback) ─────────────────────────────────────────────────

const SEED_RULES: DetectionRule[] = [
  {
    id: '1',
    name: 'Mimikatz LSASS Access',
    language: 'sigma',
    severity: 'critical',
    techniques: [{ id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' }],
    mitre_techniques: ['T1003.001'],
    tags: ['attack.credential_access', 'attack.t1003.001'],
    enabled: true,
    raw_text: 'title: Mimikatz\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|contains: lsass.exe\n  condition: selection',
    description: 'Detects Mimikatz credential dumping via LSASS process access',
    created_at: new Date().toISOString(),
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
    mitre_techniques: ['T1059.001', 'T1027'],
    tags: ['attack.execution', 'attack.t1059.001'],
    enabled: true,
    raw_text: "title: PS Encoded\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection",
    description: 'Detects PowerShell with encoded command line arguments',
    created_at: new Date().toISOString(),
  },
  {
    id: '3',
    name: 'Splunk - Lateral Movement RDP',
    language: 'spl',
    severity: 'high',
    techniques: [{ id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' }],
    mitre_techniques: ['T1021.001'],
    tags: [],
    enabled: false,
    raw_text: 'index=wineventlog EventCode=4624 Logon_Type=10\n| stats count by src_ip, dest_ip, user',
    description: 'Detects RDP lateral movement via Windows Event 4624',
    created_at: new Date().toISOString(),
  },
  {
    id: '4',
    name: 'Sentinel - DNS Tunneling',
    language: 'kql',
    severity: 'medium',
    techniques: [{ id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' }],
    mitre_techniques: ['T1071.004'],
    tags: [],
    enabled: true,
    raw_text: 'DnsEvents\n| where QueryType == "TXT"\n| where strlen(Name) > 50\n| summarize count() by Name, ClientIP',
    description: 'Detects potential DNS tunneling via long TXT record queries',
    created_at: new Date().toISOString(),
  },
  {
    id: '5',
    name: 'Elastic - Ransomware File Rename',
    language: 'esql',
    severity: 'critical',
    techniques: [{ id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' }],
    mitre_techniques: ['T1486'],
    tags: ['attack.impact', 'attack.t1486'],
    enabled: true,
    raw_text: 'FROM logs-endpoint*\n| WHERE event.type == "file" AND file.extension IN ("locked","encrypted","ransom")\n| STATS count = COUNT() BY host.name',
    description: 'Detects mass file rename indicative of ransomware encryption',
    created_at: new Date().toISOString(),
  },
]

// ─── Utility components ───────────────────────────────────────────────────────

function LangBadge({ lang }: { lang: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-mono font-medium uppercase',
        LANGUAGE_STYLES[lang] ?? 'bg-slate-500/15 text-slate-300 border border-slate-500/30'
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

// ─── Batch validate modal ─────────────────────────────────────────────────────

function BatchValidateModal({
  onClose,
  ruleIds,
}: {
  onClose: () => void
  ruleIds: string[]
}) {
  const [result, setResult] = useState<ValidateResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    void (async () => {
      try {
        const data = await apiPost<ValidateResult>('/api/v2/rules/validate/batch', {
          rule_ids: ruleIds,
        })
        setResult(data)
      } catch (err) {
        setResult({
          results: [{ valid: false, errors: [err instanceof Error ? err.message : 'Validation failed'], warnings: [] }],
          valid: 0,
          invalid: 1,
        })
      } finally {
        setLoading(false)
      }
    })()
  }, [ruleIds])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-950 shadow-2xl mx-4">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Batch Validation Results</h2>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {loading ? (
            <div className="flex items-center justify-center py-8 gap-2 text-sm text-slate-400">
              <Loader2 className="h-4 w-4 animate-spin" />
              Validating rules…
            </div>
          ) : result ? (
            <>
              {/* Summary row */}
              <div className="flex items-center gap-3">
                <div className="flex-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-center">
                  <p className="text-2xl font-bold text-emerald-400">{result.valid}</p>
                  <p className="text-xs text-emerald-300/70 mt-0.5">Valid</p>
                </div>
                <div className="flex-1 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-center">
                  <p className="text-2xl font-bold text-red-400">{result.invalid}</p>
                  <p className="text-xs text-red-300/70 mt-0.5">Invalid</p>
                </div>
              </div>

              {/* Per-rule list */}
              {result.results.length > 0 && (
                <div className="space-y-1.5 max-h-64 overflow-y-auto">
                  {result.results.map((r, i) => (
                    <div
                      key={i}
                      className={cn(
                        'rounded-lg border px-3 py-2',
                        r.valid
                          ? 'border-emerald-500/20 bg-emerald-500/5'
                          : 'border-red-500/20 bg-red-500/5'
                      )}
                    >
                      <div className="flex items-center gap-2">
                        {r.valid ? (
                          <Check className="h-3 w-3 text-emerald-400 shrink-0" />
                        ) : (
                          <X className="h-3 w-3 text-red-400 shrink-0" />
                        )}
                        <span className="text-xs text-slate-300 truncate">
                          {r.name ?? r.rule_id ?? `Rule ${i + 1}`}
                        </span>
                      </div>
                      {r.errors.length > 0 && (
                        <div className="mt-1 space-y-0.5 pl-5">
                          {r.errors.map((e, j) => (
                            <p key={j} className="text-[11px] text-red-300">{e}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : null}
        </div>

        <div className="border-t border-slate-800 px-5 py-3 flex justify-end">
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Import drawer content ────────────────────────────────────────────────────

type ImportTab = 'paste' | 'upload' | 'library'

interface ImportDrawerProps {
  onClose: () => void
  onImported: () => void
}

function ImportDrawerContent({ onClose, onImported }: ImportDrawerProps) {
  const [tab, setTab] = useState<ImportTab>('paste')
  const [text, setText] = useState('')
  const [detectedLang, setDetectedLang] = useState<string | null>(null)
  const [detecting, setDetecting] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [importCount, setImportCount] = useState<number | null>(null)

  // Upload tab
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadDrag, setUploadDrag] = useState(false)
  const [uploading, setUploading] = useState(false)

  // Library tab
  const [selected, setSelected] = useState<Set<string>>(new Set())

  async function detectLanguage(content: string) {
    if (!content.trim()) return
    setDetecting(true)
    try {
      const res = await apiPost<{ language: string }>('/api/v2/rules/detect-language', { content })
      setDetectedLang(res.language)
    } catch {
      if (content.includes('title:') && content.includes('detection:')) setDetectedLang('sigma')
      else if (content.toLowerCase().includes('index=')) setDetectedLang('spl')
      else if (content.includes('| where') || content.includes('summarize')) setDetectedLang('kql')
      else if (content.toUpperCase().includes('FROM ') && content.includes('|')) setDetectedLang('esql')
    } finally {
      setDetecting(false)
    }
  }

  function handleTextChange(v: string) {
    setText(v)
    if (v.length > 20) {
      const t = setTimeout(() => void detectLanguage(v), 600)
      return () => clearTimeout(t)
    }
  }

  async function handlePasteImport() {
    if (!text.trim()) return
    setImporting(true)
    setError(null)
    setImportCount(null)
    try {
      // Use bulk import endpoint so --- separators work
      const sections = text.split(/\n---\n|\n---$/).filter((s) => s.trim())
      const res = await apiPost<{ imported: number; failed: Array<{ index: number; error: string }> }>(
        '/api/v2/rules/import/bulk',
        { rules: sections.map((content) => ({ content, format: detectedLang ?? 'auto' })) }
      )
      setImportCount(res.imported)
      if (res.imported > 0) {
        onImported()
        setTimeout(onClose, 1200)
      } else {
        setError(`All ${res.failed.length} rules failed. First error: ${res.failed[0]?.error}`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  function handleFileDrop(e: React.DragEvent) {
    e.preventDefault()
    setUploadDrag(false)
    const file = e.dataTransfer.files?.[0]
    if (file) setUploadFile(file)
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) setUploadFile(file)
  }

  async function handleFileUpload() {
    if (!uploadFile) return
    setUploading(true)
    setError(null)
    setImportCount(null)
    try {
      const formData = new FormData()
      formData.append('file', uploadFile)
      const resp = await fetch(`${API_BASE}/api/v2/rules/import/file`, {
        method: 'POST',
        body: formData,
      })
      if (!resp.ok) {
        const body = (await resp.json()) as { detail?: string }
        throw new Error(body.detail ?? 'Upload failed')
      }
      const result = (await resp.json()) as { imported: number; total: number }
      setImportCount(result.imported)
      if (result.imported > 0) {
        onImported()
        setTimeout(onClose, 1200)
      } else {
        setError(`No rules imported out of ${result.total} sections`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  async function handleLibraryImport() {
    if (selected.size === 0) return
    setImporting(true)
    setError(null)
    setImportCount(null)
    try {
      const rules = SIGMA_LIBRARY.filter((r) => selected.has(r.key)).map((r) => ({
        name: r.label,
        content: r.content,
        format: 'sigma',
      }))
      const res = await apiPost<{ imported: number; failed: Array<{ index: number; error: string }> }>(
        '/api/v2/rules/import/bulk',
        { rules }
      )
      setImportCount(res.imported)
      if (res.imported > 0) {
        onImported()
        setTimeout(onClose, 1200)
      } else {
        setError('Import failed for all selected rules')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="p-5 space-y-5">
      {/* Tab bar */}
      <div className="flex rounded-lg border border-slate-700 overflow-hidden">
        {(
          [
            { key: 'paste', label: 'Paste', icon: FileText },
            { key: 'upload', label: 'Upload File', icon: Upload },
            { key: 'library', label: 'Sigma Library', icon: BookOpen },
          ] as const
        ).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cn(
              'flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors',
              tab === key
                ? 'bg-cyan-600/20 text-cyan-400 border-b-2 border-cyan-500'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* ── Paste tab ── */}
      {tab === 'paste' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-medium text-slate-400">Rule Content</label>
            <span className="text-[11px] text-slate-600">Separate multiple rules with ---</span>
          </div>
          <textarea
            value={text}
            onChange={(e) => handleTextChange(e.target.value)}
            placeholder={`Paste one or more Sigma / SPL / KQL / ES|QL rules here…\n\nSeparate multiple rules with:\n---`}
            rows={12}
            className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
          />
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
        </div>
      )}

      {/* ── Upload tab ── */}
      {tab === 'upload' && (
        <div className="space-y-3">
          <div
            onDragOver={(e) => { e.preventDefault(); setUploadDrag(true) }}
            onDragLeave={() => setUploadDrag(false)}
            onDrop={handleFileDrop}
            onClick={() => fileRef.current?.click()}
            className={cn(
              'flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-10 cursor-pointer transition-colors',
              uploadDrag
                ? 'border-cyan-500 bg-cyan-500/10'
                : 'border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800/50'
            )}
          >
            <Upload className="h-10 w-10 text-slate-500 mb-3" />
            <p className="text-sm font-medium text-slate-300">Drop a rule file or click to browse</p>
            <p className="text-xs text-slate-600 mt-1">.yml · .yaml · .json · .txt</p>
            <input
              ref={fileRef}
              type="file"
              accept=".yml,.yaml,.json,.txt"
              onChange={handleFileInput}
              className="hidden"
            />
          </div>

          {uploadFile && (
            <div className="flex items-center gap-3 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5">
              <FileText className="h-4 w-4 text-cyan-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-slate-200 truncate">{uploadFile.name}</p>
                <p className="text-[11px] text-slate-500">{(uploadFile.size / 1024).toFixed(1)} KB</p>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); setUploadFile(null) }}
                className="text-slate-500 hover:text-slate-300"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Library tab ── */}
      {tab === 'library' && (
        <div className="space-y-2">
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs text-slate-400">Community rule starters — select to import</p>
            <button
              onClick={() => {
                if (selected.size === SIGMA_LIBRARY.length) {
                  setSelected(new Set())
                } else {
                  setSelected(new Set(SIGMA_LIBRARY.map((r) => r.key)))
                }
              }}
              className="text-[11px] text-cyan-400 hover:text-cyan-300"
            >
              {selected.size === SIGMA_LIBRARY.length ? 'Deselect all' : 'Select all'}
            </button>
          </div>
          {SIGMA_LIBRARY.map((item) => (
            <label
              key={item.key}
              className={cn(
                'flex items-start gap-3 rounded-lg border px-3 py-2.5 cursor-pointer transition-colors',
                selected.has(item.key)
                  ? 'border-cyan-500/40 bg-cyan-500/10'
                  : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/50'
              )}
            >
              <input
                type="checkbox"
                checked={selected.has(item.key)}
                onChange={(e) => {
                  const next = new Set(selected)
                  if (e.target.checked) next.add(item.key)
                  else next.delete(item.key)
                  setSelected(next)
                }}
                className="mt-0.5 rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500"
              />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-slate-200">{item.label}</p>
                <div className="flex items-center gap-1.5 mt-1">
                  <span className="rounded bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 text-[10px] font-mono text-purple-400">
                    {item.technique}
                  </span>
                  <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-medium', SEVERITY_STYLES[item.severity as Severity])}>
                    {item.severity}
                  </span>
                </div>
              </div>
            </label>
          ))}
        </div>
      )}

      {/* Success message */}
      {importCount !== null && importCount > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2.5 text-xs text-emerald-300">
          <Check className="h-3.5 w-3.5" />
          Imported {importCount} rule{importCount !== 1 ? 's' : ''} successfully
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

        {tab === 'paste' && (
          <button
            onClick={() => void handlePasteImport()}
            disabled={!text.trim() || importing}
            className="flex-1 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
          >
            {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {importing ? 'Importing…' : 'Import Rules'}
          </button>
        )}

        {tab === 'upload' && (
          <button
            onClick={() => void handleFileUpload()}
            disabled={!uploadFile || uploading}
            className="flex-1 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
          >
            {uploading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
            {uploading ? 'Uploading…' : 'Upload & Import'}
          </button>
        )}

        {tab === 'library' && (
          <button
            onClick={() => void handleLibraryImport()}
            disabled={selected.size === 0 || importing}
            className="flex-1 rounded-lg bg-cyan-600 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
          >
            {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {importing ? 'Importing…' : `Import ${selected.size > 0 ? selected.size : ''} Rule${selected.size !== 1 ? 's' : ''}`}
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Export dropdown ──────────────────────────────────────────────────────────

function ExportDropdown({ selectedIds, totalCount }: { selectedIds: string[]; totalCount: number }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function buildExportUrl(format: 'sigma' | 'json' | 'csv') {
    const params = new URLSearchParams({ format })
    if (selectedIds.length > 0) params.set('ids', selectedIds.join(','))
    return `${API_BASE}/api/v2/rules/export?${params}`
  }

  const label = selectedIds.length > 0
    ? `Export ${selectedIds.length} selected`
    : `Export all (${totalCount})`

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
      >
        <Download className="h-3.5 w-3.5" />
        Export
        <ChevronDown className="h-3 w-3 ml-0.5" />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 z-30 w-52 rounded-lg border border-slate-700 bg-slate-900 shadow-xl overflow-hidden">
          <p className="px-3 py-2 text-[11px] text-slate-500 border-b border-slate-800">{label}</p>
          {(
            [
              { format: 'sigma', label: 'Sigma YAML (.yml)' },
              { format: 'json', label: 'JSON Array (.json)' },
              { format: 'csv', label: 'CSV Spreadsheet (.csv)' },
            ] as const
          ).map(({ format, label: fLabel }) => (
            <a
              key={format}
              href={buildExportUrl(format)}
              download
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-slate-500" />
              {fLabel}
            </a>
          ))}
        </div>
      )}
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
  const [eventJson, setEventJson] = useState('')
  const [eventError, setEventError] = useState<string | null>(null)

  const mitreTechs = rule.mitre_techniques ?? rule.techniques?.map((t) => t.id) ?? []

  async function runTest() {
    setEventError(null)
    let eventObj: Record<string, unknown>
    try {
      eventObj = JSON.parse(eventJson || '{}') as Record<string, unknown>
    } catch {
      setEventError('Invalid JSON — fix the event before testing')
      return
    }
    setTesting(true)
    setTestResult(null)
    try {
      const result = await apiPost<{ matched: boolean; match_count: number; details: string; evaluation_time_ms: number }>(
        `/api/v2/rules/${rule.id}/test`,
        { event: eventObj }
      )
      setTestResult({
        passed: result.matched,
        matched_events: result.match_count,
        false_positives: 0,
        duration_ms: Math.round(result.evaluation_time_ms),
      })
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

  const rawContent = rule.raw_text ?? rule.source ?? ''

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
      {mitreTechs.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">MITRE Techniques</p>
          <div className="flex flex-wrap gap-1.5">
            {mitreTechs.map((tid) => (
              <a
                key={tid}
                href={`/mitre?technique=${tid}`}
                className="group flex items-center gap-1 rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-1 text-[11px] font-mono text-purple-300 hover:bg-purple-500/25 transition-colors"
              >
                <span className="font-semibold">{tid}</span>
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Tags */}
      {(rule.tags ?? []).length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Tags</p>
          <div className="flex flex-wrap gap-1">
            {(rule.tags ?? []).map((tag) => (
              <span
                key={tag}
                className="flex items-center gap-1 rounded bg-slate-700/60 border border-slate-600/50 px-2 py-0.5 text-[10px] text-slate-400"
              >
                <Tag className="h-2.5 w-2.5" />
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Rule content with line numbers */}
      <div className="space-y-2">
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Rule Content</p>
        <div className="rounded-lg border border-slate-700 bg-slate-900 overflow-hidden">
          <div className="overflow-x-auto">
            <pre
              className="p-3 text-[11px] font-mono text-slate-300 leading-relaxed whitespace-pre [counter-reset:line]"
              style={{ tabSize: 2 }}
            >
              {rawContent.split('\n').map((line, i) => (
                <span key={i} className="block [counter-increment:line] before:content-[counter(line)] before:mr-3 before:text-slate-600 before:select-none before:text-[10px] before:inline-block before:w-5 before:text-right">
                  {line || ' '}
                </span>
              ))}
            </pre>
          </div>
        </div>
      </div>

      {/* Test rule panel */}
      <div className="space-y-2">
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Test Rule</p>
        <textarea
          value={eventJson}
          onChange={(e) => setEventJson(e.target.value)}
          placeholder={'Paste a sample event JSON here, e.g.:\n{"CommandLine": "-EncodedCommand abc", "Image": "powershell.exe"}'}
          rows={5}
          className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-[11px] font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
        />
        {eventError && (
          <p className="text-[11px] text-red-400 flex items-center gap-1">
            <AlertCircle className="h-3 w-3" /> {eventError}
          </p>
        )}
        <button
          onClick={() => void runTest()}
          disabled={testing}
          className="flex items-center gap-1.5 rounded-lg bg-slate-800 border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-50 transition-colors"
        >
          {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <PlayCircle className="h-3 w-3" />}
          {testing ? 'Testing…' : 'Run Test'}
        </button>

        {testResult && (
          <div
            className={cn(
              'rounded-lg border p-3 space-y-2',
              testResult.passed ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-red-500/30 bg-red-500/10'
            )}
          >
            <div className="flex items-center gap-2">
              {testResult.passed ? (
                <Check className="h-4 w-4 text-emerald-400" />
              ) : (
                <X className="h-4 w-4 text-red-400" />
              )}
              <span className={cn('text-sm font-medium', testResult.passed ? 'text-emerald-300' : 'text-red-300')}>
                {testResult.passed ? 'Rule Matched' : 'No Match'}
              </span>
              <span className="ml-auto text-xs text-slate-500">{testResult.duration_ms}ms</span>
            </div>
            {!testResult.error && (
              <div className="text-xs text-slate-400">
                Matched events: <span className="text-slate-200 font-medium">{testResult.matched_events}</span>
              </div>
            )}
            {testResult.error && <p className="text-xs text-red-300">{testResult.error}</p>}
          </div>
        )}
      </div>

      {/* Version history placeholder */}
      <div className="rounded-lg border border-slate-800 px-3 py-2.5">
        <p className="text-xs text-slate-500">Version history — coming soon</p>
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-1 border-t border-slate-800">
        <Toggle checked={rule.enabled} onChange={(v) => onToggle(rule.id, v)} />
        <span className="text-xs text-slate-400 self-center">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
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
  const [tagFilter, setTagFilter] = useState('')
  const [mitreFilter, setMitreFilter] = useState('')
  const [hasMitreFilter, setHasMitreFilter] = useState<boolean | null>(null)
  const [sortOrder, setSortOrder] = useState<'created_at_desc' | 'name_asc' | 'severity_desc'>('created_at_desc')

  // Pagination
  const [page, setPage] = useState(0)

  // Selection (bulk actions)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  // Drawers / modals
  const [importDrawerOpen, setImportDrawerOpen] = useState(false)
  const [detailRule, setDetailRule] = useState<DetectionRule | null>(null)
  const [validateOpen, setValidateOpen] = useState(false)
  const [validateIds, setValidateIds] = useState<string[]>([])

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
      const params = new URLSearchParams()
      if (langFilter) params.set('language', langFilter)
      if (severityFilter) params.set('severity', severityFilter)
      if (mitreFilter) params.set('technique_id', mitreFilter)
      if (tagFilter) params.set('tag', tagFilter)
      if (hasMitreFilter !== null) params.set('has_mitre', String(hasMitreFilter))
      params.set('sort', sortOrder)
      params.set('limit', '200')

      const query = params.toString()
      const data = await apiGet<{ rules: DetectionRule[] } | DetectionRule[]>(
        `/api/v2/rules${query ? `?${query}` : ''}`
      )
      const ruleList = Array.isArray(data) ? data : data.rules
      setRules(ruleList)
    } catch {
      setRules(SEED_RULES)
    } finally {
      setLoading(false)
    }
  }, [langFilter, severityFilter, mitreFilter, tagFilter, hasMitreFilter, sortOrder])

  useEffect(() => {
    void loadRules()
  }, [loadRules])

  // ── Client-side search filter (on top of server-filtered results) ─────────

  const filtered = rules.filter((r) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      r.name.toLowerCase().includes(q) ||
      (r.description ?? '').toLowerCase().includes(q) ||
      (r.mitre_techniques ?? []).some((t) => t.toLowerCase().includes(q)) ||
      (r.tags ?? []).some((t) => t.toLowerCase().includes(q))
    )
  })

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageRules = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  // ── Toggle rule enabled ───────────────────────────────────────────────────

  function toggleRule(id: string, enabled: boolean) {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled } : r)))
    void apiPost(`/api/v2/rules/${id}`, { enabled }).catch(() => {})
  }

  // ── Delete rule ────────────────────────────────────────────────────────────

  async function deleteRule(id: string) {
    try {
      await apiDelete(`/api/v2/rules/${id}`)
    } catch {
      // remove locally even on API error
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

  function openBatchValidate() {
    const ids = selected.size > 0 ? [...selected] : filtered.map((r) => r.id)
    setValidateIds(ids)
    setValidateOpen(true)
  }

  // ── Coverage ───────────────────────────────────────────────────────────────

  async function loadCoverage() {
    setLoadingCoverage(true)
    try {
      const data = await apiGet<CoverageCell[]>('/api/v2/rules/coverage')
      setCoverageCells(data)
    } catch {
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

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <>
      <div className="space-y-4">
        {/* Page header */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Detection Rules</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              {rules.length} rules · {rules.filter((r) => r.enabled).length} enabled
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => void loadCoverage()}
              disabled={loadingCoverage}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              {loadingCoverage ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Grid3X3 className="h-3.5 w-3.5" />}
              Coverage Matrix
            </button>
            <button
              onClick={openBatchValidate}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {selected.size > 0 ? `Validate ${selected.size}` : 'Validate All'}
            </button>
            <ExportDropdown
              selectedIds={[...selected]}
              totalCount={filtered.length}
            />
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

        {/* Filter bar */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0) }}
                placeholder="Search rules, tags, techniques…"
                className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <select
              value={langFilter}
              onChange={(e) => { setLangFilter(e.target.value as RuleLanguage | ''); setPage(0) }}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Languages</option>
              {LANGUAGES.map((l) => (
                <option key={l} value={l}>{l.toUpperCase()}</option>
              ))}
            </select>
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value as Severity | ''); setPage(0) }}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as typeof sortOrder)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="created_at_desc">Newest first</option>
              <option value="name_asc">Name A–Z</option>
              <option value="severity_desc">Severity (high first)</option>
            </select>
          </div>

          {/* Advanced filters row */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <Tag className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-500" />
              <input
                value={tagFilter}
                onChange={(e) => { setTagFilter(e.target.value); setPage(0) }}
                placeholder="Tag filter…"
                className="rounded-lg border border-slate-700 bg-slate-800 pl-7 pr-3 py-1.5 text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 w-36"
              />
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3 w-3 text-slate-500" />
              <input
                value={mitreFilter}
                onChange={(e) => { setMitreFilter(e.target.value); setPage(0) }}
                placeholder="Technique ID…"
                className="rounded-lg border border-slate-700 bg-slate-800 pl-7 pr-3 py-1.5 text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 w-36"
              />
            </div>
            <button
              onClick={() => setHasMitreFilter(hasMitreFilter === true ? null : true)}
              className={cn(
                'flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                hasMitreFilter === true
                  ? 'border-purple-500/50 bg-purple-500/20 text-purple-300'
                  : 'border-slate-700 bg-slate-800 text-slate-400 hover:text-slate-200'
              )}
            >
              Has MITRE
            </button>
            {(tagFilter || mitreFilter || hasMitreFilter !== null) && (
              <button
                onClick={() => { setTagFilter(''); setMitreFilter(''); setHasMitreFilter(null) }}
                className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
              >
                <X className="h-3 w-3" />
                Clear filters
              </button>
            )}
          </div>
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
                onClick={openBatchValidate}
                className="flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white transition-colors"
              >
                <ShieldCheck className="h-3 w-3" />
                Validate
              </button>
              <button
                onClick={() => void bulkDelete()}
                className="flex items-center gap-1.5 rounded-md bg-red-500/10 border border-red-500/30 px-2.5 py-1.5 text-xs text-red-300 hover:bg-red-500/20 transition-colors"
              >
                <Trash2 className="h-3 w-3" />
                Delete
              </button>
              <button onClick={() => setSelected(new Set())} className="text-xs text-slate-500 hover:text-slate-300">
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
              {pageRules.map((rule) => {
                const techs = rule.mitre_techniques ?? rule.techniques?.map((t) => t.id) ?? []
                return (
                  <div
                    key={rule.id}
                    className="grid grid-cols-[2rem_2fr_5rem_6rem_1fr_6rem_4rem] gap-3 items-center px-4 py-3 hover:bg-slate-800/50 transition-colors group"
                  >
                    <label className="flex items-center cursor-pointer" onClick={(e) => e.stopPropagation()}>
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

                    <button onClick={() => setDetailRule(rule)} className="text-left min-w-0 group/name">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm font-medium text-slate-200 truncate group-hover/name:text-cyan-400 transition-colors">
                          {rule.name}
                        </span>
                        <ChevronRight className="h-3 w-3 text-slate-600 opacity-0 group-hover/name:opacity-100 shrink-0 transition-opacity" />
                      </div>
                      {rule.description && (
                        <p className="text-[11px] text-slate-500 truncate mt-0.5">{rule.description}</p>
                      )}
                    </button>

                    <LangBadge lang={rule.language} />
                    <SeverityBadge severity={rule.severity} />

                    <div className="flex flex-wrap gap-1 min-w-0">
                      {techs.slice(0, 3).map((t) => (
                        <span
                          key={t}
                          title={t}
                          className="rounded bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 text-[10px] font-mono text-purple-400"
                        >
                          {t}
                        </span>
                      ))}
                      {techs.length > 3 && (
                        <span className="text-[10px] text-slate-500">+{techs.length - 3}</span>
                      )}
                    </div>

                    <div className="flex justify-center">
                      <Toggle checked={rule.enabled} onChange={(v) => toggleRule(rule.id, v)} />
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
                )
              })}
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
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => (
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
      <Drawer open={importDrawerOpen} onClose={() => setImportDrawerOpen(false)} title="Import Detection Rules">
        <ImportDrawerContent onClose={() => setImportDrawerOpen(false)} onImported={() => void loadRules()} />
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
      <Drawer open={coverageOpen} onClose={() => setCoverageOpen(false)} title="MITRE ATT&CK Coverage Matrix">
        <div className="p-5">
          {coverageCells.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-sm text-slate-500">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
              Loading coverage…
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 mb-4 text-xs text-slate-500">
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded bg-slate-800" /> 0%</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded bg-cyan-900/60" /> 1–25%</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded bg-cyan-700/60" /> 26–50%</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded bg-cyan-600/70" /> 51–75%</div>
                <div className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded bg-cyan-500/80" /> 76–100%</div>
              </div>
              <CoverageHeatmap cells={coverageCells} />
            </>
          )}
        </div>
      </Drawer>

      {/* Batch validate modal */}
      {validateOpen && (
        <BatchValidateModal
          ruleIds={validateIds}
          onClose={() => setValidateOpen(false)}
        />
      )}
    </>
  )
}
