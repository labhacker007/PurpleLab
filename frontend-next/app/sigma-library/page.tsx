'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Search,
  Plus,
  RefreshCw,
  Loader2,
  AlertCircle,
  X,
  Check,
  ChevronLeft,
  ChevronRight,
  BookMarked,
  GitBranch,
  ToggleLeft,
  ToggleRight,
  Send,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost, apiPut } from '@/lib/api/client'
import { Drawer } from '@/components/ui/Drawer'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SigmaSource {
  id: number
  name: string
  github_url: string
  description: string
  enabled: boolean
  last_synced_at: string | null
  rule_count: number
}

interface SigmaRule {
  id: string
  source_id: number | null
  title: string
  description: string
  rule_yaml: string
  status: string
  level: string
  category: string | null
  product: string | null
  technique_ids: string[]
  tags: string[]
  added_by: string | null
  created_at: string
}

interface Session {
  id: string
  name: string
}

// ─── Seed data ────────────────────────────────────────────────────────────────

const SEED_SOURCES: SigmaSource[] = [
  { id: 1, name: 'SigmaHQ Core Rules', github_url: 'https://github.com/SigmaHQ/sigma', description: 'Official Sigma rules repository maintained by the Sigma project.', enabled: true, last_synced_at: new Date(Date.now() - 86400000).toISOString(), rule_count: 3241 },
  { id: 2, name: 'MITRE ATT&CK Sigma', github_url: 'https://github.com/Neo23x0/sigma', description: 'Sigma rules aligned with MITRE ATT&CK framework techniques.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 2).toISOString(), rule_count: 892 },
  { id: 3, name: 'Elastic Detection Rules', github_url: 'https://github.com/elastic/detection-rules', description: 'Elastic SIEM detection rules converted to Sigma format.', enabled: false, last_synced_at: null, rule_count: 0 },
  { id: 4, name: 'Splunk Security Essentials', github_url: 'https://github.com/splunk/security_content', description: 'Splunk Security Content converted for Sigma compatibility.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 5).toISOString(), rule_count: 1103 },
  { id: 5, name: 'Florian Roth Rules', github_url: 'https://github.com/Neo23x0/sigma', description: 'High-quality curated rules from Florian Roth.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 3).toISOString(), rule_count: 541 },
  { id: 6, name: 'SOCPrime Community', github_url: 'https://github.com/socprime/the-prime-hunt', description: 'Community-contributed rules from SOCPrime platform.', enabled: false, last_synced_at: null, rule_count: 0 },
  { id: 7, name: 'Phishtank IOC Rules', github_url: 'https://github.com/phishtank/phishtank-sigma', description: 'Network-level rules based on known phishing infrastructure.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 7).toISOString(), rule_count: 204 },
  { id: 8, name: 'CISA Alerts Sigma', github_url: 'https://github.com/cisagov/sigma-rules', description: 'Sigma rules derived from CISA advisories and alerts.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 4).toISOString(), rule_count: 89 },
  { id: 9, name: 'APT Detection Pack', github_url: 'https://github.com/threat-detection/apt-sigma', description: 'APT-focused detection rules for nation-state threat tracking.', enabled: false, last_synced_at: null, rule_count: 0 },
  { id: 10, name: 'Ransomware Detection', github_url: 'https://github.com/ransomware-sigma/rules', description: 'Rules targeting ransomware pre-execution and encryption behaviors.', enabled: true, last_synced_at: new Date(Date.now() - 86400000 * 6).toISOString(), rule_count: 327 },
]

const SEED_RULES: SigmaRule[] = [
  {
    id: 'sr-1', source_id: 1, title: 'Mimikatz LSASS Dump via PowerShell', description: 'Detects Mimikatz credential dumping from LSASS using PowerShell reflection.',
    rule_yaml: `title: Mimikatz LSASS Dump via PowerShell
status: stable
level: critical
logsource:
  product: windows
  service: powershell
detection:
  keywords:
    - 'Invoke-Mimikatz'
    - 'sekurlsa::logonPasswords'
  condition: keywords`,
    status: 'stable', level: 'critical', category: 'windows', product: 'windows',
    technique_ids: ['T1003.001'], tags: ['attack.credential_access', 'attack.t1003.001'],
    added_by: null, created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  },
  {
    id: 'sr-2', source_id: 1, title: 'PowerShell Encoded Command', description: 'Detects PowerShell execution with base64 encoded commands.',
    rule_yaml: `title: PowerShell Encoded Command
status: stable
level: high
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4103
    Payload|contains:
      - '-EncodedCommand'
      - '-enc '
  condition: selection`,
    status: 'stable', level: 'high', category: 'windows', product: 'windows',
    technique_ids: ['T1059.001'], tags: ['attack.execution', 'attack.t1059.001'],
    added_by: null, created_at: new Date(Date.now() - 86400000 * 8).toISOString(),
  },
  {
    id: 'sr-3', source_id: 2, title: 'Kerberoasting Activity', description: 'Detects Kerberoasting via Windows Security event 4769 with RC4 encryption.',
    rule_yaml: `title: Kerberoasting Activity
status: stable
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|endswith: '$'
  condition: selection | count() > 5`,
    status: 'stable', level: 'high', category: 'windows', product: 'windows',
    technique_ids: ['T1558.003'], tags: ['attack.credential_access', 'attack.t1558.003'],
    added_by: null, created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: 'sr-4', source_id: 3, title: 'DNS Exfiltration Pattern', description: 'Detects high-frequency DNS queries indicative of DNS tunneling.',
    rule_yaml: `title: DNS Exfiltration Pattern
status: experimental
level: medium
logsource:
  category: dns
detection:
  selection:
    query_length|gt: 50
  condition: selection | count(dns.query) > 100`,
    status: 'experimental', level: 'medium', category: 'network', product: null,
    technique_ids: ['T1071.004'], tags: ['attack.command_and_control'],
    added_by: null, created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: 'sr-5', source_id: 4, title: 'Ransomware Shadow Copy Deletion', description: 'Detects deletion of VSS shadow copies — common ransomware pre-encryption step.',
    rule_yaml: `title: Ransomware Shadow Copy Deletion
status: stable
level: critical
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'wbadmin delete catalog'
  condition: selection`,
    status: 'stable', level: 'critical', category: 'windows', product: 'windows',
    technique_ids: ['T1490'], tags: ['attack.impact', 'attack.t1490'],
    added_by: null, created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const LEVEL_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  informational: 'bg-muted text-muted-foreground border-border',
}

function LevelBadge({ level }: { level: string }) {
  return (
    <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-medium capitalize', LEVEL_STYLES[level] ?? LEVEL_STYLES.informational)}>
      {level}
    </span>
  )
}

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`
  return `${Math.floor(ms / 86400000)}d ago`
}

// ─── Sources Tab ──────────────────────────────────────────────────────────────

function SourcesTab() {
  const [sources, setSources] = useState<SigmaSource[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState<Record<number, boolean>>({})
  const [syncResult, setSyncResult] = useState<Record<number, string>>({})

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<SigmaSource[]>('/api/v2/sigma-library/sources')
      setSources(data)
    } catch {
      setSources(SEED_SOURCES)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleSync(id: number) {
    setSyncing((p) => ({ ...p, [id]: true }))
    setSyncResult((p) => ({ ...p, [id]: '' }))
    try {
      const res = await apiPost<{ synced: number; skipped: number }>(`/api/v2/sigma-library/sources/${id}/sync`, {})
      setSyncResult((p) => ({ ...p, [id]: `Synced ${res.synced ?? 0} rules, skipped ${res.skipped ?? 0}` }))
      void load()
    } catch (err) {
      setSyncResult((p) => ({ ...p, [id]: err instanceof Error ? err.message : 'Sync failed' }))
    } finally {
      setSyncing((p) => ({ ...p, [id]: false }))
    }
  }

  async function handleToggle(id: number, enabled: boolean) {
    setSources((prev) => prev.map((s) => s.id === id ? { ...s, enabled: !enabled } : s))
    try {
      await apiPut(`/api/v2/sigma-library/sources/${id}/toggle`, { enabled: !enabled })
    } catch {
      setSources((prev) => prev.map((s) => s.id === id ? { ...s, enabled } : s))
    }
  }

  if (loading) return <div className="flex items-center gap-2 py-8 justify-center text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading sources…</div>

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-xs">
        <thead className="bg-muted/60 text-muted-foreground border-b border-border">
          <tr>
            <th className="text-left px-4 py-2.5 font-medium">Source</th>
            <th className="text-left px-4 py-2.5 font-medium">Rules</th>
            <th className="text-left px-4 py-2.5 font-medium">Last Synced</th>
            <th className="text-left px-4 py-2.5 font-medium">Enabled</th>
            <th className="text-right px-4 py-2.5 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {sources.map((source) => (
            <tr key={source.id} className="border-b border-border hover:bg-muted/40 transition-colors">
              <td className="px-4 py-3">
                <div>
                  <p className="font-medium text-foreground">{source.name}</p>
                  <p className="text-muted-foreground mt-0.5 truncate max-w-xs">{source.description}</p>
                </div>
              </td>
              <td className="px-4 py-3">
                <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-foreground">
                  {source.rule_count.toLocaleString()}
                </span>
              </td>
              <td className="px-4 py-3 text-muted-foreground">
                {source.last_synced_at ? relativeDate(source.last_synced_at) : 'Never'}
                {syncResult[source.id] && (
                  <p className="text-[10px] text-green-400 mt-0.5">{syncResult[source.id]}</p>
                )}
              </td>
              <td className="px-4 py-3">
                <button
                  onClick={() => void handleToggle(source.id, source.enabled)}
                  className={cn('transition-colors', source.enabled ? 'text-green-400 hover:text-green-300' : 'text-muted-foreground hover:text-foreground')}
                  title={source.enabled ? 'Disable' : 'Enable'}
                >
                  {source.enabled ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
                </button>
              </td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => void handleSync(source.id)}
                  disabled={syncing[source.id] || !source.enabled}
                  className="flex items-center gap-1.5 rounded border border-border bg-muted/40 hover:bg-muted px-2.5 py-1.5 text-xs text-foreground transition-colors disabled:opacity-50 ml-auto"
                >
                  {syncing[source.id] ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                  Sync
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Rule Detail Drawer ───────────────────────────────────────────────────────

function RuleDetailContent({ rule, onClose }: { rule: SigmaRule; onClose: () => void }) {
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSession, setSelectedSession] = useState('')
  const [deploying, setDeploying] = useState(false)
  const [deployResult, setDeployResult] = useState<string | null>(null)

  useEffect(() => {
    apiGet<Session[]>('/api/v2/sessions')
      .then((data) => { setSessions(data); if (data.length > 0) setSelectedSession(data[0].id) })
      .catch(() => {
        const s = [{ id: 'sess-demo', name: 'Demo Session' }]
        setSessions(s); setSelectedSession(s[0].id)
      })
  }, [])

  async function handleDeploy() {
    if (!selectedSession) return
    setDeploying(true)
    setDeployResult(null)
    try {
      await apiPost(`/api/v2/sigma-library/sessions/${selectedSession}/deploy`, { rule_ids: [rule.id] })
      setDeployResult('Rule added to session successfully')
    } catch (err) {
      setDeployResult(err instanceof Error ? err.message : 'Deploy failed')
    } finally {
      setDeploying(false)
    }
  }

  return (
    <div className="p-5 space-y-5">
      {/* Header badges */}
      <div className="flex flex-wrap gap-2">
        <LevelBadge level={rule.level} />
        <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground capitalize">{rule.status}</span>
        {rule.category && <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{rule.category}</span>}
        {rule.product && <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{rule.product}</span>}
      </div>

      {/* Title */}
      <div>
        <h3 className="text-base font-semibold text-foreground">{rule.title}</h3>
        {rule.description && <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{rule.description}</p>}
      </div>

      {/* Technique IDs */}
      {rule.technique_ids.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">MITRE Techniques</p>
          <div className="flex flex-wrap gap-1.5">
            {rule.technique_ids.map((tid) => (
              <span key={tid} className="rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-[11px] font-mono text-primary">{tid}</span>
            ))}
          </div>
        </div>
      )}

      {/* Tags */}
      {rule.tags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {rule.tags.map((tag) => (
            <span key={tag} className="rounded-full border border-border px-2 py-0.5 text-[10px] text-muted-foreground">{tag}</span>
          ))}
        </div>
      )}

      {/* YAML */}
      <div className="space-y-1.5">
        <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">Rule YAML</p>
        <pre className="rounded-lg border border-border bg-muted p-3 text-[11px] font-mono text-foreground overflow-x-auto whitespace-pre leading-relaxed">
          {rule.rule_yaml}
        </pre>
      </div>

      {/* Add to Session */}
      <div className="space-y-2 rounded-lg border border-border p-3">
        <p className="text-xs font-medium text-foreground">Add to Session</p>
        <div className="flex gap-2">
          <select
            value={selectedSession}
            onChange={(e) => setSelectedSession(e.target.value)}
            className="field px-3 py-2 text-sm flex-1"
          >
            {sessions.length === 0 && <option value="">No sessions available</option>}
            {sessions.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <button
            onClick={() => void handleDeploy()}
            disabled={!selectedSession || deploying}
            className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors"
          >
            {deploying ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Deploy
          </button>
        </div>
        {deployResult && (
          <p className={cn('text-xs', deployResult.includes('success') ? 'text-green-400' : 'text-red-400')}>{deployResult}</p>
        )}
      </div>
    </div>
  )
}

// ─── Add Rule Modal ───────────────────────────────────────────────────────────

function AddRuleModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [title, setTitle] = useState('')
  const [level, setLevel] = useState('medium')
  const [status, setStatus] = useState('experimental')
  const [description, setDescription] = useState('')
  const [tags, setTags] = useState('')
  const [techniqueIds, setTechniqueIds] = useState('')
  const [ruleYaml, setRuleYaml] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!title.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost('/api/v2/sigma-library/rules', {
        title: title.trim(),
        level,
        status,
        description: description.trim(),
        tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
        technique_ids: techniqueIds.split(',').map((t) => t.trim()).filter(Boolean),
        rule_yaml: ruleYaml.trim(),
      })
      onAdded()
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add rule')
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-lg rounded-xl border border-border bg-card shadow-2xl flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between border-b border-border px-5 py-4 shrink-0">
          <h3 className="text-sm font-semibold text-foreground">Add Rule Manually</h3>
          <button onClick={onClose} className="rounded-lg p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-5 space-y-3 overflow-y-auto flex-1">
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Title</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Rule title" className="field px-3 py-2 text-sm w-full" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[11px] text-muted-foreground">Level</label>
              <select value={level} onChange={(e) => setLevel(e.target.value)} className="field px-3 py-2 text-sm w-full">
                {['critical', 'high', 'medium', 'low', 'informational'].map((l) => <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className="text-[11px] text-muted-foreground">Status</label>
              <select value={status} onChange={(e) => setStatus(e.target.value)} className="field px-3 py-2 text-sm w-full">
                {['stable', 'experimental', 'test', 'deprecated'].map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
              </select>
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Description</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="What does this rule detect?" className="field px-3 py-2 text-sm w-full resize-none" />
          </div>
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Tags (comma-separated)</label>
            <input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="attack.execution, attack.t1059" className="field px-3 py-2 text-sm w-full" />
          </div>
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Technique IDs (comma-separated)</label>
            <input value={techniqueIds} onChange={(e) => setTechniqueIds(e.target.value)} placeholder="T1059.001, T1003" className="field px-3 py-2 text-sm w-full font-mono" />
          </div>
          <div className="space-y-1">
            <label className="text-[11px] text-muted-foreground">Rule YAML</label>
            <textarea
              value={ruleYaml}
              onChange={(e) => setRuleYaml(e.target.value)}
              rows={10}
              placeholder="title: My Rule&#10;status: experimental&#10;level: high&#10;logsource:&#10;  product: windows&#10;  ..."
              className="field px-3 py-2 text-sm w-full font-mono resize-none"
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex gap-2 border-t border-border px-5 py-4 shrink-0">
          <button onClick={onClose} className="flex-1 rounded border border-border bg-muted/40 hover:bg-muted px-3 py-2 text-xs text-foreground transition-colors">Cancel</button>
          <button onClick={() => void handleSubmit()} disabled={!title.trim() || submitting} className="flex-1 flex items-center justify-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
            {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            {submitting ? 'Adding…' : 'Add Rule'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Rules Tab ────────────────────────────────────────────────────────────────

function RulesTab() {
  const [rules, setRules] = useState<SigmaRule[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [levelFilter, setLevelFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [sources, setSources] = useState<SigmaSource[]>([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const PAGE_SIZE = 25
  const [selectedRule, setSelectedRule] = useState<SigmaRule | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)

  const loadRules = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
      if (search) params.set('search', search)
      if (levelFilter) params.set('level', levelFilter)
      if (sourceFilter) params.set('source_id', sourceFilter)
      const data = await apiGet<{ rules: SigmaRule[]; total: number }>(`/api/v2/sigma-library/rules?${params}`)
      setRules(data.rules)
      setTotal(data.total)
    } catch {
      setRules(SEED_RULES)
      setTotal(SEED_RULES.length)
    } finally {
      setLoading(false)
    }
  }, [page, search, levelFilter, sourceFilter])

  useEffect(() => { void loadRules() }, [loadRules])
  useEffect(() => { setPage(1) }, [search, levelFilter, sourceFilter])

  useEffect(() => {
    apiGet<SigmaSource[]>('/api/v2/sigma-library/sources')
      .then(setSources)
      .catch(() => setSources(SEED_SOURCES))
  }, [])

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules…"
            className="field pl-9 pr-3 py-2 text-sm w-full"
          />
        </div>
        <select value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)} className="field px-3 py-2 text-sm">
          <option value="">All Levels</option>
          {['critical', 'high', 'medium', 'low', 'informational'].map((l) => <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>)}
        </select>
        <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="field px-3 py-2 text-sm">
          <option value="">All Sources</option>
          {sources.map((s) => <option key={s.id} value={String(s.id)}>{s.name}</option>)}
        </select>
        <button onClick={() => setShowAddModal(true)} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 transition-colors">
          <Plus className="h-3.5 w-3.5" />
          Add Rule
        </button>
        <button onClick={() => void loadRules()} className="rounded border border-border bg-muted/40 hover:bg-muted p-2 text-muted-foreground hover:text-foreground transition-colors">
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
        </button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/60 text-muted-foreground border-b border-border">
            <tr>
              <th className="text-left px-4 py-2.5 font-medium">Title</th>
              <th className="text-left px-4 py-2.5 font-medium w-24">Level</th>
              <th className="text-left px-4 py-2.5 font-medium w-24">Status</th>
              <th className="text-left px-4 py-2.5 font-medium">Techniques</th>
              <th className="text-left px-4 py-2.5 font-medium w-28">Added</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-12 text-center text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin mx-auto" /></td></tr>
            ) : rules.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-12 text-center text-muted-foreground">No rules found</td></tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} onClick={() => setSelectedRule(rule)} className="border-b border-border hover:bg-muted/40 cursor-pointer transition-colors">
                  <td className="px-4 py-3">
                    <p className="font-medium text-foreground truncate max-w-sm">{rule.title}</p>
                    {rule.tags.slice(0, 2).map((tag) => (
                      <span key={tag} className="text-[10px] text-muted-foreground mr-1.5">#{tag}</span>
                    ))}
                  </td>
                  <td className="px-4 py-3"><LevelBadge level={rule.level} /></td>
                  <td className="px-4 py-3 text-muted-foreground capitalize">{rule.status}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {rule.technique_ids.slice(0, 3).map((tid) => (
                        <span key={tid} className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-mono text-primary">{tid}</span>
                      ))}
                      {rule.technique_ids.length > 3 && <span className="text-[10px] text-muted-foreground">+{rule.technique_ids.length - 3}</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{relativeDate(rule.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3">
          <span className="text-xs text-muted-foreground">{total} total rules</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="rounded border border-border bg-muted/40 p-1.5 text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
              <ChevronLeft className="h-3.5 w-3.5" />
            </button>
            <span className="text-xs text-foreground">{page} / {totalPages}</span>
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="rounded border border-border bg-muted/40 p-1.5 text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
              <ChevronRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Rule detail drawer */}
      <Drawer open={!!selectedRule} onClose={() => setSelectedRule(null)} title={selectedRule?.title ?? 'Rule'}>
        {selectedRule && <RuleDetailContent rule={selectedRule} onClose={() => setSelectedRule(null)} />}
      </Drawer>

      {/* Add rule modal */}
      {showAddModal && <AddRuleModal onClose={() => setShowAddModal(false)} onAdded={() => { void loadRules(); setShowAddModal(false) }} />}
    </>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

type MainTab = 'library' | 'sources'

export default function SigmaLibraryPage() {
  const [activeTab, setActiveTab] = useState<MainTab>('library')

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Sigma Rule Library</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Browse, sync, and deploy Sigma detection rules to sessions</p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-border bg-muted/40 p-1">
          {([
            { key: 'library', label: 'Rule Library', icon: BookMarked },
            { key: 'sources', label: 'Sources', icon: GitBranch },
          ] as const).map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
                activeTab === key ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'library' && <RulesTab />}
      {activeTab === 'sources' && <SourcesTab />}
    </div>
  )
}
