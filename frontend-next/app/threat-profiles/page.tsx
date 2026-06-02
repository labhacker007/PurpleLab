'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Plus,
  Trash2,
  X,
  Loader2,
  AlertCircle,
  RefreshCw,
  Upload,
  Link2,
  ChevronDown,
  Shield,
  Bug,
  User,
  Hash,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost, apiDelete } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ThreatProfile {
  id: string
  environment_id: string
  profile_type: 'cve' | 'ttp' | 'actor' | 'ioc'
  name: string
  data: Record<string, unknown>
  source: string
  created_by?: string
  created_at: string
}

interface Environment {
  id: string
  name: string
  siem_platform?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PROFILE_TYPE_META = {
  cve: { label: 'CVE', icon: Bug, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
  ttp: { label: 'TTP', icon: Shield, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  actor: { label: 'Actor', icon: User, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30' },
  ioc: { label: 'IOC', icon: Hash, color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/30' },
} as const

const PROFILE_ORDER: ThreatProfile['profile_type'][] = ['cve', 'ttp', 'actor', 'ioc']

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 60000) return 'just now'
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m ago`
  if (ms < 86400000) return `${Math.floor(ms / 3600000)}h ago`
  return `${Math.floor(ms / 86400000)}d ago`
}

// ─── Profile Card ─────────────────────────────────────────────────────────────

function ProfileCard({ profile, onDelete }: { profile: ThreatProfile; onDelete: () => void }) {
  const meta = PROFILE_TYPE_META[profile.profile_type]
  const Icon = meta.icon

  return (
    <div className={cn('flex items-center gap-3 rounded-lg border p-3', meta.bg)}>
      <Icon className={cn('h-4 w-4 shrink-0', meta.color)} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-foreground truncate">{profile.name}</p>
        <p className="text-[10px] text-muted-foreground mt-0.5">
          {profile.source} · {relativeDate(profile.created_at)}
        </p>
      </div>
      <button
        onClick={onDelete}
        className="rounded p-1 text-muted-foreground hover:text-red-400 transition-colors"
        title="Remove profile"
      >
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

// ─── CVE Form ─────────────────────────────────────────────────────────────────

function CVEForm({ envId, onAdded }: { envId: string; onAdded: () => void }) {
  const [cveId, setCveId] = useState('')
  const [cvss, setCvss] = useState('')
  const [component, setComponent] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [desc, setDesc] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!cveId.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost(`/api/v2/environments/${envId}/threat-profiles`, {
        profile_type: 'cve',
        name: cveId.trim(),
        data: { cvss: parseFloat(cvss) || null, affected_component: component, severity, description: desc },
        source: 'manual',
      })
      setCveId(''); setCvss(''); setComponent(''); setDesc('')
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add CVE')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">CVE ID</label>
          <input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2024-12345" className="field px-3 py-2 text-sm w-full" />
        </div>
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">CVSS Score</label>
          <input value={cvss} onChange={(e) => setCvss(e.target.value)} placeholder="9.8" type="number" min="0" max="10" step="0.1" className="field px-3 py-2 text-sm w-full" />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Affected Component</label>
        <input value={component} onChange={(e) => setComponent(e.target.value)} placeholder="e.g. Apache Log4j 2.x" className="field px-3 py-2 text-sm w-full" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Severity</label>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="field px-3 py-2 text-sm w-full">
          {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Description</label>
        <textarea value={desc} onChange={(e) => setDesc(e.target.value)} rows={2} placeholder="Brief description of the vulnerability" className="field px-3 py-2 text-sm w-full resize-none" />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button onClick={() => void handleSubmit()} disabled={!cveId.trim() || submitting} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
        {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
        Add CVE
      </button>
    </div>
  )
}

// ─── TTP Form ─────────────────────────────────────────────────────────────────

function TTPForm({ envId, onAdded }: { envId: string; onAdded: () => void }) {
  const [techId, setTechId] = useState('')
  const [name, setName] = useState('')
  const [tactic, setTactic] = useState('')
  const [desc, setDesc] = useState('')
  const [guidance, setGuidance] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!techId.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost(`/api/v2/environments/${envId}/threat-profiles`, {
        profile_type: 'ttp',
        name: techId.trim(),
        data: { name: name.trim(), tactic, description: desc, detection_guidance: guidance },
        source: 'manual',
      })
      setTechId(''); setName(''); setTactic(''); setDesc(''); setGuidance('')
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add TTP')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">Technique ID</label>
          <input value={techId} onChange={(e) => setTechId(e.target.value)} placeholder="T1059.001" className="field px-3 py-2 text-sm w-full font-mono" />
        </div>
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">Tactic</label>
          <input value={tactic} onChange={(e) => setTactic(e.target.value)} placeholder="Execution" className="field px-3 py-2 text-sm w-full" />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Name</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="PowerShell Encoded Execution" className="field px-3 py-2 text-sm w-full" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Description</label>
        <textarea value={desc} onChange={(e) => setDesc(e.target.value)} rows={2} placeholder="Describe the technique" className="field px-3 py-2 text-sm w-full resize-none" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Detection Guidance</label>
        <textarea value={guidance} onChange={(e) => setGuidance(e.target.value)} rows={2} placeholder="How to detect this technique" className="field px-3 py-2 text-sm w-full resize-none" />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button onClick={() => void handleSubmit()} disabled={!techId.trim() || submitting} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
        {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
        Add TTP
      </button>
    </div>
  )
}

// ─── Actor Form ───────────────────────────────────────────────────────────────

function ActorForm({ envId, onAdded }: { envId: string; onAdded: () => void }) {
  const [actorName, setActorName] = useState('')
  const [aliases, setAliases] = useState('')
  const [motivation, setMotivation] = useState('')
  const [ttps, setTtps] = useState('')
  const [countries, setCountries] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!actorName.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost(`/api/v2/environments/${envId}/threat-profiles`, {
        profile_type: 'actor',
        name: actorName.trim(),
        data: {
          aliases: aliases.split(',').map((a) => a.trim()).filter(Boolean),
          motivation,
          ttps: ttps.split(',').map((t) => t.trim()).filter(Boolean),
          countries_of_origin: countries.split(',').map((c) => c.trim()).filter(Boolean),
        },
        source: 'manual',
      })
      setActorName(''); setAliases(''); setMotivation(''); setTtps(''); setCountries('')
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add Actor')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Actor Name</label>
        <input value={actorName} onChange={(e) => setActorName(e.target.value)} placeholder="APT29 / Cozy Bear" className="field px-3 py-2 text-sm w-full" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Aliases (comma-separated)</label>
        <input value={aliases} onChange={(e) => setAliases(e.target.value)} placeholder="Cozy Bear, The Dukes" className="field px-3 py-2 text-sm w-full" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Motivation</label>
        <input value={motivation} onChange={(e) => setMotivation(e.target.value)} placeholder="Espionage" className="field px-3 py-2 text-sm w-full" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">TTPs (comma-separated technique IDs)</label>
        <input value={ttps} onChange={(e) => setTtps(e.target.value)} placeholder="T1059.001, T1003.001" className="field px-3 py-2 text-sm w-full font-mono" />
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Countries of Origin (comma-separated)</label>
        <input value={countries} onChange={(e) => setCountries(e.target.value)} placeholder="Russia, China" className="field px-3 py-2 text-sm w-full" />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button onClick={() => void handleSubmit()} disabled={!actorName.trim() || submitting} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
        {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
        Add Actor
      </button>
    </div>
  )
}

// ─── IOC Form ─────────────────────────────────────────────────────────────────

function IOCForm({ envId, onAdded }: { envId: string; onAdded: () => void }) {
  const [iocType, setIocType] = useState('ip')
  const [value, setValue] = useState('')
  const [context, setContext] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    if (!value.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost(`/api/v2/environments/${envId}/threat-profiles`, {
        profile_type: 'ioc',
        name: value.trim(),
        data: { type: iocType, value: value.trim(), context },
        source: 'manual',
      })
      setValue(''); setContext('')
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add IOC')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">IOC Type</label>
          <select value={iocType} onChange={(e) => setIocType(e.target.value)} className="field px-3 py-2 text-sm w-full">
            {['ip', 'domain', 'hash', 'url'].map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
          </select>
        </div>
        <div className="space-y-1">
          <label className="text-[11px] text-muted-foreground">Value</label>
          <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="192.168.1.1 / evil.com" className="field px-3 py-2 text-sm w-full font-mono" />
        </div>
      </div>
      <div className="space-y-1">
        <label className="text-[11px] text-muted-foreground">Context</label>
        <textarea value={context} onChange={(e) => setContext(e.target.value)} rows={2} placeholder="Context or notes for this IOC" className="field px-3 py-2 text-sm w-full resize-none" />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button onClick={() => void handleSubmit()} disabled={!value.trim() || submitting} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
        {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
        Add IOC
      </button>
    </div>
  )
}

// ─── Bulk Import Form ─────────────────────────────────────────────────────────

function BulkImportForm({ envId, onAdded }: { envId: string; onAdded: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [parsed, setParsed] = useState<unknown[] | null>(null)
  const [parseError, setParseError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function processFile(file: File) {
    setFileName(file.name)
    setParsed(null)
    setParseError(null)
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      try {
        if (file.name.endsWith('.json')) {
          const arr = JSON.parse(text) as unknown[]
          if (!Array.isArray(arr)) throw new Error('JSON must be an array')
          setParsed(arr)
        } else {
          // CSV / TSV
          const sep = file.name.endsWith('.tsv') ? '\t' : ','
          const lines = text.trim().split('\n')
          const headers = lines[0].split(sep).map((h) => h.trim())
          const rows = lines.slice(1).map((line) => {
            const vals = line.split(sep)
            return Object.fromEntries(headers.map((h, i) => [h, vals[i]?.trim() ?? '']))
          })
          setParsed(rows)
        }
      } catch (e) {
        setParseError(e instanceof Error ? e.message : 'Parse error')
      }
    }
    reader.readAsText(file)
  }

  async function handleImport() {
    if (!parsed) return
    setSubmitting(true)
    setError(null)
    try {
      await apiPost(`/api/v2/environments/${envId}/threat-profiles/bulk-import`, { profiles: parsed })
      setParsed(null)
      setFileName(null)
      onAdded()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-3">
      <div
        className={cn(
          'relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-6 text-center transition-colors cursor-pointer',
          dragging ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'
        )}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) processFile(f) }}
        onClick={() => fileRef.current?.click()}
      >
        <Upload className="h-6 w-6 text-muted-foreground mb-2" />
        <p className="text-sm text-muted-foreground">Drop a JSON, CSV, or TSV file here</p>
        <p className="text-xs text-muted-foreground mt-1">or click to browse</p>
        <input ref={fileRef} type="file" accept=".json,.csv,.tsv" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) processFile(f) }} />
      </div>
      {fileName && (
        <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3 py-2">
          <Upload className="h-3.5 w-3.5 text-primary shrink-0" />
          <span className="text-xs text-foreground flex-1 truncate">{fileName}</span>
          {parsed && <span className="text-[10px] text-green-400">{parsed.length} rows parsed</span>}
          <button onClick={() => { setFileName(null); setParsed(null) }} className="text-muted-foreground hover:text-foreground">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
      {parseError && <p className="text-xs text-red-400">{parseError}</p>}
      {error && <p className="text-xs text-red-400">{error}</p>}
      {parsed && parsed.length > 0 && (
        <button onClick={() => void handleImport()} disabled={submitting} className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors">
          {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
          {submitting ? 'Importing…' : `Import ${parsed.length} profiles`}
        </button>
      )}
    </div>
  )
}

// ─── TIP Integration notice ───────────────────────────────────────────────────

function TIPIntegrationPanel() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border p-8 text-center">
      <Link2 className="h-8 w-8 text-muted-foreground" />
      <div>
        <p className="text-sm font-medium text-foreground">Connect Joti TIP</p>
        <p className="text-xs text-muted-foreground mt-1 max-w-xs">
          Connect your Joti TIP instance via Settings &gt; Integrations to pull threat profiles automatically.
        </p>
      </div>
      <a
        href="/settings"
        className="flex items-center gap-1.5 rounded border border-border bg-muted/40 hover:bg-muted px-3 py-2 text-xs text-foreground transition-colors"
      >
        <Link2 className="h-3.5 w-3.5" />
        Go to Integrations Settings
      </a>
    </div>
  )
}

// ─── Add Panel Tabs ───────────────────────────────────────────────────────────

type AddTab = 'cve' | 'ttp' | 'actor' | 'ioc' | 'bulk' | 'tip'

const ADD_TABS: { key: AddTab; label: string }[] = [
  { key: 'cve', label: 'CVE' },
  { key: 'ttp', label: 'TTP' },
  { key: 'actor', label: 'Actor' },
  { key: 'ioc', label: 'IOC' },
  { key: 'bulk', label: 'Bulk Import' },
  { key: 'tip', label: 'TIP / API' },
]

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatProfilesPage() {
  const [environments, setEnvironments] = useState<Environment[]>([])
  const [selectedEnvId, setSelectedEnvId] = useState<string>('')
  const [profiles, setProfiles] = useState<ThreatProfile[]>([])
  const [loadingEnvs, setLoadingEnvs] = useState(true)
  const [loadingProfiles, setLoadingProfiles] = useState(false)
  const [activeTab, setActiveTab] = useState<AddTab>('cve')

  // Load environments
  useEffect(() => {
    setLoadingEnvs(true)
    apiGet<Environment[]>('/api/v2/environments')
      .then((data) => {
        setEnvironments(data)
        if (data.length > 0) setSelectedEnvId(data[0].id)
      })
      .catch(() => {
        const fallback = [{ id: 'env-demo', name: 'Demo Environment', siem_platform: 'splunk' }]
        setEnvironments(fallback)
        setSelectedEnvId(fallback[0].id)
      })
      .finally(() => setLoadingEnvs(false))
  }, [])

  const loadProfiles = useCallback(async () => {
    if (!selectedEnvId) return
    setLoadingProfiles(true)
    try {
      const data = await apiGet<ThreatProfile[]>(`/api/v2/environments/${selectedEnvId}/threat-profiles`)
      setProfiles(data)
    } catch {
      setProfiles([])
    } finally {
      setLoadingProfiles(false)
    }
  }, [selectedEnvId])

  useEffect(() => { void loadProfiles() }, [loadProfiles])

  async function handleDelete(id: string) {
    try {
      await apiDelete(`/api/v2/environments/${selectedEnvId}/threat-profiles/${id}`)
    } catch { /* continue */ }
    setProfiles((prev) => prev.filter((p) => p.id !== id))
  }

  const grouped = PROFILE_ORDER.reduce<Record<string, ThreatProfile[]>>((acc, type) => {
    acc[type] = profiles.filter((p) => p.profile_type === type)
    return acc
  }, {} as Record<string, ThreatProfile[]>)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Threat Profiles</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Inject CVEs, TTPs, threat actors, and IOCs into environments</p>
        </div>
        <button onClick={() => void loadProfiles()} className="rounded border border-border bg-muted/40 hover:bg-muted p-2 text-muted-foreground hover:text-foreground transition-colors">
          <RefreshCw className={cn('h-3.5 w-3.5', loadingProfiles && 'animate-spin')} />
        </button>
      </div>

      {/* Environment selector */}
      <div className="flex items-center gap-3">
        <label className="text-xs font-medium text-muted-foreground shrink-0">Environment:</label>
        {loadingEnvs ? (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        ) : (
          <div className="relative">
            <select
              value={selectedEnvId}
              onChange={(e) => setSelectedEnvId(e.target.value)}
              className="field px-3 py-2 text-sm pr-8"
            >
              {environments.map((env) => (
                <option key={env.id} value={env.id}>{env.name}</option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          </div>
        )}
        <span className="text-xs text-muted-foreground">{profiles.length} profiles loaded</span>
      </div>

      {/* Two-panel layout */}
      {!selectedEnvId ? (
        <div className="flex items-center justify-center py-20 text-sm text-muted-foreground">
          <AlertCircle className="h-4 w-4 mr-2" />
          Select an environment to manage profiles
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Left: current profiles */}
          <div className="space-y-4">
            <h2 className="text-sm font-medium text-foreground">Current Profiles</h2>
            {loadingProfiles ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground py-8 justify-center">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading profiles…
              </div>
            ) : profiles.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 gap-2 text-sm text-muted-foreground rounded-lg border border-dashed border-border">
                <Shield className="h-8 w-8 opacity-30" />
                No profiles yet. Add some using the panel on the right.
              </div>
            ) : (
              PROFILE_ORDER.map((type) => {
                const group = grouped[type]
                if (!group || group.length === 0) return null
                const meta = PROFILE_TYPE_META[type]
                return (
                  <div key={type} className="space-y-2">
                    <div className="flex items-center gap-2">
                      <meta.icon className={cn('h-3.5 w-3.5', meta.color)} />
                      <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{meta.label}</span>
                      <span className="text-[10px] text-muted-foreground">({group.length})</span>
                    </div>
                    <div className="space-y-1.5">
                      {group.map((p) => (
                        <ProfileCard key={p.id} profile={p} onDelete={() => void handleDelete(p.id)} />
                      ))}
                    </div>
                  </div>
                )
              })
            )}
          </div>

          {/* Right: add panel */}
          <div className="rounded-lg border border-border bg-card">
            <div className="flex border-b border-border overflow-x-auto">
              {ADD_TABS.map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={cn(
                    'px-3 py-2.5 text-xs font-medium whitespace-nowrap transition-colors',
                    activeTab === tab.key
                      ? 'border-b-2 border-primary text-primary'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>
            <div className="p-4">
              {activeTab === 'cve' && <CVEForm envId={selectedEnvId} onAdded={() => void loadProfiles()} />}
              {activeTab === 'ttp' && <TTPForm envId={selectedEnvId} onAdded={() => void loadProfiles()} />}
              {activeTab === 'actor' && <ActorForm envId={selectedEnvId} onAdded={() => void loadProfiles()} />}
              {activeTab === 'ioc' && <IOCForm envId={selectedEnvId} onAdded={() => void loadProfiles()} />}
              {activeTab === 'bulk' && <BulkImportForm envId={selectedEnvId} onAdded={() => void loadProfiles()} />}
              {activeTab === 'tip' && <TIPIntegrationPanel />}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
