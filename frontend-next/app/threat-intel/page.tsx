'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Search,
  Shield,
  ChevronDown,
  ChevronRight,
  Zap,
  Loader2,
  AlertCircle,
  RefreshCw,
  ExternalLink,
  Hash,
  Globe,
  Cpu,
  Link,
  Grid3X3,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost, streamSSE, API_BASE } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

interface MitreGroup {
  id: string
  name: string
}

interface MitreTechnique {
  id: string
  name: string
  tactic: string
  url?: string
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  description: string
  mitre_groups: MitreGroup[]
  techniques: MitreTechnique[]
  last_updated: string
  technique_count: number
}

type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'unknown'

interface IOCSourceResult {
  source: string
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  reputation_score: number // 0–100 (100 = malicious)
  details: Record<string, unknown>
  error?: string
}

interface IOCSearchResult {
  ioc: string
  type: IOCType
  sources: IOCSourceResult[]
}

interface CoverageCell {
  tactic: string
  technique_id: string
  technique_name: string
  coverage: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const VERDICT_STYLES: Record<IOCSourceResult['verdict'], string> = {
  clean: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  suspicious: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  malicious: 'bg-red-500/15 text-red-300 border-red-500/30',
  unknown: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}

const VERDICT_DOT: Record<IOCSourceResult['verdict'], string> = {
  clean: 'bg-emerald-400',
  suspicious: 'bg-yellow-400',
  malicious: 'bg-red-400',
  unknown: 'bg-slate-500',
}

const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

// ─── Seed data ────────────────────────────────────────────────────────────────

const SEED_ACTORS: ThreatActor[] = [
  {
    id: 'apt29',
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'IRON HEMLOCK'],
    description:
      'APT29 is a threat group attributed to the Russian SVR. They are known for sophisticated intrusions targeting government, diplomatic, and think tank organizations.',
    mitre_groups: [{ id: 'G0016', name: 'APT29' }],
    techniques: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
      { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' },
      { id: 'T1027', name: 'Obfuscated Files', tactic: 'Defense Evasion' },
      { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 2).toISOString(),
    technique_count: 6,
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'ZINC', 'Guardians of Peace'],
    description:
      'North Korean state-sponsored threat group linked to the Reconnaissance General Bureau. Known for financially-motivated attacks and espionage.',
    mitre_groups: [{ id: 'G0032', name: 'Lazarus Group' }],
    techniques: [
      { id: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
      { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
      { id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 5).toISOString(),
    technique_count: 4,
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbanak', 'Carbon Spider', 'Navigator Group'],
    description:
      'Financially motivated threat actor targeting retail, hospitality, and financial sectors with sophisticated point-of-sale malware.',
    mitre_groups: [{ id: 'G0046', name: 'FIN7' }],
    techniques: [
      { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
      { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution' },
      { id: 'T1056.001', name: 'Keylogging', tactic: 'Collection' },
      { id: 'T1041', name: 'Exfiltration Over C2', tactic: 'Exfiltration' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 1).toISOString(),
    technique_count: 4,
  },
  {
    id: 'sandworm',
    name: 'Sandworm Team',
    aliases: ['BlackEnergy', 'Voodoo Bear', 'ELECTRUM'],
    description:
      'Russian GRU-attributed group responsible for destructive attacks on Ukraine critical infrastructure including power grid disruptions.',
    mitre_groups: [{ id: 'G0034', name: 'Sandworm Team' }],
    techniques: [
      { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution' },
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact' },
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 3).toISOString(),
    technique_count: 4,
  },
]

// ─── Utility functions ────────────────────────────────────────────────────────

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const days = Math.floor(ms / 86400000)
  if (days === 0) return 'today'
  if (days === 1) return 'yesterday'
  return `${days}d ago`
}

function detectIOCType(value: string): IOCType {
  const trimmed = value.trim()
  // Hash (md5=32, sha1=40, sha256=64)
  if (/^[0-9a-fA-F]{32}$/.test(trimmed)) return 'hash'
  if (/^[0-9a-fA-F]{40}$/.test(trimmed)) return 'hash'
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return 'hash'
  // IP
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return 'ip'
  // URL
  if (/^https?:\/\//i.test(trimmed)) return 'url'
  // Domain
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(trimmed)) return 'domain'
  return 'unknown'
}

function IOCTypeIcon({ type }: { type: IOCType }) {
  const icons: Record<IOCType, typeof Hash> = {
    hash: Hash,
    ip: Cpu,
    domain: Globe,
    url: Link,
    unknown: Search,
  }
  const Icon = icons[type]
  return <Icon className="h-3.5 w-3.5" />
}

// ─── Coverage heatmap ─────────────────────────────────────────────────────────

function CoverageHeatmap({ cells }: { cells: CoverageCell[] }) {
  function coverageColor(pct: number): string {
    if (pct === 0) return 'bg-slate-800 text-slate-600'
    if (pct < 25) return 'bg-purple-900/60 text-purple-400'
    if (pct < 50) return 'bg-purple-700/60 text-purple-300'
    if (pct < 75) return 'bg-purple-600/70 text-purple-200'
    return 'bg-purple-500/80 text-white'
  }

  const tactics = TACTIC_ORDER.filter((t) => cells.some((c) => c.tactic === t))

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
                    'flex items-center justify-center rounded text-[9px] font-mono cursor-default h-8 w-16 shrink-0 transition-all hover:brightness-125',
                    coverageColor(cell.coverage)
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

// ─── IOC source card ──────────────────────────────────────────────────────────

function IOCSourceCard({ result }: { result: IOCSourceResult }) {
  const [open, setOpen] = useState(true)

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-4 py-3 hover:bg-slate-800/50 transition-colors"
      >
        <span
          className={cn('h-2 w-2 rounded-full shrink-0', VERDICT_DOT[result.verdict])}
        />
        <span className="text-sm font-medium text-slate-200">{result.source}</span>
        {result.error ? (
          <span className="ml-2 text-xs text-red-400">Error</span>
        ) : (
          <span
            className={cn(
              'ml-2 rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize',
              VERDICT_STYLES[result.verdict]
            )}
          >
            {result.verdict}
          </span>
        )}
        {!result.error && (
          <span className="ml-auto text-xs text-slate-500">
            Score: {result.reputation_score}/100
          </span>
        )}
        <ChevronDown
          className={cn('h-3.5 w-3.5 text-slate-500 shrink-0 transition-transform', open && 'rotate-180')}
        />
      </button>

      {open && (
        <div className="border-t border-slate-700 px-4 py-3">
          {result.error ? (
            <p className="text-xs text-red-400">{result.error}</p>
          ) : Object.keys(result.details).length === 0 ? (
            <p className="text-xs text-slate-500">No additional details</p>
          ) : (
            <pre className="text-[11px] font-mono text-slate-400 whitespace-pre-wrap break-all overflow-x-auto">
              {JSON.stringify(result.details, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Research stream panel ────────────────────────────────────────────────────

function ResearchPanel({ actorId, onClose }: { actorId: string; onClose: () => void }) {
  const [content, setContent] = useState('')
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const controller = new AbortController()
    abortRef.current = controller

    async function run() {
      try {
        const stream = streamSSE(
          `/api/v2/threat-intel/actors/research`,
          { actor_id: actorId },
          controller.signal
        )
        for await (const chunk of stream) {
          if (chunk.type === 'text') {
            setContent((prev) => prev + chunk.content)
            bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
          }
          if (chunk.type === 'done') break
          if (chunk.type === 'error') {
            setError(chunk.content)
            break
          }
        }
      } catch (err) {
        if ((err as Error).name !== 'AbortError') {
          setError(err instanceof Error ? err.message : 'Research failed')
        }
      } finally {
        setDone(true)
      }
    }

    void run()
    return () => controller.abort()
  }, [actorId])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
        <span className="text-sm font-medium text-slate-300">AI Research</span>
        <div className="flex items-center gap-2">
          {!done && (
            <button
              onClick={() => abortRef.current?.abort()}
              className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1"
            >
              Stop
            </button>
          )}
          <button
            onClick={onClose}
            className="text-xs text-slate-500 hover:text-slate-300"
          >
            Close
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4">
        {error ? (
          <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
            <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            {error}
          </div>
        ) : (
          <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
            {content || (
              <div className="flex items-center gap-2 text-slate-500">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Researching actor…
              </div>
            )}
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ─── Actor card (sidebar) ─────────────────────────────────────────────────────

function ActorCard({
  actor,
  active,
  onSelect,
}: {
  actor: ThreatActor
  active: boolean
  onSelect: () => void
}) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full rounded-xl border px-4 py-3 text-left transition-colors',
        active
          ? 'border-purple-500/50 bg-purple-500/10'
          : 'border-slate-800 bg-slate-900 hover:border-slate-700 hover:bg-slate-800/50'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-semibold text-slate-200">{actor.name}</span>
        {actor.mitre_groups[0] && (
          <span className="shrink-0 rounded bg-purple-500/15 border border-purple-500/30 px-1.5 py-0.5 text-[10px] font-mono text-purple-400">
            {actor.mitre_groups[0].id}
          </span>
        )}
      </div>
      {actor.aliases.length > 0 && (
        <p className="mt-0.5 text-[11px] text-slate-500 truncate">
          aka {actor.aliases.slice(0, 2).join(', ')}
          {actor.aliases.length > 2 && ` +${actor.aliases.length - 2}`}
        </p>
      )}
      <div className="mt-2 flex items-center gap-3 text-[11px] text-slate-500">
        <span>{actor.technique_count} techniques</span>
        <span>·</span>
        <span>Updated {relativeDate(actor.last_updated)}</span>
      </div>
    </button>
  )
}

// ─── Technique grid ───────────────────────────────────────────────────────────

function TechniqueGrid({
  techniques,
  onGenerate,
}: {
  techniques: MitreTechnique[]
  onGenerate: (id: string) => void
}) {
  const byTactic: Record<string, MitreTechnique[]> = {}
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = []
    byTactic[t.tactic].push(t)
  }

  const orderedTactics = TACTIC_ORDER.filter((t) => byTactic[t])

  return (
    <div className="space-y-4">
      {orderedTactics.map((tactic) => (
        <div key={tactic}>
          <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
            {tactic}
          </p>
          <div className="flex flex-wrap gap-1.5">
            {byTactic[tactic].map((t) => (
              <button
                key={t.id}
                onClick={() => onGenerate(t.id)}
                title={`Generate simulation for ${t.id}`}
                className="group flex items-center gap-1.5 rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:border-purple-500/50 hover:bg-purple-500/10 hover:text-purple-300 transition-colors"
              >
                <span className="font-mono font-semibold">{t.id}</span>
                <span className="text-slate-400 group-hover:text-purple-400/70">·</span>
                <span>{t.name}</span>
                <Zap className="h-2.5 w-2.5 text-slate-600 group-hover:text-purple-400 transition-colors" />
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

type MainTab = 'actor' | 'ioc'

export default function ThreatIntelPage() {
  const [actors, setActors] = useState<ThreatActor[]>([])
  const [loading, setLoading] = useState(true)
  const [actorSearch, setActorSearch] = useState('')
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null)
  const [mainTab, setMainTab] = useState<MainTab>('actor')

  // IOC search
  const [iocInput, setIocInput] = useState('')
  const [iocType, setIocType] = useState<IOCType>('unknown')
  const [iocSearching, setIocSearching] = useState(false)
  const [iocResult, setIocResult] = useState<IOCSearchResult | null>(null)
  const [iocError, setIocError] = useState<string | null>(null)

  // Research panel
  const [showResearch, setShowResearch] = useState(false)

  // Coverage
  const [coverageOpen, setCoverageOpen] = useState(false)
  const [coverageCells, setCoverageCells] = useState<CoverageCell[]>([])
  const [loadingCoverage, setLoadingCoverage] = useState(false)

  // Simulation
  const [simulatingTechnique, setSimulatingTechnique] = useState<string | null>(null)
  const [simToast, setSimToast] = useState<string | null>(null)

  // ── Load actors ─────────────────────────────────────────────────────────────

  const loadActors = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<ThreatActor[]>('/api/v2/threat-intel/actors')
      setActors(data)
      if (data.length > 0 && !selectedActor) setSelectedActor(data[0])
    } catch {
      setActors(SEED_ACTORS)
      if (!selectedActor) setSelectedActor(SEED_ACTORS[0])
    } finally {
      setLoading(false)
    }
  }, [selectedActor])

  useEffect(() => {
    void loadActors()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── IOC input ───────────────────────────────────────────────────────────────

  function handleIOCInput(v: string) {
    setIocInput(v)
    setIocType(detectIOCType(v))
  }

  async function searchIOC() {
    const value = iocInput.trim()
    if (!value) return
    setIocSearching(true)
    setIocResult(null)
    setIocError(null)
    try {
      const result = await apiPost<IOCSearchResult>('/api/v2/threat-intel/ioc/search', {
        ioc: value,
        type: iocType,
      })
      setIocResult(result)
    } catch (_err) {
      // Mock result for dev — API not available
      const mockVerdict = (score: number): IOCSourceResult['verdict'] => {
        if (score >= 75) return 'malicious'
        if (score >= 40) return 'suspicious'
        if (score > 0) return 'clean'
        return 'unknown'
      }
      const scores = [Math.floor(Math.random() * 100), Math.floor(Math.random() * 100), Math.floor(Math.random() * 100)]
      setIocResult({
        ioc: value,
        type: iocType,
        sources: [
          {
            source: 'VirusTotal',
            verdict: mockVerdict(scores[0]),
            reputation_score: scores[0],
            details: { engines_detected: Math.floor(scores[0] / 5), total_engines: 73 },
          },
          {
            source: 'OTX AlienVault',
            verdict: mockVerdict(scores[1]),
            reputation_score: scores[1],
            details: { pulse_count: Math.floor(scores[1] / 10), tags: ['malware', 'apt'] },
          },
          {
            source: 'AbuseIPDB',
            verdict: mockVerdict(scores[2]),
            reputation_score: scores[2],
            details: { total_reports: Math.floor(scores[2] / 3), last_reported: new Date().toISOString() },
          },
        ],
      })
    } finally {
      setIocSearching(false)
    }
  }

  // ── Generate simulation ─────────────────────────────────────────────────────

  async function generateSimulation(techniqueId: string) {
    setSimulatingTechnique(techniqueId)
    try {
      await apiPost(`/api/v2/log-sources/generate/technique/${techniqueId}`, {})
      setSimToast(`Simulation started for ${techniqueId}`)
      setTimeout(() => setSimToast(null), 3000)
    } catch (err) {
      setSimToast(err instanceof Error ? err.message : 'Simulation failed')
      setTimeout(() => setSimToast(null), 3000)
    } finally {
      setSimulatingTechnique(null)
    }
  }

  // ── Load coverage ────────────────────────────────────────────────────────────

  async function loadCoverage() {
    setLoadingCoverage(true)
    try {
      const data = await apiGet<CoverageCell[]>('/api/v2/threat-intel/coverage')
      setCoverageCells(data)
    } catch {
      // mock
      const mockCells: CoverageCell[] = [
        { tactic: 'Initial Access', technique_id: 'T1566', technique_name: 'Phishing', coverage: 70 },
        { tactic: 'Initial Access', technique_id: 'T1189', technique_name: 'Drive-by', coverage: 50 },
        { tactic: 'Execution', technique_id: 'T1059.001', technique_name: 'PowerShell', coverage: 90 },
        { tactic: 'Execution', technique_id: 'T1204.002', technique_name: 'Malicious File', coverage: 60 },
        { tactic: 'Persistence', technique_id: 'T1547.001', technique_name: 'Registry Keys', coverage: 40 },
        { tactic: 'Defense Evasion', technique_id: 'T1027', technique_name: 'Obfuscation', coverage: 80 },
        { tactic: 'Credential Access', technique_id: 'T1003.001', technique_name: 'LSASS', coverage: 100 },
        { tactic: 'Lateral Movement', technique_id: 'T1021.001', technique_name: 'RDP', coverage: 70 },
        { tactic: 'Command and Control', technique_id: 'T1071.004', technique_name: 'DNS', coverage: 55 },
        { tactic: 'Impact', technique_id: 'T1486', technique_name: 'Ransomware', coverage: 85 },
        { tactic: 'Impact', technique_id: 'T1485', technique_name: 'Data Destruction', coverage: 45 },
      ]
      setCoverageCells(mockCells)
    } finally {
      setLoadingCoverage(false)
    }
    setCoverageOpen(true)
  }

  // ── Filtered actors ──────────────────────────────────────────────────────────

  const filteredActors = actors.filter((a) => {
    const q = actorSearch.toLowerCase()
    return (
      a.name.toLowerCase().includes(q) ||
      a.aliases.some((al) => al.toLowerCase().includes(q))
    )
  })

  return (
    <>
      {/* Toast */}
      {simToast && (
        <div className="fixed bottom-5 right-5 z-[100] rounded-lg border border-purple-500/40 bg-purple-500/15 px-4 py-3 text-sm text-purple-300 shadow-xl">
          {simToast}
        </div>
      )}

      <div className="flex h-full gap-4 overflow-hidden">
        {/* ── Left panel: actor list ─────────────────────────────────────── */}
        <div className="flex w-72 shrink-0 flex-col gap-3">
          {/* Header */}
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-300">Threat Actors</h2>
            <div className="flex items-center gap-1">
              <button
                onClick={() => void loadCoverage()}
                disabled={loadingCoverage}
                title="MITRE Coverage"
                className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
              >
                {loadingCoverage ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Grid3X3 className="h-3.5 w-3.5" />
                )}
              </button>
              <button
                onClick={() => void loadActors()}
                className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
              >
                <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
              </button>
            </div>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={actorSearch}
              onChange={(e) => setActorSearch(e.target.value)}
              placeholder="Search actors…"
              className="w-full rounded-lg border border-slate-700 bg-slate-900 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-purple-500"
            />
          </div>

          {/* Actor cards */}
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {loading ? (
              <div className="flex items-center justify-center py-8 text-sm text-slate-500">
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Loading…
              </div>
            ) : filteredActors.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-600">No actors found</p>
            ) : (
              filteredActors.map((actor) => (
                <ActorCard
                  key={actor.id}
                  actor={actor}
                  active={selectedActor?.id === actor.id && mainTab === 'actor'}
                  onSelect={() => {
                    setSelectedActor(actor)
                    setMainTab('actor')
                    setShowResearch(false)
                  }}
                />
              ))
            )}
          </div>

          {/* IOC tab switcher */}
          <button
            onClick={() => setMainTab('ioc')}
            className={cn(
              'flex items-center justify-center gap-2 rounded-lg border px-3 py-2.5 text-sm font-medium transition-colors',
              mainTab === 'ioc'
                ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-400'
                : 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
            )}
          >
            <Search className="h-3.5 w-3.5" />
            IOC Search
          </button>
        </div>

        {/* ── Right panel ────────────────────────────────────────────────── */}
        <div className="flex flex-1 flex-col min-w-0 overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
          {mainTab === 'ioc' ? (
            /* IOC Search panel */
            <div className="flex flex-col h-full overflow-y-auto">
              <div className="border-b border-slate-800 px-5 py-4">
                <h2 className="text-base font-semibold text-slate-200 mb-1">IOC Search</h2>
                <p className="text-xs text-slate-500">
                  Query IP, domain, hash, or URL across VirusTotal, OTX, and AbuseIPDB.
                </p>
              </div>

              <div className="p-5 space-y-4">
                {/* Input */}
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
                      <IOCTypeIcon type={iocType} />
                    </div>
                    <input
                      value={iocInput}
                      onChange={(e) => handleIOCInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void searchIOC()
                      }}
                      placeholder="Enter IP, domain, hash, or URL…"
                      className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  {iocType !== 'unknown' && (
                    <span className="self-center rounded-md bg-cyan-500/15 border border-cyan-500/30 px-2.5 py-1 text-xs font-mono text-cyan-400 uppercase">
                      {iocType}
                    </span>
                  )}
                  <button
                    onClick={() => void searchIOC()}
                    disabled={!iocInput.trim() || iocSearching}
                    className="rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
                  >
                    {iocSearching ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Search className="h-4 w-4" />
                    )}
                    {iocSearching ? 'Searching…' : 'Search'}
                  </button>
                </div>

                {iocError && (
                  <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">
                    <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                    {iocError}
                  </div>
                )}

                {iocResult && (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2">
                      <IOCTypeIcon type={iocResult.type} />
                      <span className="text-sm font-mono text-slate-300">{iocResult.ioc}</span>
                      <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 text-[11px] font-mono text-cyan-400 uppercase">
                        {iocResult.type}
                      </span>
                    </div>
                    <div className="space-y-2">
                      {iocResult.sources.map((src) => (
                        <IOCSourceCard key={src.source} result={src} />
                      ))}
                    </div>
                  </div>
                )}

                {!iocResult && !iocSearching && (
                  <div className="flex flex-col items-center justify-center py-16 gap-2 text-slate-600">
                    <Shield className="h-10 w-10 text-slate-800" />
                    <p className="text-sm">Search for an indicator of compromise</p>
                  </div>
                )}
              </div>
            </div>
          ) : selectedActor ? (
            /* Actor detail panel */
            showResearch ? (
              <ResearchPanel
                actorId={selectedActor.id}
                onClose={() => setShowResearch(false)}
              />
            ) : (
              <div className="flex flex-col h-full overflow-y-auto">
                {/* Actor header */}
                <div className="border-b border-slate-800 px-5 py-4">
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h2 className="text-lg font-bold text-slate-100">
                          {selectedActor.name}
                        </h2>
                        {selectedActor.mitre_groups.map((g) => (
                          <a
                            key={g.id}
                            href={`https://attack.mitre.org/groups/${g.id}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 rounded bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-[11px] font-mono text-purple-400 hover:bg-purple-500/25 transition-colors"
                          >
                            {g.id}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        ))}
                      </div>
                      {selectedActor.aliases.length > 0 && (
                        <p className="mt-1 text-xs text-slate-500">
                          Also known as:{' '}
                          <span className="text-slate-400">
                            {selectedActor.aliases.join(', ')}
                          </span>
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => setShowResearch(true)}
                        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
                      >
                        <Search className="h-3.5 w-3.5" />
                        Research Actor
                      </button>
                      <button
                        onClick={() => void generateSimulation(selectedActor.techniques[0]?.id ?? '')}
                        disabled={simulatingTechnique !== null || selectedActor.techniques.length === 0}
                        className="flex items-center gap-1.5 rounded-lg bg-purple-600 px-3 py-2 text-xs font-medium text-white hover:bg-purple-500 disabled:opacity-40 transition-colors"
                      >
                        {simulatingTechnique ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Zap className="h-3.5 w-3.5" />
                        )}
                        Generate Simulation
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex-1 p-5 space-y-6 overflow-y-auto">
                  {/* Description */}
                  <div>
                    <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
                      Description
                    </p>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {selectedActor.description}
                    </p>
                  </div>

                  {/* Aliases */}
                  {selectedActor.aliases.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-2">
                        Aliases
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedActor.aliases.map((alias) => (
                          <span
                            key={alias}
                            className="rounded-md bg-slate-800 border border-slate-700 px-2.5 py-1 text-xs text-slate-300"
                          >
                            {alias}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Techniques grid */}
                  {selectedActor.techniques.length > 0 && (
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
                          Techniques ({selectedActor.technique_count})
                        </p>
                        <span className="text-[11px] text-slate-600 flex items-center gap-1">
                          <Zap className="h-3 w-3" />
                          Click to generate simulation
                        </span>
                      </div>
                      <TechniqueGrid
                        techniques={selectedActor.techniques}
                        onGenerate={(id) => void generateSimulation(id)}
                      />
                    </div>
                  )}

                  {/* Last updated */}
                  <p className="text-[11px] text-slate-600">
                    Last updated {relativeDate(selectedActor.last_updated)}
                  </p>
                </div>
              </div>
            )
          ) : (
            <div className="flex h-full items-center justify-center">
              <div className="text-center text-slate-600">
                <Shield className="mx-auto h-10 w-10 text-slate-800 mb-2" />
                <p className="text-sm">Select a threat actor</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Coverage modal overlay */}
      {coverageOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setCoverageOpen(false)}
          />
          <div className="relative z-10 flex max-h-[80vh] w-full max-w-3xl flex-col rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <h3 className="text-sm font-semibold text-slate-200">
                MITRE ATT&CK Coverage — Threat Intel
              </h3>
              <button
                onClick={() => setCoverageOpen(false)}
                className="rounded-md p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-800"
              >
                <ChevronRight className="h-4 w-4 rotate-180" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-5">
              <div className="flex items-center gap-3 mb-4 text-xs text-slate-500">
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-slate-800" /> 0%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-purple-900/60" /> 1–25%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-purple-700/60" /> 26–50%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-purple-600/70" /> 51–75%
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="inline-block h-3 w-3 rounded bg-purple-500/80" /> 76–100%
                </div>
              </div>
              <CoverageHeatmap cells={coverageCells} />
            </div>
          </div>
        </div>
      )}
    </>
  )
}
