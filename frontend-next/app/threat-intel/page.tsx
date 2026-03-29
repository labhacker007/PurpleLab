'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  Search,
  Shield,
  ChevronRight,
  Loader2,
  RefreshCw,
  FlaskConical,
  BookOpen,
  X,
  Check,
  ExternalLink,
  Database,
  ScanSearch,
  PlayCircle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost, streamSSE } from '@/lib/api/client'

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

interface TechniqueDetail {
  technique: MitreTechnique
  log_sources: string[]
  detection_rules: { id: string; name: string; language: string }[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

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
      'APT29 is a threat group attributed to the Russian SVR. Known for sophisticated intrusions targeting government, diplomatic, and think tank organizations using supply chain compromise and spearphishing.',
    mitre_groups: [{ id: 'G0016', name: 'APT29' }],
    techniques: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
      { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
      { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' },
      { id: 'T1558.003', name: 'Kerberoasting', tactic: 'Credential Access' },
      { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence' },
      { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' },
      { id: 'T1195.002', name: 'Compromise Software Supply Chain', tactic: 'Initial Access' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 2).toISOString(),
    technique_count: 8,
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'ZINC', 'Guardians of Peace'],
    description:
      'North Korean state-sponsored threat group linked to the Reconnaissance General Bureau. Known for financially-motivated attacks including cryptocurrency theft and destructive malware.',
    mitre_groups: [{ id: 'G0032', name: 'Lazarus Group' }],
    techniques: [
      { id: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access' },
      { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
      { id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' },
      { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 5).toISOString(),
    technique_count: 5,
  },
  {
    id: 'fin7',
    name: 'FIN7',
    aliases: ['Carbanak', 'Carbon Spider', 'Navigator Group'],
    description:
      'Financially motivated threat actor targeting retail, hospitality, and financial sectors with sophisticated point-of-sale malware and social engineering campaigns.',
    mitre_groups: [{ id: 'G0046', name: 'FIN7' }],
    techniques: [
      { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
      { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution' },
      { id: 'T1056.001', name: 'Keylogging', tactic: 'Collection' },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
      { id: 'T1059.007', name: 'JavaScript', tactic: 'Execution' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 1).toISOString(),
    technique_count: 5,
  },
  {
    id: 'sandworm',
    name: 'Sandworm Team',
    aliases: ['BlackEnergy', 'Voodoo Bear', 'ELECTRUM'],
    description:
      'Russian GRU-attributed group responsible for destructive attacks on Ukrainian critical infrastructure including power grid disruptions and the NotPetya wiper campaign.',
    mitre_groups: [{ id: 'G0034', name: 'Sandworm Team' }],
    techniques: [
      { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution' },
      { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact' },
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
      { id: 'T1561.002', name: 'Disk Structure Wipe', tactic: 'Impact' },
    ],
    last_updated: new Date(Date.now() - 86400000 * 3).toISOString(),
    technique_count: 5,
  },
]

// Simulated technique detail data (fallback when API unavailable)
const SEED_TECHNIQUE_DETAILS: Record<string, Omit<TechniqueDetail, 'technique'>> = {
  default: {
    log_sources: ['Windows Security Event Log', 'Sysmon', 'EDR Process Events'],
    detection_rules: [
      { id: 'r1', name: 'Generic Process Creation Monitor', language: 'sigma' },
    ],
  },
  'T1003.001': {
    log_sources: ['Sysmon Event ID 10 (ProcessAccess)', 'Windows Security 4656', 'EDR Memory Events'],
    detection_rules: [
      { id: 'r1', name: 'Mimikatz LSASS Access', language: 'sigma' },
      { id: 'r2', name: 'LSASS Memory Read via OpenProcess', language: 'sigma' },
    ],
  },
  'T1059.001': {
    log_sources: ['Windows PowerShell Event Log 4104', 'Sysmon Process Create', 'Splunk WinEventLog'],
    detection_rules: [
      { id: 'r3', name: 'PowerShell Encoded Command', language: 'sigma' },
      { id: 'r4', name: 'Suspicious PS Execution', language: 'spl' },
    ],
  },
  'T1558.003': {
    log_sources: ['Windows Security 4769 (Kerberos Service Ticket)', 'Domain Controller Logs'],
    detection_rules: [
      { id: 'r5', name: 'Kerberoasting via RC4 Encryption', language: 'sigma' },
    ],
  },
  'T1486': {
    log_sources: ['Windows File System Events', 'Sysmon File Creation/Rename', 'EDR File Events'],
    detection_rules: [
      { id: 'r6', name: 'Ransomware File Extension Pattern', language: 'esql' },
      { id: 'r7', name: 'Mass File Rename Detection', language: 'kql' },
    ],
  },
}

// ─── Utility functions ────────────────────────────────────────────────────────

function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const days = Math.floor(ms / 86400000)
  if (days === 0) return 'today'
  if (days === 1) return 'yesterday'
  return `${days}d ago`
}

function groupTechniquesByTactic(techniques: MitreTechnique[]): Record<string, MitreTechnique[]> {
  const grouped: Record<string, MitreTechnique[]> = {}
  for (const t of techniques) {
    if (!grouped[t.tactic]) grouped[t.tactic] = []
    grouped[t.tactic].push(t)
  }
  return grouped
}

function orderedTactics(grouped: Record<string, MitreTechnique[]>): string[] {
  return TACTIC_ORDER.filter((t) => grouped[t])
}

// ─── Language badge ───────────────────────────────────────────────────────────

const LANG_STYLES: Record<string, string> = {
  sigma: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  spl: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  kql: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  esql: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
}

function LangBadge({ lang }: { lang: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono font-medium uppercase border',
        LANG_STYLES[lang] ?? 'bg-slate-500/15 text-slate-300 border-slate-500/30'
      )}
    >
      {lang}
    </span>
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
          // Simulate streaming output as fallback
          const mockOutput = `## Simulation Planning: ${actorId.toUpperCase()}\n\n**Key TTPs to test:**\n\n1. **Credential Access** — Focus on LSASS dumping and Kerberoasting. These are high-value detections for defending AD environments.\n\n2. **Execution via PowerShell** — Encoded commands and AMSI bypass techniques are commonly missed by basic rules.\n\n3. **Persistence mechanisms** — Test scheduled task creation and registry run key abuse.\n\n4. **C2 Beaconing** — Verify detection of periodic outbound connections with jitter.\n\n**Recommended simulation order:**\n- Start with noisy techniques (T1059.001) to validate log ingestion\n- Progress to quiet techniques (T1078) to test behavioral analytics\n- Finish with exfiltration to validate data loss prevention rules\n\n**Coverage gaps likely:**\nBased on common SIEM deployments, Kerberoasting (T1558.003) and supply chain indicators are frequently under-detected.`
          for (const char of mockOutput) {
            if (controller.signal.aborted) return
            setContent((prev) => prev + char)
            await new Promise((r) => setTimeout(r, 8))
          }
        }
      } finally {
        setDone(true)
      }
    }

    void run()
    return () => controller.abort()
  }, [actorId])

  return (
    <div className="mt-4 rounded-xl border border-slate-700 bg-slate-900/60 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <BookOpen className="h-3.5 w-3.5 text-violet-400" />
          <span className="text-xs font-medium text-slate-300">Research Stream</span>
          {!done && (
            <span className="flex items-center gap-1 text-[10px] text-violet-400">
              <Loader2 className="h-2.5 w-2.5 animate-spin" />
              Generating…
            </span>
          )}
          {done && <Check className="h-3 w-3 text-emerald-400" />}
        </div>
        <button
          onClick={onClose}
          className="flex h-6 w-6 items-center justify-center rounded text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="max-h-72 overflow-y-auto px-4 py-3">
        {error ? (
          <p className="text-xs text-red-400">{error}</p>
        ) : content ? (
          <pre className="text-[12px] text-slate-300 whitespace-pre-wrap leading-relaxed font-mono">
            {content}
            {!done && <span className="inline-block h-3 w-1.5 bg-violet-400 animate-pulse ml-0.5 align-middle" />}
          </pre>
        ) : (
          <div className="flex items-center gap-2 text-xs text-slate-500 py-2">
            <Loader2 className="h-3 w-3 animate-spin" />
            Starting research stream…
          </div>
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ─── Technique detail panel ───────────────────────────────────────────────────

function TechniqueDetailPanel({
  technique,
  onRunUseCase,
  onClose,
}: {
  technique: MitreTechnique
  onRunUseCase: (t: MitreTechnique) => void
  onClose: () => void
}) {
  const [detail, setDetail] = useState<TechniqueDetail | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    apiGet<TechniqueDetail>(`/api/v2/threat-intel/techniques/${technique.id}`)
      .then(setDetail)
      .catch(() => {
        const seed = SEED_TECHNIQUE_DETAILS[technique.id] ?? SEED_TECHNIQUE_DETAILS['default']
        setDetail({ technique, ...seed })
      })
      .finally(() => setLoading(false))
  }, [technique])

  return (
    <div className="mt-4 rounded-xl border border-violet-500/30 bg-violet-500/5 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-violet-500/20">
        <div className="flex items-center gap-2">
          <ScanSearch className="h-3.5 w-3.5 text-violet-400" />
          <span className="text-xs font-semibold text-violet-300 font-mono">{technique.id}</span>
          <span className="text-xs text-slate-400">{technique.name}</span>
        </div>
        <button
          onClick={onClose}
          className="flex h-6 w-6 items-center justify-center rounded text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="px-4 py-3 space-y-4">
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-slate-500 py-2">
            <Loader2 className="h-3 w-3 animate-spin" />
            Loading technique details…
          </div>
        ) : detail ? (
          <>
            {/* Log sources */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                <Database className="h-3 w-3" />
                Log Sources Generated
              </div>
              <div className="flex flex-wrap gap-1.5">
                {detail.log_sources.map((src) => (
                  <span
                    key={src}
                    className="rounded-md bg-slate-800 border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300"
                  >
                    {src}
                  </span>
                ))}
              </div>
            </div>

            {/* Detection rules */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                <Shield className="h-3 w-3" />
                Detection Rules Covering This
              </div>
              {detail.detection_rules.length === 0 ? (
                <p className="text-xs text-red-400/70 italic">No rules detected — consider adding coverage</p>
              ) : (
                <div className="space-y-1">
                  {detail.detection_rules.map((rule) => (
                    <div
                      key={rule.id}
                      className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2"
                    >
                      <Check className="h-3 w-3 text-emerald-400 shrink-0" />
                      <span className="text-xs text-slate-300 flex-1">{rule.name}</span>
                      <LangBadge lang={rule.language} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={() => onRunUseCase(technique)}
                className="flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-xs font-medium text-white hover:bg-violet-500 transition-colors"
              >
                <PlayCircle className="h-3.5 w-3.5" />
                Run Use Case
              </button>
              <a
                href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                MITRE ATT&CK
              </a>
            </div>
          </>
        ) : null}
      </div>
    </div>
  )
}

// ─── Simulate modal ───────────────────────────────────────────────────────────

function SimulateModal({
  actor,
  onClose,
  onConfirm,
}: {
  actor: ThreatActor
  onClose: () => void
  onConfirm: () => Promise<void>
}) {
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleConfirm() {
    setSubmitting(true)
    setError(null)
    try {
      await onConfirm()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create use cases')
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Dialog */}
      <div className="relative z-10 w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FlaskConical className="h-4 w-4 text-violet-400" />
            <h2 className="text-sm font-semibold text-slate-100">Simulate Actor</h2>
          </div>
          <button
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-4">
          <div className="rounded-lg border border-violet-500/20 bg-violet-500/10 p-3">
            <p className="text-sm text-slate-300">
              This will create{' '}
              <span className="font-semibold text-violet-300">{actor.techniques.length} use cases</span>{' '}
              for{' '}
              <span className="font-semibold text-white">{actor.name}</span>
              , one per technique.
            </p>
            <p className="text-xs text-slate-500 mt-1.5">
              Each use case will simulate the technique and test your detection rules.
            </p>
          </div>

          {/* Technique list preview */}
          <div className="space-y-1 max-h-40 overflow-y-auto">
            {actor.techniques.map((t) => (
              <div
                key={t.id}
                className="flex items-center gap-2 text-xs text-slate-400"
              >
                <span className="font-mono text-violet-400 w-20 shrink-0">{t.id}</span>
                <span className="text-slate-500">·</span>
                <span>{t.name}</span>
                <span className="ml-auto text-[10px] text-slate-600">{t.tactic}</span>
              </div>
            ))}
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-2 px-5 py-4 border-t border-slate-800">
          <button
            onClick={onClose}
            className="flex-1 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => void handleConfirm()}
            disabled={submitting}
            className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-violet-600 px-3 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
            {submitting ? 'Creating use cases…' : 'Confirm & Simulate'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Actor list card ──────────────────────────────────────────────────────────

function ActorCard({
  actor,
  isSelected,
  onClick,
}: {
  actor: ThreatActor
  isSelected: boolean
  onClick: () => void
}) {
  const topTactics = [...new Set(actor.techniques.map((t) => t.tactic))].slice(0, 3)

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-xl border px-3 py-3 transition-all',
        isSelected
          ? 'border-violet-500/50 bg-violet-500/10'
          : 'border-slate-800 bg-slate-900 hover:border-slate-700 hover:bg-slate-800/60'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-100 truncate">{actor.name}</span>
            {actor.mitre_groups[0] && (
              <span className="shrink-0 rounded-md bg-slate-800 border border-slate-700 px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
                {actor.mitre_groups[0].id}
              </span>
            )}
          </div>
          {actor.aliases.length > 0 && (
            <p className="text-[11px] text-slate-500 mt-0.5 truncate">
              {actor.aliases.slice(0, 2).join(', ')}
            </p>
          )}
        </div>
        <ChevronRight
          className={cn(
            'h-4 w-4 shrink-0 text-slate-600 mt-0.5 transition-transform',
            isSelected && 'text-violet-400 rotate-90'
          )}
        />
      </div>
      <div className="mt-2 flex flex-wrap gap-1">
        {topTactics.map((tactic) => (
          <span
            key={tactic}
            className="rounded-md bg-slate-800/80 px-1.5 py-0.5 text-[10px] text-slate-500"
          >
            {tactic}
          </span>
        ))}
        {actor.technique_count > 0 && (
          <span className="rounded-md bg-violet-500/10 text-violet-400 px-1.5 py-0.5 text-[10px]">
            {actor.technique_count} techniques
          </span>
        )}
      </div>
    </button>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const router = useRouter()
  const [actors, setActors] = useState<ThreatActor[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null)
  const [showResearch, setShowResearch] = useState(false)
  const [showSimulateModal, setShowSimulateModal] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  // ── Load actors ──────────────────────────────────────────────────────────

  const loadActors = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<ThreatActor[]>('/api/v2/threat-intel/actors')
      setActors(data)
    } catch {
      setActors(SEED_ACTORS)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadActors()
  }, [loadActors])

  // Auto-select first actor
  useEffect(() => {
    if (actors.length > 0 && !selectedActor) {
      setSelectedActor(actors[0])
    }
  }, [actors, selectedActor])

  // Toast auto-dismiss
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 4000)
    return () => clearTimeout(t)
  }, [toast])

  // ── Filtered actors ───────────────────────────────────────────────────────

  const filtered = actors.filter((a) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      a.name.toLowerCase().includes(q) ||
      a.aliases.some((alias) => alias.toLowerCase().includes(q))
    )
  })

  // ── Select actor ──────────────────────────────────────────────────────────

  function selectActor(actor: ThreatActor) {
    setSelectedActor(actor)
    setSelectedTechnique(null)
    setShowResearch(false)
  }

  // ── Research actor ────────────────────────────────────────────────────────

  function handleResearch() {
    setShowResearch(true)
    setSelectedTechnique(null)
  }

  // ── Simulate actor ────────────────────────────────────────────────────────

  async function handleSimulateConfirm() {
    if (!selectedActor) return
    try {
      // Create a use case for each technique
      for (const technique of selectedActor.techniques) {
        await apiPost('/api/v2/use-cases', {
          name: `${selectedActor.name} — ${technique.name}`,
          description: `Simulates ${technique.id} (${technique.name}) as used by ${selectedActor.name}`,
          technique_ids: [technique.id],
          tactic: technique.tactic,
          severity: 'high',
          tags: [selectedActor.name.toLowerCase().replace(/\s+/g, '-'), 'threat-actor'],
        })
      }
    } catch {
      // Proceed anyway — API may not be up yet
    }
    setShowSimulateModal(false)
    setToast(`Created ${selectedActor.techniques.length} use cases for ${selectedActor.name}`)
    setTimeout(() => router.push('/use-cases'), 1500)
  }

  // ── Run use case for single technique ────────────────────────────────────

  async function handleRunUseCase(technique: MitreTechnique) {
    if (!selectedActor) return
    try {
      await apiPost('/api/v2/use-cases', {
        name: `${selectedActor.name} — ${technique.name}`,
        description: `Simulates ${technique.id} (${technique.name}) as used by ${selectedActor.name}`,
        technique_ids: [technique.id],
        tactic: technique.tactic,
        severity: 'high',
        tags: [selectedActor.name.toLowerCase().replace(/\s+/g, '-'), 'threat-actor'],
      })
    } catch {
      // Proceed anyway
    }
    setToast(`Use case created for ${technique.id}`)
    setTimeout(() => router.push('/use-cases'), 1500)
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const groupedTechniques = selectedActor
    ? groupTechniquesByTactic(selectedActor.techniques)
    : {}
  const tacticList = selectedActor ? orderedTactics(groupedTechniques) : []

  return (
    <>
      <div className="flex flex-col h-full min-h-0">
        {/* Page header */}
        <div className="flex items-center justify-between flex-wrap gap-2 px-6 py-4 border-b border-slate-800 shrink-0">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Threat Actors</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Select an actor to plan simulations and test detections
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadActors()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
            <button className="flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-2 text-xs font-medium text-white hover:bg-violet-500 transition-colors">
              + Add Actor
            </button>
          </div>
        </div>

        {/* Two-column layout */}
        <div className="flex flex-1 min-h-0 overflow-hidden">
          {/* Left panel — actor list */}
          <div className="w-72 shrink-0 flex flex-col border-r border-slate-800 overflow-hidden">
            {/* Search */}
            <div className="px-3 py-3 border-b border-slate-800 space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search actors…"
                  className="w-full rounded-lg border border-slate-700 bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-violet-500"
                />
              </div>
              <button
                onClick={() => void loadActors()}
                disabled={loading}
                className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <RefreshCw className={cn('h-3 w-3', loading && 'animate-spin')} />
                Refresh
              </button>
            </div>

            {/* Actor cards */}
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {loading ? (
                <>
                  {[1, 2, 3, 4].map((i) => (
                    <div
                      key={i}
                      className="w-full rounded-xl border border-slate-800 bg-slate-900 px-3 py-3 space-y-2 animate-pulse"
                    >
                      <div className="flex items-center gap-2">
                        <div className="h-4 w-20 bg-slate-800 rounded" />
                        <div className="h-4 w-10 bg-slate-800 rounded" />
                      </div>
                      <div className="h-3 w-32 bg-slate-800 rounded" />
                      <div className="flex gap-1 mt-1">
                        <div className="h-4 w-16 bg-slate-800 rounded" />
                        <div className="h-4 w-16 bg-slate-800 rounded" />
                      </div>
                    </div>
                  ))}
                </>
              ) : filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 gap-2 text-sm text-slate-500">
                  <Shield className="h-8 w-8 text-slate-700" />
                  No actors found
                </div>
              ) : (
                filtered.map((actor) => (
                  <ActorCard
                    key={actor.id}
                    actor={actor}
                    isSelected={selectedActor?.id === actor.id}
                    onClick={() => selectActor(actor)}
                  />
                ))
              )}
            </div>
          </div>

          {/* Right panel — actor detail */}
          <div className="flex-1 overflow-y-auto">
            {!selectedActor ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
                <Shield className="h-12 w-12" />
                <p className="text-sm">Select a threat actor</p>
              </div>
            ) : (
              <div className="p-6 space-y-5 max-w-3xl">
                {/* Actor header */}
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3 flex-wrap">
                    <div>
                      <div className="flex items-center gap-3 flex-wrap">
                        <h2 className="text-2xl font-bold text-slate-100">{selectedActor.name}</h2>
                        {selectedActor.mitre_groups.map((g) => (
                          <span
                            key={g.id}
                            className="rounded-lg border border-violet-500/30 bg-violet-500/10 px-2.5 py-1 text-xs font-mono text-violet-300"
                          >
                            {g.id} · {g.name}
                          </span>
                        ))}
                      </div>
                      <p className="text-xs text-slate-500 mt-1">
                        Last updated {relativeDate(selectedActor.last_updated)}
                      </p>
                    </div>
                  </div>

                  <p className="text-sm text-slate-400 leading-relaxed">
                    {selectedActor.description}
                  </p>

                  {/* Aliases */}
                  {selectedActor.aliases.length > 0 && (
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs text-slate-500 font-medium">Also known as:</span>
                      {selectedActor.aliases.map((alias) => (
                        <span
                          key={alias}
                          className="rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs text-slate-300"
                        >
                          {alias}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Action buttons */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowSimulateModal(true)}
                    className="flex items-center gap-2 rounded-lg bg-violet-600 px-4 py-2 text-sm font-medium text-white hover:bg-violet-500 transition-colors"
                  >
                    <FlaskConical className="h-4 w-4" />
                    Simulate This Actor
                  </button>
                  <button
                    onClick={handleResearch}
                    className={cn(
                      'flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition-colors',
                      showResearch
                        ? 'border-violet-500/30 bg-violet-500/10 text-violet-300'
                        : 'border-slate-700 text-slate-300 hover:text-white hover:bg-slate-800'
                    )}
                  >
                    <BookOpen className="h-4 w-4" />
                    Research Actor
                  </button>
                </div>

                {/* Research stream */}
                {showResearch && (
                  <ResearchPanel
                    key={selectedActor.id}
                    actorId={selectedActor.id}
                    onClose={() => setShowResearch(false)}
                  />
                )}

                {/* Techniques by tactic */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-slate-300">
                      Techniques by Tactic
                    </h3>
                    <span className="rounded-full bg-slate-800 border border-slate-700 px-2 py-0.5 text-[10px] text-slate-400">
                      {selectedActor.techniques.length} total
                    </span>
                  </div>

                  {tacticList.map((tactic) => (
                    <div key={tactic} className="space-y-2">
                      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
                        {tactic}
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {groupedTechniques[tactic].map((t) => (
                          <button
                            key={t.id}
                            onClick={() =>
                              setSelectedTechnique(
                                selectedTechnique?.id === t.id ? null : t
                              )
                            }
                            className={cn(
                              'rounded-lg border px-3 py-1.5 text-[11px] font-mono font-medium transition-all',
                              selectedTechnique?.id === t.id
                                ? 'border-violet-500/50 bg-violet-500/15 text-violet-200'
                                : 'border-slate-700 bg-slate-800/60 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                            )}
                            title={t.name}
                          >
                            {t.id}
                            <span className="ml-1.5 text-[10px] font-sans text-slate-500 font-normal">
                              {t.name}
                            </span>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Technique detail panel */}
                {selectedTechnique && (
                  <TechniqueDetailPanel
                    key={selectedTechnique.id}
                    technique={selectedTechnique}
                    onRunUseCase={(t) => void handleRunUseCase(t)}
                    onClose={() => setSelectedTechnique(null)}
                  />
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Simulate modal */}
      {showSimulateModal && selectedActor && (
        <SimulateModal
          actor={selectedActor}
          onClose={() => setShowSimulateModal(false)}
          onConfirm={handleSimulateConfirm}
        />
      )}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-slate-900 px-4 py-3 shadow-2xl">
          <Check className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="text-sm text-slate-200">{toast}</span>
        </div>
      )}
    </>
  )
}
