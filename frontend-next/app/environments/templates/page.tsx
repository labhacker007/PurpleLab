'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Monitor,
  Cloud,
  Database,
  Shield,
  Users,
  Globe,
  Package,
  Plus,
  X,
  Check,
  Loader2,
  AlertCircle,
  RefreshCw,
  ExternalLink,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { apiGet, apiPost } from '@/lib/api/client'
import { useAuthStore } from '@/stores/auth'

// ─── Types ────────────────────────────────────────────────────────────────────

interface EnvironmentTemplate {
  id: string
  name: string
  slug: string
  category: string
  description: string
  topology: Record<string, unknown>
  default_log_sources: string[]
  default_settings: Record<string, unknown>
  icon: string
  is_builtin: boolean
  created_at: string
}

// ─── Icon map ─────────────────────────────────────────────────────────────────

const ICON_MAP: Record<string, React.ElementType> = {
  monitor: Monitor,
  cloud: Cloud,
  database: Database,
  shield: Shield,
  users: Users,
  globe: Globe,
  package: Package,
}

const CATEGORY_LABELS: Record<string, string> = {
  endpoint: 'Endpoint',
  k8s: 'Kubernetes',
  cspm: 'CSPM',
  vm: 'VM / Hypervisor',
  cmdb: 'CMDB',
  asm: 'Attack Surface',
  product: 'Product',
}

const CATEGORY_COLORS: Record<string, string> = {
  endpoint: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  k8s: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  cspm: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  vm: 'bg-green-500/15 text-green-400 border-green-500/30',
  cmdb: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  asm: 'bg-red-500/15 text-red-400 border-red-500/30',
  product: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
}

const SIEM_PLATFORMS = ['splunk', 'elastic', 'sentinel', 'qradar']

// ─── Seed data ────────────────────────────────────────────────────────────────

const SEED_TEMPLATES: EnvironmentTemplate[] = [
  {
    id: 'tpl-1', name: 'Windows Endpoint Lab', slug: 'windows-endpoint',
    category: 'endpoint', description: 'Standard Windows workstation environment with Sysmon, WEF, and EDR log sources for endpoint detection testing.',
    topology: { nodes: ['dc01', 'ws01', 'ws02'] }, default_log_sources: ['Sysmon', 'Windows Security', 'Windows PowerShell', 'WEF'],
    default_settings: { os: 'windows', domain: true }, icon: 'monitor', is_builtin: true, created_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'tpl-2', name: 'Kubernetes Cluster', slug: 'k8s-cluster',
    category: 'k8s', description: 'Multi-node Kubernetes cluster with Falco runtime security and audit logging for container threat detection.',
    topology: { nodes: ['master', 'node1', 'node2'] }, default_log_sources: ['Falco', 'K8s Audit', 'Containerd'],
    default_settings: { version: '1.29', cni: 'calico' }, icon: 'cloud', is_builtin: true, created_at: '2026-01-02T00:00:00Z',
  },
  {
    id: 'tpl-3', name: 'AWS CSPM Environment', slug: 'aws-cspm',
    category: 'cspm', description: 'AWS cloud environment with CloudTrail, GuardDuty, and Config rules for cloud security posture testing.',
    topology: { regions: ['us-east-1'], services: ['ec2', 's3', 'iam'] }, default_log_sources: ['CloudTrail', 'GuardDuty', 'VPC Flow Logs', 'Config'],
    default_settings: { provider: 'aws' }, icon: 'cloud', is_builtin: true, created_at: '2026-01-03T00:00:00Z',
  },
  {
    id: 'tpl-4', name: 'Linux VM Farm', slug: 'linux-vm',
    category: 'vm', description: 'Linux hypervisor environment with auditd, syslog, and network monitoring for server-side detections.',
    topology: { nodes: ['kvm-host', 'guest1', 'guest2'] }, default_log_sources: ['auditd', 'syslog', 'auth.log', 'Network Flow'],
    default_settings: { distro: 'ubuntu22' }, icon: 'database', is_builtin: true, created_at: '2026-01-04T00:00:00Z',
  },
  {
    id: 'tpl-5', name: 'Active Directory Domain', slug: 'ad-domain',
    category: 'endpoint', description: 'Full Active Directory lab with domain controller, LDAP, Kerberos event logging for identity attacks.',
    topology: { nodes: ['dc01', 'dc02', 'workstation'] }, default_log_sources: ['Windows Security 4624', 'Windows Security 4769', 'LDAP', 'DNS'],
    default_settings: { domain: 'lab.local', functional_level: '2019' }, icon: 'users', is_builtin: true, created_at: '2026-01-05T00:00:00Z',
  },
  {
    id: 'tpl-6', name: 'Azure CSPM', slug: 'azure-cspm',
    category: 'cspm', description: 'Azure cloud environment with Defender for Cloud, Activity Logs, and AAD sign-in log sources.',
    topology: { subscriptions: ['prod-sub'], resource_groups: ['rg-security'] }, default_log_sources: ['Azure Activity Log', 'AAD Sign-In', 'Microsoft Defender', 'NSG Flow Logs'],
    default_settings: { provider: 'azure' }, icon: 'shield', is_builtin: true, created_at: '2026-01-06T00:00:00Z',
  },
]

// ─── Category filter ──────────────────────────────────────────────────────────

const CATEGORIES = ['All', 'endpoint', 'k8s', 'cspm', 'vm', 'cmdb', 'asm', 'product']

// ─── Apply Template Modal ─────────────────────────────────────────────────────

interface ApplyModalProps {
  template: EnvironmentTemplate
  onClose: () => void
  onSuccess: (envId: string, envName: string) => void
}

function ApplyTemplateModal({ template, onClose, onSuccess }: ApplyModalProps) {
  const [envName, setEnvName] = useState(template.name + ' (Test)')
  const [siemPlatform, setSiemPlatform] = useState('splunk')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleApply() {
    if (!envName.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      const res = await apiPost<{ id: string; name: string }>('/api/v2/environments', {
        name: envName.trim(),
        siem_platform: siemPlatform,
        log_sources: template.default_log_sources,
        settings: {
          ...template.default_settings,
          siem_platform: siemPlatform,
          canvas_topology: template.topology,
          template_id: template.id,
          template_slug: template.slug,
        },
      })
      onSuccess(res.id, res.name)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create environment')
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md rounded-xl border border-border bg-card shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h3 className="text-sm font-semibold text-foreground">Apply Template</h3>
          <button onClick={onClose} className="rounded-lg p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Template info */}
          <div className="rounded-lg border border-border bg-muted/40 p-3">
            <p className="text-xs font-medium text-foreground">{template.name}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{template.description}</p>
            <div className="flex flex-wrap gap-1 mt-2">
              {template.default_log_sources.map((ls) => (
                <span key={ls} className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{ls}</span>
              ))}
            </div>
          </div>

          {/* Environment name */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Environment Name</label>
            <input
              value={envName}
              onChange={(e) => setEnvName(e.target.value)}
              placeholder="My Environment"
              className="field px-3 py-2 text-sm w-full"
            />
          </div>

          {/* SIEM platform */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">SIEM Platform</label>
            <select
              value={siemPlatform}
              onChange={(e) => setSiemPlatform(e.target.value)}
              className="field px-3 py-2 text-sm w-full"
            >
              {SIEM_PLATFORMS.map((p) => (
                <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
              ))}
            </select>
          </div>

          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
              <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              {error}
            </div>
          )}

          <div className="flex gap-2 pt-1">
            <button onClick={onClose} className="flex-1 rounded border border-border bg-muted/40 hover:bg-muted px-3 py-2 text-xs text-foreground transition-colors">
              Cancel
            </button>
            <button
              onClick={() => void handleApply()}
              disabled={!envName.trim() || submitting}
              className="flex-1 flex items-center justify-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {submitting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
              {submitting ? 'Creating…' : 'Create Environment'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Success Banner ───────────────────────────────────────────────────────────

function SuccessBanner({ envId, envName, onClose }: { envId: string; envName: string; onClose: () => void }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-xl border border-green-500/30 bg-card px-4 py-3 shadow-2xl">
      <Check className="h-4 w-4 text-green-400 shrink-0" />
      <div>
        <p className="text-sm font-medium text-foreground">Environment created</p>
        <p className="text-xs text-muted-foreground">{envName}</p>
      </div>
      <a
        href={`/environments/${envId}`}
        className="flex items-center gap-1 rounded border border-border bg-muted px-2.5 py-1 text-xs text-foreground hover:bg-muted/80 transition-colors ml-2"
      >
        <ExternalLink className="h-3 w-3" />
        Go to Environment
      </a>
      <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:text-foreground transition-colors">
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

// ─── Template Card ────────────────────────────────────────────────────────────

function TemplateCard({ template, onApply }: { template: EnvironmentTemplate; onApply: () => void }) {
  const Icon = ICON_MAP[template.icon] ?? Package
  const categoryLabel = CATEGORY_LABELS[template.category] ?? template.category

  return (
    <div className="rounded-lg border border-border bg-card p-4 flex flex-col gap-3 hover:border-primary/50 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
          <Icon className="h-5 w-5" />
        </div>
        <span className={cn('rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase', CATEGORY_COLORS[template.category] ?? 'bg-muted text-muted-foreground border-border')}>
          {categoryLabel}
        </span>
      </div>

      <div>
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-foreground">{template.name}</h3>
          {!template.is_builtin && (
            <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">custom</span>
          )}
        </div>
        <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{template.description}</p>
      </div>

      <div>
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">Default Log Sources</p>
        <div className="flex flex-wrap gap-1">
          {template.default_log_sources.slice(0, 4).map((ls) => (
            <span key={ls} className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-foreground">{ls}</span>
          ))}
          {template.default_log_sources.length > 4 && (
            <span className="text-[10px] text-muted-foreground">+{template.default_log_sources.length - 4} more</span>
          )}
        </div>
      </div>

      <button
        onClick={onApply}
        className="mt-auto flex items-center justify-center gap-1.5 rounded border border-border bg-muted/40 hover:bg-primary hover:text-white hover:border-primary px-3 py-2 text-xs font-medium text-foreground transition-colors"
      >
        <Plus className="h-3.5 w-3.5" />
        Apply Template
      </button>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EnvironmentTemplatesPage() {
  const user = useAuthStore((s) => s.user)
  const [templates, setTemplates] = useState<EnvironmentTemplate[]>([])
  const [loading, setLoading] = useState(true)
  const [category, setCategory] = useState('All')
  const [applyTarget, setApplyTarget] = useState<EnvironmentTemplate | null>(null)
  const [success, setSuccess] = useState<{ envId: string; envName: string } | null>(null)

  const canManage = user?.role === 'admin' || user?.role === 'engineer'

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = category !== 'All' ? `?category=${category}` : ''
      const data = await apiGet<EnvironmentTemplate[]>(`/api/v2/environment-templates${params}`)
      setTemplates(data)
    } catch {
      setTemplates(SEED_TEMPLATES)
    } finally {
      setLoading(false)
    }
  }, [category])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    if (!success) return
    const t = setTimeout(() => setSuccess(null), 8000)
    return () => clearTimeout(t)
  }, [success])

  const filtered = category === 'All' ? templates : templates.filter((t) => t.category === category)

  return (
    <>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div>
            <h1 className="text-lg font-semibold text-foreground">Environment Templates</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Apply pre-built environment topologies to accelerate testing setup
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => void load()} className="rounded border border-border bg-muted/40 hover:bg-muted p-2 text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </button>
            {canManage && (
              <button className="flex items-center gap-1.5 rounded bg-primary px-3 py-2 text-xs font-medium text-white hover:bg-primary/90 transition-colors">
                <Plus className="h-3.5 w-3.5" />
                Create Custom Template
              </button>
            )}
          </div>
        </div>

        {/* Category filter chips */}
        <div className="flex flex-wrap items-center gap-2">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={cn(
                'rounded-full border px-3 py-1 text-xs font-medium transition-colors',
                category === cat
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border bg-muted/40 text-muted-foreground hover:text-foreground hover:bg-muted'
              )}
            >
              {cat === 'All' ? 'All' : (CATEGORY_LABELS[cat] ?? cat)}
            </button>
          ))}
        </div>

        {/* Grid */}
        {loading ? (
          <div className="flex items-center justify-center py-20 gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading templates…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-2 text-sm text-muted-foreground">
            <Package className="h-8 w-8 opacity-30" />
            No templates found for this category
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {filtered.map((tpl) => (
              <TemplateCard key={tpl.id} template={tpl} onApply={() => setApplyTarget(tpl)} />
            ))}
          </div>
        )}
      </div>

      {/* Apply modal */}
      {applyTarget && (
        <ApplyTemplateModal
          template={applyTarget}
          onClose={() => setApplyTarget(null)}
          onSuccess={(envId, envName) => {
            setApplyTarget(null)
            setSuccess({ envId, envName })
          }}
        />
      )}

      {/* Success banner */}
      {success && (
        <SuccessBanner envId={success.envId} envName={success.envName} onClose={() => setSuccess(null)} />
      )}
    </>
  )
}
