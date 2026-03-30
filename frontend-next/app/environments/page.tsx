'use client'

import { useState, useEffect, useCallback } from 'react'
import Link from 'next/link'
import {
  Plus, Server, Clock, Layers, CheckCircle2, XCircle, ExternalLink, Trash2,
  RefreshCw, Loader2, Monitor, Settings2, Shield, Cpu, HardDrive,
  AlertTriangle, Pencil,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Dialog, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { authFetch } from '@/lib/auth'
import { cn } from '@/lib/utils'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Environment {
  id: string
  name: string
  description: string
  siem_platform: string
  os_type: string
  log_sources: string[]
  settings: Record<string, unknown>
  siem_connections: any[]
  test_runs: any[]
  rules_count: number
  created_at: string
  updated_at: string
}

const OS_OPTIONS = [
  { id: 'windows', label: 'Windows', icon: Monitor, desc: 'Windows Server/Desktop endpoints' },
  { id: 'linux', label: 'Linux', icon: HardDrive, desc: 'Linux servers and containers' },
  { id: 'macos', label: 'macOS', icon: Cpu, desc: 'macOS endpoints' },
  { id: 'multi', label: 'Multi-OS', icon: Layers, desc: 'Mixed OS environment' },
]

const SIEM_OPTIONS = [
  { id: 'splunk', label: 'Splunk', color: 'text-green' },
  { id: 'elastic', label: 'Elastic SIEM', color: 'text-amber-400' },
  { id: 'sentinel', label: 'Microsoft Sentinel', color: 'text-blue' },
  { id: 'qradar', label: 'IBM QRadar', color: 'text-purple-400' },
  { id: 'chronicle', label: 'Google Chronicle', color: 'text-red' },
]

const LOG_SOURCES: Record<string, { label: string; os: string[] }> = {
  windows_security: { label: 'Windows Security', os: ['windows', 'multi'] },
  sysmon: { label: 'Sysmon', os: ['windows', 'multi'] },
  windows_powershell: { label: 'PowerShell', os: ['windows', 'multi'] },
  crowdstrike: { label: 'CrowdStrike', os: ['windows', 'linux', 'macos', 'multi'] },
  linux_audit: { label: 'Linux Audit', os: ['linux', 'multi'] },
  syslog: { label: 'Syslog', os: ['linux', 'macos', 'multi'] },
  osquery: { label: 'osquery', os: ['windows', 'linux', 'macos', 'multi'] },
  okta: { label: 'Okta', os: ['windows', 'linux', 'macos', 'multi'] },
  azure_ad: { label: 'Azure AD / Entra ID', os: ['windows', 'linux', 'macos', 'multi'] },
  aws_cloudtrail: { label: 'AWS CloudTrail', os: ['linux', 'multi'] },
  kubernetes: { label: 'Kubernetes', os: ['linux', 'multi'] },
  dns: { label: 'DNS Logs', os: ['windows', 'linux', 'macos', 'multi'] },
  firewall: { label: 'Firewall Logs', os: ['windows', 'linux', 'macos', 'multi'] },
  proxy: { label: 'Web Proxy', os: ['windows', 'linux', 'macos', 'multi'] },
  email_gateway: { label: 'Email Gateway', os: ['windows', 'linux', 'macos', 'multi'] },
  active_directory: { label: 'Active Directory', os: ['windows', 'multi'] },
  gcp_audit: { label: 'GCP Audit', os: ['linux', 'multi'] },
  office365: { label: 'Office 365', os: ['windows', 'macos', 'multi'] },
  waf: { label: 'WAF Logs', os: ['linux', 'multi'] },
  ids: { label: 'IDS/IPS', os: ['windows', 'linux', 'macos', 'multi'] },
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ type, message }: { type: 'success' | 'error'; message: string }) {
  return (
    <div className={cn(
      'fixed bottom-5 right-5 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-xl',
      type === 'success' ? 'border-green/40 bg-green/10 text-green' : 'border-red/40 bg-red/10 text-red'
    )}>
      {type === 'success' ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
      {message}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EnvironmentsPage() {
  const [environments, setEnvironments] = useState<Environment[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [creating, setCreating] = useState(false)
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Create form state
  const [form, setForm] = useState({
    name: '',
    description: '',
    os_type: 'windows',
    siem_platform: 'splunk',
    log_sources: ['windows_security', 'sysmon'] as string[],
  })

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await authFetch('/api/v2/environments')
      if (res.ok) {
        const data = await res.json()
        setEnvironments(data.environments ?? data ?? [])
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { void load() }, [load])

  // Filter log sources by selected OS
  function getLogSourcesForOS(os: string) {
    return Object.entries(LOG_SOURCES).filter(([, v]) => v.os.includes(os))
  }

  function toggleLogSource(src: string) {
    setForm(f => ({
      ...f,
      log_sources: f.log_sources.includes(src)
        ? f.log_sources.filter(s => s !== src)
        : [...f.log_sources, src]
    }))
  }

  // Update default log sources when OS changes
  function handleOSChange(os: string) {
    const defaults: Record<string, string[]> = {
      windows: ['windows_security', 'sysmon', 'windows_powershell'],
      linux: ['linux_audit', 'syslog'],
      macos: ['syslog', 'osquery'],
      multi: ['windows_security', 'sysmon', 'linux_audit', 'syslog'],
    }
    setForm(f => ({ ...f, os_type: os, log_sources: defaults[os] ?? [] }))
  }

  async function handleCreate() {
    if (!form.name.trim()) return
    setCreating(true)
    try {
      const res = await authFetch('/api/v2/environments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: form.name.trim(),
          description: form.description.trim(),
          siem_platform: form.siem_platform,
          log_sources: form.log_sources,
          settings: { os_type: form.os_type },
        }),
      })
      if (res.ok) {
        showToast('success', 'Environment created')
        setShowCreate(false)
        setForm({ name: '', description: '', os_type: 'windows', siem_platform: 'splunk', log_sources: ['windows_security', 'sysmon'] })
        await load()
      } else {
        const err = await res.json()
        showToast('error', err.detail ?? 'Failed to create')
      }
    } catch {
      showToast('error', 'Failed to create environment')
    }
    setCreating(false)
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this environment? This will also delete all connected SIEM connections and test runs.')) return
    try {
      const res = await authFetch(`/api/v2/environments/${id}`, { method: 'DELETE' })
      if (res.ok) {
        showToast('success', 'Environment deleted')
        await load()
      }
    } catch {
      showToast('error', 'Failed to delete')
    }
  }

  function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return 'just now'
    if (mins < 60) return `${mins}m ago`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `${hrs}h ago`
    return `${Math.floor(hrs / 24)}d ago`
  }

  const osIcon = (os: string) => {
    const opt = OS_OPTIONS.find(o => o.id === os)
    return opt ? <opt.icon className="h-4 w-4" /> : <Server className="h-4 w-4" />
  }

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-text">Environments</h1>
            <p className="text-sm text-muted mt-1">
              Configure detection environments with OS type, SIEM platform, and log sources.
            </p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="ghost" onClick={load} disabled={loading}>
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </Button>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4" /> New Environment
            </Button>
          </div>
        </div>

        {/* Environment List */}
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="animate-pulse h-48 rounded-xl bg-border/40" />)}
          </div>
        ) : environments.length === 0 ? (
          <Card>
            <CardContent className="p-12 text-center">
              <Server className="h-12 w-12 text-muted mx-auto mb-4" />
              <h2 className="text-lg font-semibold">No environments yet</h2>
              <p className="text-sm text-muted mt-1">
                Create your first environment to configure OS, SIEM, log sources, and detection rules.
              </p>
              <Button className="mt-4" onClick={() => setShowCreate(true)}>
                Create Environment
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {environments.map(env => {
              const os = (env.settings as any)?.os_type ?? 'windows'
              const logCount = Array.isArray(env.log_sources) ? env.log_sources.length : 0
              const siemCount = env.siem_connections?.length ?? 0

              return (
                <Card key={env.id} className="hover:border-primary/40 transition-colors group">
                  <CardContent className="p-5 flex flex-col h-full">
                    {/* Header */}
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 shrink-0">
                          {osIcon(os)}
                        </div>
                        <div>
                          <h3 className="font-semibold text-sm text-text">{env.name}</h3>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] rounded-full px-2 py-0.5 border border-border text-muted">
                              {OS_OPTIONS.find(o => o.id === os)?.label ?? os}
                            </span>
                            <span className="text-[10px] rounded-full px-2 py-0.5 border border-border text-muted">
                              {SIEM_OPTIONS.find(s => s.id === env.siem_platform)?.label ?? env.siem_platform}
                            </span>
                          </div>
                        </div>
                      </div>
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100"
                        onClick={() => handleDelete(env.id)}>
                        <Trash2 className="h-3 w-3 text-red" />
                      </Button>
                    </div>

                    <p className="text-xs text-muted line-clamp-2 flex-1 mb-3">
                      {env.description || 'No description'}
                    </p>

                    {/* Stats */}
                    <div className="flex items-center gap-3 text-[10px] text-muted mb-3">
                      <span className="flex items-center gap-1"><Layers className="h-3 w-3" /> {logCount} sources</span>
                      <span className="flex items-center gap-1"><Shield className="h-3 w-3" /> {env.rules_count ?? 0} rules</span>
                      <span className="flex items-center gap-1"><Server className="h-3 w-3" /> {siemCount} SIEM</span>
                      <span className="ml-auto flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {timeAgo(env.created_at)}
                      </span>
                    </div>

                    {/* Log sources preview */}
                    {logCount > 0 && (
                      <div className="flex gap-1 flex-wrap mb-3">
                        {(Array.isArray(env.log_sources) ? env.log_sources : []).slice(0, 5).map(src => (
                          <span key={src} className="text-[9px] rounded-full px-2 py-0.5 bg-border text-muted">
                            {LOG_SOURCES[src]?.label ?? src}
                          </span>
                        ))}
                        {logCount > 5 && <span className="text-[9px] text-muted">+{logCount - 5} more</span>}
                      </div>
                    )}

                    {/* Actions */}
                    <div className="pt-3 border-t border-border flex gap-2">
                      <Link href={`/environments/${env.id}`} className="flex-1">
                        <Button size="sm" variant="ghost" className="w-full gap-1.5">
                          <ExternalLink className="h-3.5 w-3.5" /> Open Canvas
                        </Button>
                      </Link>
                    </div>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        )}

        {/* ── Create Dialog ──────────────────────────────────────────────────── */}
        <Dialog open={showCreate} onClose={() => setShowCreate(false)}>
          <DialogHeader>
            <DialogTitle>Create Environment</DialogTitle>
          </DialogHeader>
          <div className="space-y-5">
            {/* Name & Description */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">Name</label>
                <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="Corp SOC Production" className="mt-1" autoFocus />
              </div>
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">Description</label>
                <Input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Testing EDR detection coverage..." className="mt-1" />
              </div>
            </div>

            {/* OS Type */}
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider mb-2 block">Operating System</label>
              <div className="grid grid-cols-4 gap-2">
                {OS_OPTIONS.map(os => (
                  <button key={os.id} onClick={() => handleOSChange(os.id)}
                    className={cn(
                      'rounded-lg border p-3 text-left transition-colors',
                      form.os_type === os.id ? 'border-primary bg-primary/10' : 'border-border hover:border-primary/40'
                    )}>
                    <os.icon className={cn('h-5 w-5 mb-1', form.os_type === os.id ? 'text-primary' : 'text-muted')} />
                    <div className="text-xs font-medium text-text">{os.label}</div>
                    <div className="text-[9px] text-muted mt-0.5">{os.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* SIEM Platform */}
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider mb-2 block">SIEM Platform</label>
              <div className="flex gap-2 flex-wrap">
                {SIEM_OPTIONS.map(siem => (
                  <button key={siem.id} onClick={() => setForm(f => ({ ...f, siem_platform: siem.id }))}
                    className={cn(
                      'rounded-lg border px-3 py-2 text-xs font-medium transition-colors',
                      form.siem_platform === siem.id ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted hover:text-text'
                    )}>
                    {siem.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Log Sources */}
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider mb-2 block">
                Log Sources ({form.log_sources.length} selected)
              </label>
              <div className="grid grid-cols-3 gap-1.5 max-h-[200px] overflow-y-auto">
                {getLogSourcesForOS(form.os_type).map(([key, val]) => (
                  <button key={key} onClick={() => toggleLogSource(key)}
                    className={cn(
                      'rounded-md border px-2.5 py-1.5 text-xs text-left transition-colors',
                      form.log_sources.includes(key)
                        ? 'border-green/40 bg-green/10 text-green'
                        : 'border-border text-muted hover:text-text'
                    )}>
                    {form.log_sources.includes(key) && <CheckCircle2 className="h-3 w-3 inline mr-1" />}
                    {val.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={handleCreate} disabled={creating || !form.name.trim()}>
              {creating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Create Environment
            </Button>
          </DialogFooter>
        </Dialog>
      </div>
    </>
  )
}
