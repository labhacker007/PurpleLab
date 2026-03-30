'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle2, XCircle, Loader2, Plug, Zap, Trash2, Plus, RefreshCw,
  Server, Send, ArrowDownToLine, ExternalLink, AlertTriangle, Webhook,
  Bell, Shield,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { authFetch } from '@/lib/auth'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SIEMConnection {
  id: string
  name: string
  siem_type: string
  base_url: string
  status: string
  last_tested_at: string | null
  created_at: string
}

interface HITLConfig {
  action_type: string
  approval_level: number
  notify_channels: string[]
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

// ─── SIEM Connections Tab ─────────────────────────────────────────────────────

const SIEM_TYPES = [
  { id: 'splunk', name: 'Splunk Enterprise', icon: '🟢', color: 'text-green' },
  { id: 'elastic', name: 'Elastic SIEM', icon: '🟡', color: 'text-amber-400' },
  { id: 'sentinel', name: 'Microsoft Sentinel', icon: '🔵', color: 'text-blue' },
]

function SIEMTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [connections, setConnections] = useState<SIEMConnection[]>([])
  const [loading, setLoading] = useState(true)
  const [testing, setTesting] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', siem_type: 'splunk', base_url: '', token: '' })
  const [creating, setCreating] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await authFetch('/api/v2/siem/connections')
      if (res.ok) {
        const data = await res.json()
        setConnections(data.connections ?? data ?? [])
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleTest(id: string) {
    setTesting(id)
    try {
      const res = await authFetch(`/api/v2/siem/connections/${id}/test`, { method: 'POST' })
      const data = await res.json()
      showToast(data.connected ? 'success' : 'error',
        data.connected ? `Connected (${data.latency_ms}ms)` : `Failed: ${data.error}`)
      await load()
    } catch {
      showToast('error', 'Connection test failed')
    }
    setTesting(null)
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this SIEM connection?')) return
    try {
      await authFetch(`/api/v2/siem/connections/${id}`, { method: 'DELETE' })
      showToast('success', 'Connection deleted')
      await load()
    } catch {
      showToast('error', 'Failed to delete')
    }
  }

  async function handleCreate() {
    setCreating(true)
    try {
      const body = {
        name: form.name,
        siem_type: form.siem_type,
        base_url: form.base_url,
        credentials: { token: form.token },
      }
      const res = await authFetch('/api/v2/siem/connections', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        showToast('success', 'Connection created')
        setShowForm(false)
        setForm({ name: '', siem_type: 'splunk', base_url: '', token: '' })
        await load()
      } else {
        const err = await res.json()
        showToast('error', err.detail ?? 'Failed to create')
      }
    } catch {
      showToast('error', 'Failed to create connection')
    }
    setCreating(false)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">
          Connect to your SIEM platforms to push logs, sync rules, and validate detections.
        </p>
        <div className="flex gap-2">
          <Button size="sm" variant="ghost" onClick={load}><RefreshCw className="h-3.5 w-3.5" /></Button>
          <Button size="sm" onClick={() => setShowForm(true)}><Plus className="h-3.5 w-3.5" /> Add Connection</Button>
        </div>
      </div>

      {/* Add form */}
      {showForm && (
        <Card className="border-primary/30">
          <CardContent className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">Name</label>
                <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="My Splunk" className="h-8 text-xs mt-1" />
              </div>
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">SIEM Type</label>
                <select value={form.siem_type} onChange={e => setForm(f => ({ ...f, siem_type: e.target.value }))}
                  className="mt-1 h-8 w-full rounded-md border border-border bg-bg px-2 text-xs text-text">
                  {SIEM_TYPES.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">Base URL</label>
                <Input value={form.base_url} onChange={e => setForm(f => ({ ...f, base_url: e.target.value }))}
                  placeholder="https://splunk.example.com:8089" className="h-8 text-xs mt-1" />
              </div>
              <div>
                <label className="text-[10px] text-muted uppercase tracking-wider">Auth Token</label>
                <Input type="password" value={form.token} onChange={e => setForm(f => ({ ...f, token: e.target.value }))}
                  placeholder="Bearer token or API key" className="h-8 text-xs mt-1" />
              </div>
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={handleCreate} disabled={creating || !form.name || !form.base_url}>
                {creating ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plus className="h-3 w-3" />}
                Create
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setShowForm(false)}>Cancel</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Connection list */}
      {loading ? (
        <div className="space-y-2">{[1,2].map(i => <div key={i} className="animate-pulse h-20 rounded-xl bg-border/40" />)}</div>
      ) : connections.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Server className="h-8 w-8 text-muted mx-auto mb-3" />
            <p className="text-sm text-muted">No SIEM connections configured.</p>
            <p className="text-xs text-muted mt-1">Add a connection to start pushing logs and syncing rules.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {connections.map(conn => {
            const siem = SIEM_TYPES.find(s => s.id === conn.siem_type)
            return (
              <div key={conn.id} className="flex items-center justify-between rounded-xl border border-border bg-card p-4">
                <div className="flex items-center gap-3">
                  <span className="text-lg">{siem?.icon ?? '⚪'}</span>
                  <div>
                    <div className="text-sm font-medium text-text">{conn.name}</div>
                    <div className="text-[10px] text-muted font-mono">{conn.base_url}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className={cn('text-[10px] rounded-full px-2 py-0.5 border',
                    conn.status === 'connected' ? 'border-green/30 bg-green/10 text-green' : 'border-border text-muted'
                  )}>{conn.status ?? 'unknown'}</span>
                  <Button size="sm" variant="ghost" className="h-7" onClick={() => handleTest(conn.id)} disabled={testing === conn.id}>
                    {testing === conn.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                    Test
                  </Button>
                  <Button size="sm" variant="ghost" className="h-7 text-red hover:text-red" onClick={() => handleDelete(conn.id)}>
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Supported platforms */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs text-muted">Supported SIEM Platforms</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-3">
            {SIEM_TYPES.map(s => (
              <div key={s.id} className="rounded-lg border border-border p-3 text-center">
                <span className="text-2xl">{s.icon}</span>
                <div className="text-xs font-medium text-text mt-1">{s.name}</div>
                <div className="text-[10px] text-muted mt-0.5">Push logs, sync rules, test connectivity</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Webhooks & Joti Tab ──────────────────────────────────────────────────────

function WebhooksTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [metrics, setMetrics] = useState<any>(null)

  useEffect(() => {
    authFetch('/api/v2/dashboard/metrics').then(r => r.json()).then(setMetrics).catch(() => {})
  }, [])

  const jotiConnected = metrics?.joti_integration?.configured ?? false

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Manage webhook endpoints for external platform integrations.
      </p>

      {/* Joti Integration */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Shield className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm">Joti Integration</CardTitle>
            </div>
            <span className={cn('text-[10px] rounded-full px-2 py-0.5 border',
              jotiConnected ? 'border-green/30 bg-green/10 text-green' : 'border-border text-muted'
            )}>{jotiConnected ? 'connected' : 'not configured'}</span>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted">
            Connect PurpleLab to your Joti TIP instance to receive threat intel alerts and synchronize detection validation results.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-border p-3">
              <div className="text-[10px] text-muted uppercase tracking-wider mb-1">Joti Base URL</div>
              <div className="text-xs font-mono text-text">{metrics?.joti_integration?.base_url || 'Not set'}</div>
            </div>
            <div className="rounded-lg border border-border p-3">
              <div className="text-[10px] text-muted uppercase tracking-wider mb-1">Webhook Endpoint</div>
              <div className="text-xs font-mono text-text">POST /api/joti/webhook/alerts</div>
            </div>
          </div>
          <p className="text-[10px] text-muted">
            Set <code className="bg-border/50 px-1 rounded">JOTI_BASE_URL</code> and <code className="bg-border/50 px-1 rounded">JOTI_API_KEY</code> in your environment to enable this integration.
          </p>
        </CardContent>
      </Card>

      {/* Webhook endpoints info */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2.5">
            <Webhook className="h-4 w-4 text-muted" />
            <CardTitle className="text-sm">Available Webhooks</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              { method: 'POST', path: '/api/joti/webhook/alerts', desc: 'Receive attack simulation alerts from Joti', auth: 'X-Joti-Token header' },
              { method: 'POST', path: '/api/v2/siem/connections/{id}/push-logs', desc: 'Push generated logs to a SIEM', auth: 'Bearer token' },
              { method: 'GET', path: '/api/v2/notifications/stream', desc: 'SSE stream of real-time notifications', auth: 'Bearer token' },
              { method: 'GET', path: '/api/v2/hitl/approve/{token}', desc: 'Magic link approval for HITL requests', auth: 'Token in URL' },
            ].map(wh => (
              <div key={wh.path} className="flex items-start gap-3 rounded-lg border border-border p-3">
                <span className={cn('text-[10px] font-mono font-bold rounded px-1.5 py-0.5 mt-0.5',
                  wh.method === 'POST' ? 'bg-blue/10 text-blue border border-blue/30'
                    : 'bg-green/10 text-green border border-green/30'
                )}>{wh.method}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono text-text truncate">{wh.path}</div>
                  <div className="text-[10px] text-muted mt-0.5">{wh.desc}</div>
                </div>
                <span className="text-[9px] text-muted shrink-0">{wh.auth}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── HITL Notifications Tab ───────────────────────────────────────────────────

function NotificationsTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [configs, setConfigs] = useState<HITLConfig[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    authFetch('/api/v2/hitl/config')
      .then(r => r.json())
      .then(data => setConfigs(data.configs ?? data ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const levelLabels = ['Auto (L0)', 'Soft Confirm (L1)', 'Explicit Approve (L2)', 'Multi-Party (L3)']
  const levelColors = ['text-green', 'text-blue', 'text-amber-400', 'text-red']

  async function updateLevel(action: string, level: number) {
    try {
      await authFetch(`/api/v2/hitl/config/${action}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_level: level }),
      })
      setConfigs(prev => prev.map(c => c.action_type === action ? { ...c, approval_level: level } : c))
      showToast('success', `${action} approval level updated`)
    } catch {
      showToast('error', 'Failed to update')
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Configure Human-in-the-Loop (HITL) approval levels and notification channels for automated actions.
      </p>

      {loading ? (
        <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="animate-pulse h-16 rounded-xl bg-border/40" />)}</div>
      ) : configs.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center">
            <Bell className="h-8 w-8 text-muted mx-auto mb-2" />
            <p className="text-sm text-muted">No HITL configurations found.</p>
            <p className="text-xs text-muted mt-1">HITL approval policies are auto-created when features are first used.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-card/50">
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-4 py-2.5">Action</th>
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[200px]">Approval Level</th>
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5">Notify Channels</th>
              </tr>
            </thead>
            <tbody>
              {configs.map(cfg => (
                <tr key={cfg.action_type} className="border-b border-border last:border-0">
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono font-medium text-text">{cfg.action_type}</span>
                  </td>
                  <td className="px-3 py-3">
                    <select
                      value={cfg.approval_level}
                      onChange={e => updateLevel(cfg.action_type, parseInt(e.target.value))}
                      className={cn('h-7 rounded-md border border-border bg-bg px-2 text-xs', levelColors[cfg.approval_level])}
                    >
                      {levelLabels.map((l, i) => <option key={i} value={i}>{l}</option>)}
                    </select>
                  </td>
                  <td className="px-3 py-3">
                    <div className="flex gap-1">
                      {(cfg.notify_channels ?? []).length > 0
                        ? cfg.notify_channels.map(ch => (
                          <span key={ch} className="text-[9px] rounded-full px-2 py-0.5 bg-border text-muted">{ch}</span>
                        ))
                        : <span className="text-[10px] text-muted">none</span>
                      }
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Notification channels info */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs text-muted">Supported Notification Channels</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-3">
            {[
              { name: 'Slack', desc: 'Approval buttons in channel', status: 'supported' },
              { name: 'Email', desc: 'Magic link approvals', status: 'supported' },
              { name: 'PagerDuty', desc: 'Escalation routing', status: 'supported' },
              { name: 'Webhook', desc: 'Custom HTTP endpoint', status: 'supported' },
            ].map(ch => (
              <div key={ch.name} className="rounded-lg border border-border p-3 text-center">
                <div className="text-xs font-medium text-text">{ch.name}</div>
                <div className="text-[10px] text-muted mt-0.5">{ch.desc}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-text">Integrations</h1>
          <p className="text-sm text-muted mt-1">
            Manage SIEM connections, webhooks, and notification channels.
          </p>
        </div>

        <Tabs defaultValue="siem">
          <TabsList>
            <TabsTrigger value="siem">
              <Server className="h-3.5 w-3.5 mr-1.5" /> SIEM Connections
            </TabsTrigger>
            <TabsTrigger value="webhooks">
              <Webhook className="h-3.5 w-3.5 mr-1.5" /> Webhooks & Joti
            </TabsTrigger>
            <TabsTrigger value="notifications">
              <Bell className="h-3.5 w-3.5 mr-1.5" /> HITL & Notifications
            </TabsTrigger>
          </TabsList>

          <TabsContent value="siem" className="mt-4">
            <SIEMTab showToast={showToast} />
          </TabsContent>
          <TabsContent value="webhooks" className="mt-4">
            <WebhooksTab showToast={showToast} />
          </TabsContent>
          <TabsContent value="notifications" className="mt-4">
            <NotificationsTab showToast={showToast} />
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}
