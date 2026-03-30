'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle2, XCircle, Loader2, Shield, Key, Users, ScrollText,
  RefreshCw, Copy, Eye, EyeOff, AlertTriangle, Lock,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { authFetch } from '@/lib/auth'

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

// ─── Auth & Profile Tab ───────────────────────────────────────────────────────

function AuthTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [me, setMe] = useState<any>(null)
  const [passwords, setPasswords] = useState({ current: '', new_password: '', confirm: '' })
  const [changing, setChanging] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)
  const [apiKey, setApiKey] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)

  useEffect(() => {
    authFetch('/api/v2/auth/me').then(r => r.json()).then(setMe).catch(() => {})
  }, [])

  async function handleChangePassword() {
    if (passwords.new_password !== passwords.confirm) {
      showToast('error', 'Passwords do not match')
      return
    }
    if (passwords.new_password.length < 8) {
      showToast('error', 'Password must be at least 8 characters')
      return
    }
    setChanging(true)
    try {
      const res = await authFetch('/api/v2/auth/me', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: passwords.current, new_password: passwords.new_password }),
      })
      if (res.ok) {
        showToast('success', 'Password changed successfully')
        setPasswords({ current: '', new_password: '', confirm: '' })
      } else {
        const err = await res.json()
        showToast('error', err.detail ?? 'Failed to change password')
      }
    } catch {
      showToast('error', 'Failed to change password')
    }
    setChanging(false)
  }

  async function handleRotateApiKey() {
    if (!confirm('Generate a new API key? The old key will stop working immediately.')) return
    setRotating(true)
    try {
      const res = await authFetch('/api/v2/auth/api-key/rotate', { method: 'POST' })
      const data = await res.json()
      setApiKey(data.api_key)
      setShowApiKey(true)
      showToast('success', 'New API key generated. Copy it now — it won\'t be shown again.')
    } catch {
      showToast('error', 'Failed to generate API key')
    }
    setRotating(false)
  }

  return (
    <div className="space-y-4">
      {/* Profile info */}
      {me && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" /> Account
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Email', value: me.email },
                { label: 'Role', value: me.role },
                { label: 'Superadmin', value: me.is_superadmin ? 'Yes' : 'No' },
                { label: 'Last Login', value: me.last_login_at ? new Date(me.last_login_at).toLocaleDateString() : 'Never' },
              ].map(item => (
                <div key={item.label} className="rounded-lg border border-border p-3">
                  <div className="text-[10px] text-muted uppercase tracking-wider">{item.label}</div>
                  <div className="text-xs font-medium text-text mt-1">{item.value}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Change password */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Lock className="h-4 w-4 text-muted" /> Change Password
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider">Current Password</label>
              <Input type="password" value={passwords.current}
                onChange={e => setPasswords(p => ({ ...p, current: e.target.value }))}
                className="h-8 text-xs mt-1" />
            </div>
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider">New Password</label>
              <Input type="password" value={passwords.new_password}
                onChange={e => setPasswords(p => ({ ...p, new_password: e.target.value }))}
                className="h-8 text-xs mt-1" />
            </div>
            <div>
              <label className="text-[10px] text-muted uppercase tracking-wider">Confirm</label>
              <Input type="password" value={passwords.confirm}
                onChange={e => setPasswords(p => ({ ...p, confirm: e.target.value }))}
                className="h-8 text-xs mt-1" />
            </div>
          </div>
          <Button size="sm" onClick={handleChangePassword}
            disabled={changing || !passwords.current || !passwords.new_password}>
            {changing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Lock className="h-3 w-3" />}
            Update Password
          </Button>
        </CardContent>
      </Card>

      {/* API Key */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Key className="h-4 w-4 text-muted" /> API Key
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted">
            Use your API key to authenticate programmatic requests. Include it as a <code className="bg-border/50 px-1 rounded">Bearer</code> token.
          </p>
          {me?.api_key_hint && (
            <div className="text-xs text-muted">Current key ends with: <span className="font-mono text-text">...{me.api_key_hint}</span></div>
          )}
          {apiKey && (
            <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-[10px] text-amber-400 font-medium mb-1">Copy this key now — it won't be shown again</div>
                <div className="flex items-center gap-2">
                  <code className={cn('text-xs font-mono flex-1 truncate', showApiKey ? 'text-text' : 'text-muted')}>
                    {showApiKey ? apiKey : '••••••••••••••••••••••••'}
                  </code>
                  <button onClick={() => setShowApiKey(!showApiKey)} className="text-muted hover:text-text">
                    {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                  </button>
                  <button onClick={() => { navigator.clipboard.writeText(apiKey); showToast('success', 'Copied!') }}
                    className="text-muted hover:text-text">
                    <Copy className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          )}
          <Button size="sm" variant="ghost" onClick={handleRotateApiKey} disabled={rotating}>
            {rotating ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            Generate New API Key
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Audit Log Tab ────────────────────────────────────────────────────────────

interface AuditEntry {
  id: string
  user_id: string
  user_email: string
  action: string
  ip_address: string
  created_at: string
  details: string | null
}

function AuditLogTab() {
  const [logs, setLogs] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filter, setFilter] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(page), page_size: '25' })
      if (filter) params.set('action', filter)
      const res = await authFetch(`/api/v2/admin/audit-log?${params}`)
      if (res.ok) {
        const data = await res.json()
        setLogs(data.logs ?? data.entries ?? [])
        setTotal(data.total ?? 0)
      }
    } catch { /* ignore — user might not be admin */ }
    setLoading(false)
  }, [page, filter])

  useEffect(() => { void load() }, [load])

  const actionColors: Record<string, string> = {
    login: 'text-green',
    logout: 'text-muted',
    register: 'text-blue',
    update_profile: 'text-amber-400',
    rotate_api_key: 'text-red',
    change_role: 'text-purple-400',
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">
          Authentication and authorization audit trail. Requires admin role.
        </p>
        <div className="flex gap-2">
          <Input value={filter} onChange={e => { setFilter(e.target.value); setPage(1) }}
            placeholder="Filter by action..." className="h-8 text-xs w-48" />
          <Button size="sm" variant="ghost" onClick={load}><RefreshCw className="h-3.5 w-3.5" /></Button>
        </div>
      </div>

      {loading ? (
        <div className="space-y-1">{[...Array(8)].map((_, i) => <div key={i} className="animate-pulse h-10 rounded bg-border/40" />)}</div>
      ) : logs.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center">
            <ScrollText className="h-8 w-8 text-muted mx-auto mb-2" />
            <p className="text-sm text-muted">No audit logs found.</p>
            <p className="text-xs text-muted mt-1">Audit logs require admin access. Logs appear after user authentication events.</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-xl border border-border overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-card/50">
                  <th className="text-left text-[10px] text-muted uppercase tracking-wider px-4 py-2">Time</th>
                  <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2">User</th>
                  <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2">Action</th>
                  <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2">IP Address</th>
                  <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2">Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id} className="border-b border-border last:border-0 hover:bg-card/30">
                    <td className="px-4 py-2 text-[11px] text-muted font-mono whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="px-3 py-2 text-xs text-text truncate max-w-[180px]">{log.user_email}</td>
                    <td className="px-3 py-2">
                      <span className={cn('text-xs font-mono font-medium', actionColors[log.action] ?? 'text-text')}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-[11px] text-muted font-mono">{log.ip_address || '—'}</td>
                    <td className="px-3 py-2 text-[10px] text-muted truncate max-w-[200px]">{log.details || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted">{total} total entries</span>
            <div className="flex gap-1">
              <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Prev</Button>
              <span className="text-xs text-muted flex items-center px-2">Page {page}</span>
              <Button size="sm" variant="ghost" disabled={logs.length < 25} onClick={() => setPage(p => p + 1)}>Next</Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Users & RBAC Tab ─────────────────────────────────────────────────────────

function UsersTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [users, setUsers] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [total, setTotal] = useState(0)

  useEffect(() => {
    authFetch('/api/v2/admin/users?page=1&page_size=50')
      .then(r => r.json())
      .then(data => { setUsers(data.users ?? []); setTotal(data.total ?? 0) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const roles = ['viewer', 'analyst', 'engineer', 'admin']
  const roleColors: Record<string, string> = {
    viewer: 'text-muted',
    analyst: 'text-blue',
    engineer: 'text-amber-400',
    admin: 'text-red',
  }

  async function handleRoleChange(userId: string, role: string) {
    try {
      const res = await authFetch(`/api/v2/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role }),
      })
      if (res.ok) {
        setUsers(prev => prev.map(u => u.id === userId ? { ...u, role } : u))
        showToast('success', 'Role updated')
      } else {
        showToast('error', 'Failed to update role')
      }
    } catch {
      showToast('error', 'Failed to update role')
    }
  }

  async function handleToggleActive(userId: string, active: boolean) {
    const endpoint = active ? 'activate' : 'deactivate'
    try {
      const res = await authFetch(`/api/v2/admin/users/${userId}/${endpoint}`, { method: 'POST' })
      if (res.ok) {
        setUsers(prev => prev.map(u => u.id === userId ? { ...u, is_active: active } : u))
        showToast('success', `User ${active ? 'activated' : 'deactivated'}`)
      }
    } catch {
      showToast('error', 'Failed to update user')
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">Manage user accounts and role-based access control. Requires admin role.</p>
        <span className="text-xs text-muted">{total} users</span>
      </div>

      {/* RBAC info */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { role: 'Viewer', desc: 'Read-only access to dashboards and reports', color: 'border-border' },
          { role: 'Analyst', desc: 'Create rules, run sessions, manage threat intel', color: 'border-blue/30' },
          { role: 'Engineer', desc: 'Full CRUD, SIEM integrations, pipeline management', color: 'border-amber-400/30' },
          { role: 'Admin', desc: 'User management, audit logs, system configuration', color: 'border-red/30' },
        ].map(r => (
          <div key={r.role} className={cn('rounded-lg border p-2.5', r.color)}>
            <div className="text-xs font-medium text-text">{r.role}</div>
            <div className="text-[10px] text-muted mt-0.5">{r.desc}</div>
          </div>
        ))}
      </div>

      {/* Users table */}
      {loading ? (
        <div className="space-y-1">{[...Array(5)].map((_, i) => <div key={i} className="animate-pulse h-12 rounded bg-border/40" />)}</div>
      ) : users.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center">
            <Users className="h-8 w-8 text-muted mx-auto mb-2" />
            <p className="text-sm text-muted">No users found or insufficient permissions.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-card/50">
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-4 py-2">User</th>
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2 w-[140px]">Role</th>
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2 w-[80px]">Status</th>
                <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2">Last Login</th>
                <th className="text-right text-[10px] text-muted uppercase tracking-wider px-4 py-2 w-[80px]">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className="border-b border-border last:border-0">
                  <td className="px-4 py-2.5">
                    <div className="text-xs font-medium text-text">{u.full_name || u.email}</div>
                    <div className="text-[10px] text-muted">{u.email}</div>
                  </td>
                  <td className="px-3 py-2.5">
                    <select value={u.role} onChange={e => handleRoleChange(u.id, e.target.value)}
                      className={cn('h-6 rounded border border-border bg-bg px-1.5 text-[11px]', roleColors[u.role])}>
                      {roles.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td className="px-3 py-2.5">
                    <span className={cn('text-[10px] rounded-full px-2 py-0.5 border',
                      u.is_active ? 'border-green/30 bg-green/10 text-green' : 'border-red/30 bg-red/10 text-red'
                    )}>{u.is_active ? 'active' : 'disabled'}</span>
                  </td>
                  <td className="px-3 py-2.5 text-[11px] text-muted">
                    {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : 'Never'}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]"
                      onClick={() => handleToggleActive(u.id, !u.is_active)}>
                      {u.is_active ? 'Disable' : 'Enable'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SecurityPage() {
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
          <h1 className="text-xl font-bold text-text">Security</h1>
          <p className="text-sm text-muted mt-1">
            Manage authentication, API keys, user access, and audit logs.
          </p>
        </div>

        <Tabs defaultValue="auth">
          <TabsList>
            <TabsTrigger value="auth">
              <Key className="h-3.5 w-3.5 mr-1.5" /> Auth & API Keys
            </TabsTrigger>
            <TabsTrigger value="users">
              <Users className="h-3.5 w-3.5 mr-1.5" /> Users & RBAC
            </TabsTrigger>
            <TabsTrigger value="audit">
              <ScrollText className="h-3.5 w-3.5 mr-1.5" /> Audit Log
            </TabsTrigger>
          </TabsList>

          <TabsContent value="auth" className="mt-4">
            <AuthTab showToast={showToast} />
          </TabsContent>
          <TabsContent value="users" className="mt-4">
            <UsersTab showToast={showToast} />
          </TabsContent>
          <TabsContent value="audit" className="mt-4">
            <AuditLogTab />
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}
