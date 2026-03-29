'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Users,
  ClipboardList,
  BarChart3,
  Search,
  Trash2,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Megaphone,
  X,
  AlertCircle,
  Info,
  AlertTriangle,
  CheckCircle2,
  UserCog,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import { useAuthStore } from '../../stores/auth'
import { cn } from '@/lib/utils'

// ─── Types ─────────────────────────────────────────────────────────────────────

type Role = 'admin' | 'engineer' | 'analyst' | 'viewer'

interface AdminUser {
  id: string
  email: string
  full_name: string
  role: Role
  is_active: boolean
  created_at: string
}

interface AuditEntry {
  id: string
  timestamp: string
  user_email: string
  action: string
  details: string
  ip_address: string
}

interface AuditResponse {
  items: AuditEntry[]
  total: number
  page: number
  per_page: number
}

interface PlatformStats {
  total_users: number
  active_users: number
  sessions_today: number
  use_cases_passing: number
  total_rules: number
  llm_calls_today: number
}

interface Broadcast {
  id: string
  message: string
  type: 'info' | 'warning' | 'error'
  active: boolean
  created_at: string
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function shortDate(iso: string) {
  try {
    return new Date(iso).toLocaleDateString()
  } catch {
    return iso
  }
}

// ─── Role badge ────────────────────────────────────────────────────────────────

const ROLE_COLORS: Record<Role, string> = {
  admin:    'bg-violet-500/15 text-violet-400 border-violet-500/30',
  engineer: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  analyst:  'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  viewer:   'bg-slate-500/15 text-slate-400 border-slate-500/30',
}

function RoleBadge({ role }: { role: Role }) {
  return (
    <span className={cn('inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold capitalize', ROLE_COLORS[role] ?? ROLE_COLORS.viewer)}>
      {role}
    </span>
  )
}

// ─── Avatar ────────────────────────────────────────────────────────────────────

function Avatar({ name, email }: { name: string; email: string }) {
  const letter = (name || email)[0]?.toUpperCase() ?? '?'
  return (
    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-bold">
      {letter}
    </div>
  )
}

// ─── Skeleton ──────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── Toggle switch ─────────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200',
        checked ? 'bg-primary' : 'bg-border'
      )}
    >
      <span
        className={cn(
          'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform duration-200',
          checked ? 'translate-x-4' : 'translate-x-0'
        )}
      />
    </button>
  )
}

// ─── Confirm modal ─────────────────────────────────────────────────────────────

function ConfirmModal({
  open,
  title,
  message,
  onConfirm,
  onCancel,
}: {
  open: boolean
  title: string
  message: string
  onConfirm: () => void
  onCancel: () => void
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-border bg-card p-6 shadow-2xl">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-destructive/15">
            <AlertCircle className="h-4 w-4 text-destructive" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-text">{title}</h3>
            <p className="mt-1 text-xs text-muted">{message}</p>
          </div>
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button size="sm" onClick={onCancel}>
            Cancel
          </Button>
          <Button variant="destructive" size="sm" onClick={onConfirm}>
            Delete
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Tab button ────────────────────────────────────────────────────────────────

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  label: string
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors',
        active
          ? 'bg-primary/10 text-primary'
          : 'text-muted hover:text-text hover:bg-bg'
      )}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  )
}

// ─── KPI stat card ─────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon }: { label: string; value: number | string; icon: React.ElementType }) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs font-medium text-muted uppercase tracking-wide">{label}</p>
            <p className="mt-1.5 text-3xl font-bold text-text">{value}</p>
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-border/50">
            <Icon className="h-4 w-4 text-muted" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

// ─── Tab 1: Users ──────────────────────────────────────────────────────────────

function UsersTab() {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null)
  const [savingRole, setSavingRole] = useState<string | null>(null)
  const [savingActive, setSavingActive] = useState<string | null>(null)

  const fetchUsers = useCallback(async () => {
    setLoading(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/admin/users`)
      if (res.ok) {
        const data = (await res.json()) as AdminUser[]
        setUsers(data)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void fetchUsers() }, [fetchUsers])

  const handleRoleChange = async (userId: string, newRole: Role) => {
    setSavingRole(userId)
    try {
      await authFetch(`${API_BASE}/api/v2/admin/users/${userId}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      })
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole } : u))
    } catch {
      // ignore
    } finally {
      setSavingRole(null)
    }
  }

  const handleActiveToggle = async (userId: string, active: boolean) => {
    setSavingActive(userId)
    try {
      await authFetch(`${API_BASE}/api/v2/admin/users/${userId}/active`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: active }),
      })
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, is_active: active } : u))
    } catch {
      // ignore
    } finally {
      setSavingActive(null)
    }
  }

  const handleDelete = async (userId: string) => {
    try {
      await authFetch(`${API_BASE}/api/v2/admin/users/${userId}`, { method: 'DELETE' })
      setUsers(prev => prev.filter(u => u.id !== userId))
    } catch {
      // ignore
    } finally {
      setDeleteTarget(null)
    }
  }

  const filtered = users.filter(u =>
    u.full_name.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  )

  const ROLES: Role[] = ['admin', 'engineer', 'analyst', 'viewer']

  return (
    <>
      <ConfirmModal
        open={deleteTarget !== null}
        title="Delete user"
        message={`Are you sure you want to delete ${deleteTarget?.full_name || deleteTarget?.email}? This cannot be undone.`}
        onConfirm={() => deleteTarget && void handleDelete(deleteTarget.id)}
        onCancel={() => setDeleteTarget(null)}
      />

      <div className="mb-4 flex items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search by name or email..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="h-9 w-full rounded-lg border border-border bg-bg pl-9 pr-3 text-sm text-text placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <Button size="sm" onClick={() => void fetchUsers()} disabled={loading}>
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-14" />)}
        </div>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-bg/50">
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">User</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Email</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Role</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Created</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-muted uppercase tracking-wide">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-muted">
                    {search ? 'No users match your search.' : 'No users found.'}
                  </td>
                </tr>
              ) : (
                filtered.map(user => (
                  <tr key={user.id} className="bg-card hover:bg-bg/50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2.5">
                        <Avatar name={user.full_name} email={user.email} />
                        <span className="text-sm font-medium text-text">{user.full_name || '—'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted">{user.email}</td>
                    <td className="px-4 py-3">
                      <select
                        value={user.role}
                        disabled={savingRole === user.id}
                        onChange={e => void handleRoleChange(user.id, e.target.value as Role)}
                        className={cn(
                          'rounded-md border px-2 py-0.5 text-[11px] font-semibold capitalize cursor-pointer bg-card focus:outline-none focus:ring-1 focus:ring-primary transition-opacity',
                          ROLE_COLORS[user.role] ?? ROLE_COLORS.viewer,
                          savingRole === user.id && 'opacity-50 cursor-not-allowed'
                        )}
                      >
                        {ROLES.map(r => (
                          <option key={r} value={r} className="text-text bg-card">{r}</option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Toggle
                          checked={user.is_active}
                          onChange={v => !savingActive && void handleActiveToggle(user.id, v)}
                        />
                        <span className={cn('text-xs', user.is_active ? 'text-emerald-400' : 'text-muted')}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted">{shortDate(user.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setDeleteTarget(user)}
                        className="inline-flex items-center justify-center h-7 w-7 rounded-lg text-muted hover:text-destructive hover:bg-destructive/10 transition-colors"
                        title="Delete user"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

// ─── Tab 2: Audit Log ──────────────────────────────────────────────────────────

type DateRange = 'today' | '7d' | '30d' | 'all'

function AuditTab() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [userSearch, setUserSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [dateRange, setDateRange] = useState<DateRange>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const PER_PAGE = 50

  const fetchAudit = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const params = new URLSearchParams({
        page: String(page),
        per_page: String(PER_PAGE),
      })
      if (userSearch) params.set('user', userSearch)
      if (actionFilter) params.set('action', actionFilter)
      if (dateRange !== 'all') params.set('date_range', dateRange)

      const res = await authFetch(`${API_BASE}/api/v2/admin/audit-log?${params.toString()}`)
      if (res.ok) {
        const data = (await res.json()) as AuditResponse
        setEntries(data.items ?? [])
        setTotal(data.total ?? 0)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [page, userSearch, actionFilter, dateRange])

  useEffect(() => { void fetchAudit() }, [fetchAudit])

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(() => void fetchAudit(true), 30_000)
    return () => clearInterval(interval)
  }, [fetchAudit])

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  const ACTION_OPTIONS = [
    '', 'login', 'logout', 'create_user', 'delete_user', 'update_role',
    'start_session', 'stop_session', 'generate_events', 'broadcast',
  ]

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Filter by user..."
            value={userSearch}
            onChange={e => { setUserSearch(e.target.value); setPage(1) }}
            className="h-9 w-48 rounded-lg border border-border bg-bg pl-9 pr-3 text-sm text-text placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>

        <select
          value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1) }}
          className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">All actions</option>
          {ACTION_OPTIONS.filter(Boolean).map(a => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>

        <div className="flex items-center rounded-lg border border-border overflow-hidden">
          {(['today', '7d', '30d', 'all'] as DateRange[]).map(d => (
            <button
              key={d}
              onClick={() => { setDateRange(d); setPage(1) }}
              className={cn(
                'px-3 py-1.5 text-xs font-medium transition-colors',
                dateRange === d
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted hover:text-text hover:bg-bg'
              )}
            >
              {d === 'today' ? 'Today' : d === 'all' ? 'All time' : `Last ${d}`}
            </button>
          ))}
        </div>

        <Button size="sm" onClick={() => void fetchAudit()} disabled={loading}>
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* Table */}
      {loading ? (
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-12" />)}
        </div>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-bg/50">
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Timestamp</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">User</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Action</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">Details</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wide">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-sm text-muted">No audit entries found.</td>
                </tr>
              ) : (
                entries.map(entry => (
                  <>
                    <tr
                      key={entry.id}
                      className="bg-card hover:bg-bg/50 transition-colors cursor-pointer"
                      onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                    >
                      <td className="px-4 py-2.5 text-xs text-muted whitespace-nowrap">{formatDate(entry.timestamp)}</td>
                      <td className="px-4 py-2.5 text-xs text-text">{entry.user_email}</td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center rounded-md bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">
                          {entry.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted max-w-[280px]">
                        <span className="truncate block">{entry.details}</span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted font-mono">{entry.ip_address}</td>
                    </tr>
                    {expandedId === entry.id && (
                      <tr key={`${entry.id}-expanded`} className="bg-bg/80">
                        <td colSpan={5} className="px-4 py-3">
                          <p className="text-xs text-text font-medium mb-1">Full details:</p>
                          <p className="text-xs text-muted break-all">{entry.details}</p>
                        </td>
                      </tr>
                    )}
                  </>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs text-muted">
        <span>
          {total === 0 ? 'No results' : `${((page - 1) * PER_PAGE) + 1}–${Math.min(page * PER_PAGE, total)} of ${total}`}
        </span>
        <div className="flex items-center gap-1">
          <Button
           
            size="sm"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page <= 1 || loading}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            Prev
          </Button>
          <span className="px-2">Page {page} of {totalPages}</span>
          <Button
           
            size="sm"
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || loading}
          >
            Next
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Tab 3: Platform Stats ─────────────────────────────────────────────────────

function StatsTab() {
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [broadcast, setBroadcast] = useState<Broadcast | null>(null)
  const [broadcastMsg, setBroadcastMsg] = useState('')
  const [broadcastType, setBroadcastType] = useState<'info' | 'warning' | 'error'>('info')
  const [sending, setSending] = useState(false)
  const [sendSuccess, setSendSuccess] = useState(false)

  const fetchStats = useCallback(async () => {
    setLoading(true)
    try {
      const [statsRes, broadcastRes] = await Promise.all([
        authFetch(`${API_BASE}/api/v2/admin/stats`),
        authFetch(`${API_BASE}/api/v2/admin/broadcast`),
      ])
      if (statsRes.ok) setStats((await statsRes.json()) as PlatformStats)
      if (broadcastRes.ok) {
        const bc = (await broadcastRes.json()) as Broadcast | null
        setBroadcast(bc?.active ? bc : null)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void fetchStats() }, [fetchStats])

  const handleSendBroadcast = async () => {
    if (!broadcastMsg.trim()) return
    setSending(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/admin/broadcast`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: broadcastMsg.trim(), type: broadcastType }),
      })
      if (res.ok) {
        const bc = (await res.json()) as Broadcast
        setBroadcast(bc)
        setBroadcastMsg('')
        setSendSuccess(true)
        setTimeout(() => setSendSuccess(false), 3000)
      }
    } catch {
      // ignore
    } finally {
      setSending(false)
    }
  }

  const handleDismissBroadcast = async () => {
    try {
      await authFetch(`${API_BASE}/api/v2/admin/broadcast`, { method: 'DELETE' })
      setBroadcast(null)
    } catch {
      // ignore
    }
  }

  const BROADCAST_TYPE_STYLES: Record<string, string> = {
    info:    'bg-blue-500/10 border-blue-500/30 text-blue-300',
    warning: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
    error:   'bg-red-500/10 border-red-500/30 text-red-300',
  }

  const BroadcastIcon = broadcastType === 'info' ? Info : broadcastType === 'warning' ? AlertTriangle : AlertCircle

  return (
    <div className="space-y-6">
      {/* KPI grid */}
      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <StatCard label="Total Users" value={stats.total_users} icon={Users} />
          <StatCard label="Active Users" value={stats.active_users} icon={CheckCircle2} />
          <StatCard label="Sessions Today" value={stats.sessions_today} icon={BarChart3} />
          <StatCard label="Use Cases Passing" value={stats.use_cases_passing} icon={ClipboardList} />
          <StatCard label="Total Rules" value={stats.total_rules} icon={ShieldAlert} />
          <StatCard label="LLM Calls Today" value={stats.llm_calls_today} icon={UserCog} />
        </div>
      ) : (
        <p className="text-sm text-muted">Stats unavailable.</p>
      )}

      {/* Active broadcast banner */}
      {broadcast && (
        <div className={cn('flex items-start gap-3 rounded-xl border p-4', BROADCAST_TYPE_STYLES[broadcast.type] ?? BROADCAST_TYPE_STYLES.info)}>
          {broadcast.type === 'info' && <Info className="h-4 w-4 mt-0.5 shrink-0" />}
          {broadcast.type === 'warning' && <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />}
          {broadcast.type === 'error' && <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />}
          <div className="flex-1">
            <p className="text-xs font-semibold uppercase tracking-wide opacity-70 mb-0.5">Active Broadcast</p>
            <p className="text-sm">{broadcast.message}</p>
          </div>
          <button
            onClick={() => void handleDismissBroadcast()}
            className="mt-0.5 opacity-60 hover:opacity-100 transition-opacity"
            title="Dismiss broadcast"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Broadcast form */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Megaphone className="h-4 w-4 text-muted" />
            System Broadcast
          </CardTitle>
          <p className="text-xs text-muted">Send an announcement to all users currently on the platform.</p>
        </CardHeader>
        <CardContent className="space-y-3">
          <textarea
            value={broadcastMsg}
            onChange={e => setBroadcastMsg(e.target.value)}
            placeholder="Enter broadcast message..."
            rows={3}
            className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary resize-none"
          />
          <div className="flex items-center gap-3">
            <select
              value={broadcastType}
              onChange={e => setBroadcastType(e.target.value as 'info' | 'warning' | 'error')}
              className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="error">Error</option>
            </select>

            <div className={cn(
              'flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs flex-1',
              BROADCAST_TYPE_STYLES[broadcastType] ?? BROADCAST_TYPE_STYLES.info
            )}>
              <BroadcastIcon className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{broadcastMsg || 'Preview will appear here...'}</span>
            </div>

            <Button
              size="sm"
              onClick={() => void handleSendBroadcast()}
              disabled={!broadcastMsg.trim() || sending}
              className="shrink-0"
            >
              {sending ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : sendSuccess ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Megaphone className="h-3.5 w-3.5" />
              )}
              {sendSuccess ? 'Sent!' : 'Send Announcement'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Access Denied ─────────────────────────────────────────────────────────────

function AccessDenied() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardContent className="flex flex-col items-center gap-4 p-8">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-destructive/15">
            <ShieldAlert className="h-7 w-7 text-destructive" />
          </div>
          <div className="text-center">
            <h2 className="text-base font-semibold text-text">Access Denied</h2>
            <p className="mt-1 text-sm text-muted">
              You do not have permission to view this page. Admin role is required.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Admin page ────────────────────────────────────────────────────────────────

type Tab = 'users' | 'audit' | 'stats'

export default function AdminPage() {
  const user = useAuthStore((s) => s.user)
  const [activeTab, setActiveTab] = useState<Tab>('users')

  if (user?.role !== 'admin') {
    return <AccessDenied />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Admin</h1>
          <p className="text-xs text-muted mt-0.5">Manage users, review audit logs, and monitor platform health</p>
        </div>
        <Badge variant="default" className="bg-violet-500/15 text-violet-400 border-violet-500/30 text-xs">
          Admin Panel
        </Badge>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 rounded-xl border border-border bg-card p-1.5 w-fit">
        <TabButton active={activeTab === 'users'} onClick={() => setActiveTab('users')} icon={Users} label="Users" />
        <TabButton active={activeTab === 'audit'} onClick={() => setActiveTab('audit')} icon={ClipboardList} label="Audit Log" />
        <TabButton active={activeTab === 'stats'} onClick={() => setActiveTab('stats')} icon={BarChart3} label="Platform Stats" />
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'users' && <UsersTab />}
        {activeTab === 'audit' && <AuditTab />}
        {activeTab === 'stats' && <StatsTab />}
      </div>
    </div>
  )
}
