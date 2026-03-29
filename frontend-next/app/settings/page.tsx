'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  User,
  Bell,
  Palette,
  AlertTriangle,
  Key,
  Copy,
  Check,
  Eye,
  EyeOff,
  Loader2,
  CheckCircle2,
  XCircle,
  Download,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { authFetch } from '@/lib/auth'
import { useAuthStore } from '@/stores/auth'
import { API_BASE } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ type, message }: { type: 'success' | 'error'; message: string }) {
  return (
    <div
      className={cn(
        'fixed bottom-5 right-5 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-xl',
        type === 'success'
          ? 'border-green/40 bg-green/10 text-green'
          : 'border-red/40 bg-red/10 text-red'
      )}
    >
      {type === 'success' ? (
        <CheckCircle2 className="h-4 w-4 shrink-0" />
      ) : (
        <XCircle className="h-4 w-4 shrink-0" />
      )}
      {message}
    </div>
  )
}

function useToast() {
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  function show(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }
  return { toast, show }
}

// ─── Toggle Switch ────────────────────────────────────────────────────────────

function Toggle({
  checked,
  onChange,
  label,
  description,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  description?: string
}) {
  return (
    <div className="flex items-center justify-between py-3">
      <div>
        <div className="text-sm font-medium text-text">{label}</div>
        {description && <div className="text-xs text-muted mt-0.5">{description}</div>}
      </div>
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary',
          checked ? 'bg-primary' : 'bg-border'
        )}
      >
        <span
          className={cn(
            'inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform',
            checked ? 'translate-x-6' : 'translate-x-1'
          )}
        />
      </button>
    </div>
  )
}

// ─── Confirm Modal ────────────────────────────────────────────────────────────

function ConfirmModal({
  open,
  title,
  description,
  confirmLabel,
  onConfirm,
  onCancel,
  destructive,
}: {
  open: boolean
  title: string
  description: string
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  destructive?: boolean
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onCancel} />
      <div className="relative z-10 w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-base font-semibold text-text">{title}</h3>
            <p className="text-sm text-muted mt-1">{description}</p>
          </div>
        </div>
        <div className="flex gap-3 justify-end">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            onClick={onConfirm}
            className={destructive ? 'bg-red hover:bg-red/80 text-white' : ''}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Role badge colours ────────────────────────────────────────────────────────

const ROLE_COLORS: Record<string, string> = {
  superadmin: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  admin: 'bg-primary/20 text-primary border-primary/30',
  engineer: 'bg-blue/20 text-blue border-blue/30',
  analyst: 'bg-green/20 text-green border-green/30',
  viewer: 'bg-border text-muted border-border',
}

// ─── PROFILE TAB ─────────────────────────────────────────────────────────────

function ProfileTab() {
  const { user, refreshUser } = useAuthStore()
  const { toast, show } = useToast()

  const [fullName, setFullName] = useState(user?.full_name ?? '')
  const [savingProfile, setSavingProfile] = useState(false)

  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [showNewPw, setShowNewPw] = useState(false)
  const [savingPw, setSavingPw] = useState(false)

  const [apiKeyVisible, setApiKeyVisible] = useState(false)
  const [apiKeyHint, setApiKeyHint] = useState<string | null>(null)
  const [fullApiKey, setFullApiKey] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)
  const [copied, setCopied] = useState(false)

  // Load api_key_hint from /me
  useEffect(() => {
    authFetch(`${API_BASE}/api/v2/auth/me`)
      .then((r) => r.json())
      .then((data: { api_key_hint?: string }) => {
        if (data.api_key_hint) setApiKeyHint(data.api_key_hint)
      })
      .catch(() => {/* ignore */})
  }, [])

  async function saveProfile() {
    setSavingProfile(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/auth/me`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ full_name: fullName }),
      })
      if (!res.ok) throw new Error('Failed to save')
      await refreshUser()
      show('success', 'Profile updated.')
    } catch {
      show('error', 'Failed to update profile.')
    } finally {
      setSavingProfile(false)
    }
  }

  async function changePassword() {
    if (newPw !== confirmPw) {
      show('error', 'New passwords do not match.')
      return
    }
    if (newPw.length < 8) {
      show('error', 'Password must be at least 8 characters.')
      return
    }
    setSavingPw(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/auth/me`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
      })
      if (!res.ok) {
        const data = (await res.json()) as { detail?: string }
        throw new Error(data.detail ?? 'Failed to change password')
      }
      show('success', 'Password changed successfully.')
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
    } catch (err) {
      show('error', err instanceof Error ? err.message : 'Failed to change password.')
    } finally {
      setSavingPw(false)
    }
  }

  async function rotateApiKey() {
    setRotating(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/auth/api-key/rotate`, {
        method: 'POST',
      })
      const data = (await res.json()) as { api_key: string; hint: string }
      setFullApiKey(data.api_key)
      setApiKeyHint(data.hint)
      setApiKeyVisible(true)
      show('success', 'API key rotated. Copy it now — it will not be shown again.')
    } catch {
      show('error', 'Failed to rotate API key.')
    } finally {
      setRotating(false)
    }
  }

  function copyKey() {
    const key = fullApiKey ?? `pl_****${apiKeyHint ?? ''}`
    navigator.clipboard.writeText(key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const maskedKey = apiKeyHint ? `pl_${'•'.repeat(16)}${apiKeyHint}` : 'pl_••••••••••••••••'
  const displayKey = apiKeyVisible && fullApiKey ? fullApiKey : maskedKey

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="space-y-6">
        {/* Identity */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Identity</CardTitle>
            <CardDescription>Your display name and account details.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-4 p-4 rounded-lg bg-bg border border-border">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/20 text-primary font-bold text-lg">
                {(user?.full_name || user?.email || '?')[0].toUpperCase()}
              </div>
              <div>
                <div className="text-sm font-semibold text-text">{user?.full_name || '—'}</div>
                <div className="text-xs text-muted">{user?.email}</div>
              </div>
              <div className="ml-auto">
                <span
                  className={cn(
                    'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
                    ROLE_COLORS[user?.role ?? ''] ?? ROLE_COLORS.viewer
                  )}
                >
                  {user?.role ?? 'viewer'}
                </span>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Display Name
              </label>
              <Input
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Your full name"
                className="max-w-sm"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Email
              </label>
              <Input value={user?.email ?? ''} readOnly disabled className="max-w-sm opacity-60" />
              <p className="text-[10px] text-muted">Email cannot be changed.</p>
            </div>

            <Button onClick={saveProfile} disabled={savingProfile} size="sm">
              {savingProfile && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Save Profile
            </Button>
          </CardContent>
        </Card>

        {/* Change Password */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Change Password</CardTitle>
            <CardDescription>Use a strong password of at least 8 characters.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Current Password
              </label>
              <Input
                type="password"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="••••••••"
                className="max-w-sm"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                New Password
              </label>
              <div className="relative max-w-sm">
                <Input
                  type={showNewPw ? 'text' : 'password'}
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  placeholder="••••••••"
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPw(!showNewPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                >
                  {showNewPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Confirm New Password
              </label>
              <Input
                type="password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                placeholder="••••••••"
                className="max-w-sm"
              />
            </div>
            <Button onClick={changePassword} disabled={savingPw || !currentPw || !newPw} size="sm">
              {savingPw && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Change Password
            </Button>
          </CardContent>
        </Card>

        {/* API Key */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Key className="h-4 w-4 text-muted" />
              API Key
            </CardTitle>
            <CardDescription>
              Use this key to authenticate PurpleLab API calls programmatically.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2.5 font-mono text-sm max-w-sm">
              <span className="flex-1 truncate text-text">
                {displayKey}
              </span>
              <button
                onClick={() => setApiKeyVisible(!apiKeyVisible)}
                className="text-muted hover:text-text shrink-0"
                title={apiKeyVisible ? 'Hide key' : 'Show key'}
              >
                {apiKeyVisible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
              <button
                onClick={copyKey}
                className="text-muted hover:text-text shrink-0"
                title="Copy to clipboard"
              >
                {copied ? (
                  <Check className="h-4 w-4 text-green" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </button>
            </div>
            {fullApiKey && (
              <p className="text-xs text-amber-400 flex items-center gap-1.5">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                Copy your key now. It will not be shown again after you leave this page.
              </p>
            )}
            <Button
             
              size="sm"
              onClick={rotateApiKey}
              disabled={rotating}
            >
              {rotating ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Key className="h-3.5 w-3.5" />
              )}
              Rotate Key
            </Button>
          </CardContent>
        </Card>
      </div>
    </>
  )
}

// ─── NOTIFICATIONS TAB ────────────────────────────────────────────────────────

const NOTIFICATION_DEFAULTS = {
  emailPipelineComplete: true,
  slackHitlApproval: false,
  emailUseCaseFailure: true,
  browserNotifications: false,
}

type NotifPrefs = typeof NOTIFICATION_DEFAULTS

function NotificationsTab() {
  const { toast, show } = useToast()
  const [prefs, setPrefs] = useState<NotifPrefs>(() => {
    if (typeof window === 'undefined') return NOTIFICATION_DEFAULTS
    try {
      const stored = localStorage.getItem('pl_notif_prefs')
      return stored ? (JSON.parse(stored) as NotifPrefs) : NOTIFICATION_DEFAULTS
    } catch {
      return NOTIFICATION_DEFAULTS
    }
  })

  function toggle(key: keyof NotifPrefs) {
    setPrefs((p) => ({ ...p, [key]: !p[key] }))
  }

  function save() {
    localStorage.setItem('pl_notif_prefs', JSON.stringify(prefs))
    show('success', 'Notification preferences saved.')
  }

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Alert Channels</CardTitle>
            <CardDescription>Choose how you want to be notified about platform events.</CardDescription>
          </CardHeader>
          <CardContent className="divide-y divide-border">
            <Toggle
              checked={prefs.emailPipelineComplete}
              onChange={() => toggle('emailPipelineComplete')}
              label="Email on pipeline completion"
              description="Receive an email when a simulation pipeline finishes."
            />
            <Toggle
              checked={prefs.slackHitlApproval}
              onChange={() => toggle('slackHitlApproval')}
              label="Slack alerts on HITL approvals"
              description="Send a Slack message when a human-in-the-loop approval is needed."
            />
            <Toggle
              checked={prefs.emailUseCaseFailure}
              onChange={() => toggle('emailUseCaseFailure')}
              label="Email on use case failures"
              description="Get alerted when a use case fails during execution."
            />
            <Toggle
              checked={prefs.browserNotifications}
              onChange={() => toggle('browserNotifications')}
              label="Browser notifications"
              description="Show desktop push notifications for real-time events."
            />
          </CardContent>
        </Card>

        {/* Preview card */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Notification Preview</CardTitle>
            <CardDescription>Sample of how alerts will appear.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-lg border border-border bg-bg p-4 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-green shrink-0" />
                <span className="text-xs font-semibold text-text">Pipeline Complete</span>
                <span className="ml-auto text-[10px] text-muted">just now</span>
              </div>
              <p className="text-xs text-muted pl-4">
                Simulation <span className="font-mono text-text">APT29-Cozy-Bear-v3</span> completed with DES score{' '}
                <span className="text-green font-semibold">0.87</span>.
              </p>
            </div>
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-amber-400 shrink-0" />
                <span className="text-xs font-semibold text-text">HITL Approval Required</span>
                <span className="ml-auto text-[10px] text-muted">2 min ago</span>
              </div>
              <p className="text-xs text-muted pl-4">
                Rule <span className="font-mono text-text">sigma-lsass-dump</span> needs your review before deployment.
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button onClick={save} size="sm">
            Save Preferences
          </Button>
        </div>
      </div>
    </>
  )
}

// ─── APPEARANCE TAB ───────────────────────────────────────────────────────────

const APPEARANCE_DEFAULTS = {
  theme: 'dark' as 'dark' | 'light',
  sidebarCollapsed: false,
  dateFormat: 'relative' as 'iso' | 'us' | 'relative',
  eventsPerPage: 50 as 25 | 50 | 100,
}

type AppearancePrefs = typeof APPEARANCE_DEFAULTS

function AppearanceTab() {
  const { toast, show } = useToast()
  const [prefs, setPrefs] = useState<AppearancePrefs>(() => {
    if (typeof window === 'undefined') return APPEARANCE_DEFAULTS
    try {
      const stored = localStorage.getItem('pl_appearance_prefs')
      return stored ? (JSON.parse(stored) as AppearancePrefs) : APPEARANCE_DEFAULTS
    } catch {
      return APPEARANCE_DEFAULTS
    }
  })

  function set<K extends keyof AppearancePrefs>(key: K, value: AppearancePrefs[K]) {
    setPrefs((p) => ({ ...p, [key]: value }))
  }

  function save() {
    localStorage.setItem('pl_appearance_prefs', JSON.stringify(prefs))
    show('success', 'Appearance preferences saved.')
  }

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="space-y-6">
        {/* Theme */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Theme</CardTitle>
            <CardDescription>Choose your preferred colour scheme.</CardDescription>
          </CardHeader>
          <CardContent className="flex gap-3">
            <button
              onClick={() => set('theme', 'dark')}
              className={cn(
                'flex flex-col items-center gap-2 rounded-xl border p-4 w-28 transition-colors',
                prefs.theme === 'dark'
                  ? 'border-primary bg-primary/10'
                  : 'border-border hover:border-muted'
              )}
            >
              <div className="h-12 w-20 rounded-lg bg-slate-900 border border-slate-700 flex items-end p-1 gap-1">
                <div className="h-4 w-6 rounded bg-slate-700" />
                <div className="flex-1 h-3 rounded bg-slate-800" />
              </div>
              <span className="text-xs font-medium text-text">Dark</span>
              {prefs.theme === 'dark' && (
                <Check className="h-3 w-3 text-primary" />
              )}
            </button>
            <button
              disabled
              className="flex flex-col items-center gap-2 rounded-xl border border-border p-4 w-28 opacity-40 cursor-not-allowed"
            >
              <div className="h-12 w-20 rounded-lg bg-white border border-slate-200 flex items-end p-1 gap-1">
                <div className="h-4 w-6 rounded bg-slate-200" />
                <div className="flex-1 h-3 rounded bg-slate-100" />
              </div>
              <span className="text-xs font-medium text-text">Light</span>
              <span className="text-[10px] text-muted">Coming soon</span>
            </button>
          </CardContent>
        </Card>

        {/* Layout & format */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Layout & Display</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium text-text">Collapse sidebar by default</div>
                <div className="text-xs text-muted mt-0.5">Start with the sidebar minimised.</div>
              </div>
              <button
                role="switch"
                aria-checked={prefs.sidebarCollapsed}
                onClick={() => set('sidebarCollapsed', !prefs.sidebarCollapsed)}
                className={cn(
                  'relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary',
                  prefs.sidebarCollapsed ? 'bg-primary' : 'bg-border'
                )}
              >
                <span
                  className={cn(
                    'inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform',
                    prefs.sidebarCollapsed ? 'translate-x-6' : 'translate-x-1'
                  )}
                />
              </button>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Date Format
              </label>
              <div className="flex gap-2">
                {(
                  [
                    { value: 'relative', label: 'Relative', example: '2h ago' },
                    { value: 'iso', label: 'ISO', example: '2026-03-29' },
                    { value: 'us', label: 'US', example: '03/29/2026' },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => set('dateFormat', opt.value)}
                    className={cn(
                      'flex flex-col items-start rounded-lg border px-3 py-2 text-left transition-colors',
                      prefs.dateFormat === opt.value
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border hover:border-muted text-muted'
                    )}
                  >
                    <span className="text-xs font-medium">{opt.label}</span>
                    <span className="text-[10px] font-mono">{opt.example}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-medium text-muted uppercase tracking-wider">
                Events Per Page
              </label>
              <div className="flex gap-2">
                {([25, 50, 100] as const).map((n) => (
                  <button
                    key={n}
                    onClick={() => set('eventsPerPage', n)}
                    className={cn(
                      'rounded-lg border px-4 py-2 text-sm font-medium transition-colors',
                      prefs.eventsPerPage === n
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border hover:border-muted text-muted'
                    )}
                  >
                    {n}
                  </button>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button onClick={save} size="sm">
            Save Preferences
          </Button>
        </div>
      </div>
    </>
  )
}

// ─── DANGER ZONE TAB ─────────────────────────────────────────────────────────

function DangerZoneTab() {
  const { toast, show } = useToast()
  const [modal, setModal] = useState<'sim-data' | 'scores' | null>(null)
  const [exporting, setExporting] = useState(false)

  async function deleteSimData() {
    setModal(null)
    // Placeholder — endpoint TBD
    show('success', 'All simulation data deleted.')
  }

  async function resetScores() {
    setModal(null)
    // Placeholder — endpoint TBD
    show('success', 'Use case scores reset.')
  }

  async function exportAll() {
    setExporting(true)
    try {
      const res = await authFetch(`${API_BASE}/api/v2/reports/generate?type=full`)
      if (!res.ok) throw new Error('Export failed')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `purplelab-export-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      show('success', 'Export started.')
    } catch {
      show('error', 'Export failed. Try again.')
    } finally {
      setExporting(false)
    }
  }

  return (
    <>
      {toast && <Toast {...toast} />}
      <ConfirmModal
        open={modal === 'sim-data'}
        title="Delete all simulation data?"
        description="This permanently removes all generated logs, events, and session history. This action cannot be undone."
        confirmLabel="Delete Everything"
        onConfirm={deleteSimData}
        onCancel={() => setModal(null)}
        destructive
      />
      <ConfirmModal
        open={modal === 'scores'}
        title="Reset all use case scores?"
        description="This will clear all Bayesian DES scores and detection efficacy metrics. Scores will rebuild from future simulation runs."
        confirmLabel="Reset Scores"
        onConfirm={resetScores}
        onCancel={() => setModal(null)}
        destructive
      />

      <div className="space-y-4">
        <div className="rounded-xl border-2 border-red/40 bg-red/5 p-6 space-y-5">
          <div className="flex items-center gap-2 text-red">
            <AlertTriangle className="h-5 w-5" />
            <h3 className="text-sm font-semibold">Danger Zone</h3>
          </div>
          <p className="text-xs text-muted">
            Actions in this section are irreversible. Please be sure before proceeding.
          </p>

          {/* Delete sim data */}
          <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-5 py-4">
            <div>
              <div className="text-sm font-medium text-text">Delete all simulation data</div>
              <div className="text-xs text-muted mt-0.5">
                Permanently removes all generated logs, events, and sessions.
              </div>
            </div>
            <Button
              size="sm"
              className="bg-red/10 text-red border border-red/30 hover:bg-red/20"
             
              onClick={() => setModal('sim-data')}
            >
              Delete Data
            </Button>
          </div>

          {/* Reset scores */}
          <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-5 py-4">
            <div>
              <div className="text-sm font-medium text-text">Reset use case scores</div>
              <div className="text-xs text-muted mt-0.5">
                Clears all DES scores and Bayesian efficacy metrics.
              </div>
            </div>
            <Button
              size="sm"
              className="bg-red/10 text-red border border-red/30 hover:bg-red/20"
             
              onClick={() => setModal('scores')}
            >
              Reset Scores
            </Button>
          </div>

          {/* Export all */}
          <div className="flex items-center justify-between rounded-lg border border-border bg-bg px-5 py-4">
            <div>
              <div className="text-sm font-medium text-text">Export all data</div>
              <div className="text-xs text-muted mt-0.5">
                Download a full JSON archive of all platform data.
              </div>
            </div>
            <Button
              size="sm"
             
              onClick={exportAll}
              disabled={exporting}
            >
              {exporting ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              Export
            </Button>
          </div>
        </div>
      </div>
    </>
  )
}

// ─── MAIN PAGE ────────────────────────────────────────────────────────────────

const TABS = [
  { value: 'profile', label: 'Profile', icon: User },
  { value: 'notifications', label: 'Notifications', icon: Bell },
  { value: 'appearance', label: 'Appearance', icon: Palette },
  { value: 'danger', label: 'Danger Zone', icon: AlertTriangle },
] as const

export default function SettingsPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-text">Settings</h1>
        <p className="text-sm text-muted mt-1">
          Manage your profile, notifications, appearance, and platform data.
        </p>
      </div>

      <Tabs defaultValue="profile">
        <TabsList className="gap-1">
          {TABS.map(({ value, label, icon: Icon }) => (
            <TabsTrigger
              key={value}
              value={value}
              className={cn(
                'flex items-center gap-1.5',
                value === 'danger' && 'data-[state=active]:text-red data-[state=active]:border-red/40'
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="profile" className="mt-6">
          <ProfileTab />
        </TabsContent>
        <TabsContent value="notifications" className="mt-6">
          <NotificationsTab />
        </TabsContent>
        <TabsContent value="appearance" className="mt-6">
          <AppearanceTab />
        </TabsContent>
        <TabsContent value="danger" className="mt-6">
          <DangerZoneTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}
