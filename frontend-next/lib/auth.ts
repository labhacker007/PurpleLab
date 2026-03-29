/**
 * PurpleLab auth utilities — token storage, API calls, and authFetch interceptor.
 */

import { API_BASE } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AuthUser {
  id: string
  email: string
  full_name: string
  role: string
  org_id: string | null
  is_superadmin: boolean
}

export interface AuthTokens {
  access_token: string
  refresh_token: string
  token_type: string
  user: AuthUser
}

// ─── Storage keys ─────────────────────────────────────────────────────────────

const KEYS = {
  ACCESS: 'pl_access_token',
  REFRESH: 'pl_refresh_token',
  USER: 'pl_user',
} as const

// ─── Token helpers ─────────────────────────────────────────────────────────────

export function saveTokens(tokens: AuthTokens): void {
  if (typeof window === 'undefined') return
  localStorage.setItem(KEYS.ACCESS, tokens.access_token)
  localStorage.setItem(KEYS.REFRESH, tokens.refresh_token)
  localStorage.setItem(KEYS.USER, JSON.stringify(tokens.user))
  // Also persist access token in a cookie for middleware access
  document.cookie = `pl_access=${tokens.access_token}; path=/; SameSite=Lax`
}

export function clearTokens(): void {
  if (typeof window === 'undefined') return
  localStorage.removeItem(KEYS.ACCESS)
  localStorage.removeItem(KEYS.REFRESH)
  localStorage.removeItem(KEYS.USER)
  // Clear cookie
  document.cookie = 'pl_access=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
}

export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(KEYS.ACCESS)
}

export function getRefreshToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(KEYS.REFRESH)
}

export function getStoredUser(): AuthUser | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = localStorage.getItem(KEYS.USER)
    if (!raw) return null
    return JSON.parse(raw) as AuthUser
  } catch {
    return null
  }
}

// ─── API calls ────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<AuthTokens> {
  // Backend uses OAuth2PasswordRequestForm — must send as form-urlencoded
  const body = new URLSearchParams({ username: email, password })
  const res = await fetch(`${API_BASE}/api/v2/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!res.ok) {
    let msg = 'Login failed'
    try {
      const data = (await res.json()) as { detail?: string; error?: string }
      msg = data.detail ?? data.error ?? msg
    } catch {
      // ignore
    }
    throw new Error(msg)
  }
  return res.json() as Promise<AuthTokens>
}

export async function register(
  email: string,
  password: string,
  fullName: string,
  orgName?: string
): Promise<AuthTokens> {
  const res = await fetch(`${API_BASE}/api/v2/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, full_name: fullName, org_name: orgName || undefined }),
  })
  if (!res.ok) {
    let msg = 'Registration failed'
    try {
      const data = (await res.json()) as { detail?: string; error?: string }
      msg = data.detail ?? data.error ?? msg
    } catch {
      // ignore
    }
    throw new Error(msg)
  }
  return res.json() as Promise<AuthTokens>
}

export async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return null
  try {
    const res = await fetch(`${API_BASE}/api/v2/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return null
    const data = (await res.json()) as { access_token: string }
    localStorage.setItem(KEYS.ACCESS, data.access_token)
    document.cookie = `pl_access=${data.access_token}; path=/; SameSite=Lax`
    return data.access_token
  } catch {
    return null
  }
}

export async function fetchMe(): Promise<AuthUser> {
  const token = getAccessToken()
  const res = await fetch(`${API_BASE}/api/v2/auth/me`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new Error('Failed to fetch user')
  return res.json() as Promise<AuthUser>
}

export async function logout(): Promise<void> {
  clearTokens()
}

// ─── authFetch — auto-attaches Bearer token + auto-refresh on 401 ─────────────

let _refreshing: Promise<string | null> | null = null

export async function authFetch(input: RequestInfo, init?: RequestInit): Promise<Response> {
  const token = getAccessToken()

  const headers = new Headers(init?.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)

  let res = await fetch(input, { ...init, headers })

  if (res.status === 401) {
    // Deduplicate concurrent refresh calls
    if (!_refreshing) {
      _refreshing = refreshAccessToken().finally(() => {
        _refreshing = null
      })
    }
    const newToken = await _refreshing

    if (newToken) {
      headers.set('Authorization', `Bearer ${newToken}`)
      res = await fetch(input, { ...init, headers })
    }
  }

  return res
}
