"use client"

import { create } from 'zustand'
import {
  type AuthUser,
  saveTokens,
  clearTokens,
  getStoredUser,
  getAccessToken,
  login as authLogin,
  register as authRegister,
  logout as authLogout,
  fetchMe,
} from '@/lib/auth'

interface AuthState {
  user: AuthUser | null
  isLoading: boolean
  isAuthenticated: boolean
  initialize(): Promise<void>
  login(email: string, password: string): Promise<void>
  register(email: string, password: string, fullName: string, orgName?: string): Promise<void>
  logout(): Promise<void>
  refreshUser(): Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: true,
  isAuthenticated: false,

  async initialize() {
    set({ isLoading: true })
    try {
      const token = getAccessToken()
      if (!token) {
        const stored = getStoredUser()
        set({ user: stored, isAuthenticated: false, isLoading: false })
        return
      }
      // Validate token by calling /me
      const user = await fetchMe()
      // Update stored user in case it changed
      const storedTokens = {
        access_token: token,
        refresh_token: localStorage.getItem('pl_refresh_token') ?? '',
        token_type: 'bearer',
        user,
      }
      saveTokens(storedTokens)
      set({ user, isAuthenticated: true, isLoading: false })
    } catch {
      // Token invalid or expired — clear and mark unauthenticated
      clearTokens()
      set({ user: null, isAuthenticated: false, isLoading: false })
    }
  },

  async login(email, password) {
    const tokens = await authLogin(email, password)
    saveTokens(tokens)
    set({ user: tokens.user, isAuthenticated: true })
  },

  async register(email, password, fullName, orgName) {
    const tokens = await authRegister(email, password, fullName, orgName)
    saveTokens(tokens)
    set({ user: tokens.user, isAuthenticated: true })
  },

  async logout() {
    await authLogout()
    set({ user: null, isAuthenticated: false })
  },

  async refreshUser() {
    try {
      const user = await fetchMe()
      set({ user, isAuthenticated: true })
    } catch {
      clearTokens()
      set({ user: null, isAuthenticated: false })
    }
  },
}))
