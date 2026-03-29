'use client'

import { useEffect, type ReactNode } from 'react'
import { useAuthStore } from '@/stores/auth'

export function AuthProvider({ children }: { children: ReactNode }) {
  const initialize = useAuthStore((s) => s.initialize)

  useEffect(() => {
    void initialize()
  }, [initialize])

  return <>{children}</>
}
