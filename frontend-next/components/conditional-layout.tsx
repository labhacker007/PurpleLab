'use client'

import { usePathname } from 'next/navigation'
import { Sidebar } from '@/components/sidebar'
import { UserMenu } from '@/components/user-menu'

const AUTH_PATHS = ['/login', '/register']

export function ConditionalLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const isAuthPage = AUTH_PATHS.some((p) => pathname === p || pathname.startsWith(p + '/'))

  if (isAuthPage) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          {/* Brand mark */}
          <div className="flex flex-col items-center mb-8">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-white font-bold text-xl mb-3">
              PL
            </div>
            <span className="text-lg font-bold text-text">PurpleLab</span>
            <span className="text-xs text-muted">Security Simulation Platform</span>
          </div>
          {children}
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="h-14 shrink-0 border-b border-border bg-card flex items-center px-6">
          <h1 className="text-sm font-semibold text-text">PurpleLab</h1>
          <span className="ml-2 text-xs text-muted">v2.0</span>
          <div className="flex-1" />
          <div className="flex items-center gap-3">
            <span className="hidden md:block text-xs text-muted">Security Product Simulator</span>
            <UserMenu />
          </div>
        </header>
        <div className="flex-1 overflow-auto p-6">{children}</div>
      </main>
    </div>
  )
}
