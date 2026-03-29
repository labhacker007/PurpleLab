'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Cpu, KeyRound, Plug, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ReactNode } from 'react'

const settingsNav = [
  {
    href: '/settings/models',
    label: 'Models',
    icon: Cpu,
    description: 'AI model routing',
  },
  {
    href: '/settings',
    label: 'Environment',
    icon: KeyRound,
    description: 'API keys & secrets',
    exact: true,
  },
  {
    href: '/settings/integrations',
    label: 'Integrations',
    icon: Plug,
    description: 'SIEM & tool connections',
  },
  {
    href: '/settings/security',
    label: 'Security',
    icon: ShieldCheck,
    description: 'Auth & audit log',
  },
]

export default function SettingsLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname()

  return (
    <div className="flex h-full gap-0">
      {/* Settings sidebar */}
      <aside className="w-56 shrink-0 border-r border-border bg-card/50">
        <div className="p-4 border-b border-border">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-muted">
            Settings
          </h2>
        </div>
        <nav className="p-3 space-y-0.5">
          {settingsNav.map((item) => {
            const isActive = item.exact
              ? pathname === item.href
              : pathname === item.href || pathname.startsWith(item.href + '/')
            const Icon = item.icon
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors group',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted hover:text-text hover:bg-bg'
                )}
              >
                <Icon
                  className={cn(
                    'h-4 w-4 shrink-0 transition-colors',
                    isActive ? 'text-primary' : 'text-muted group-hover:text-text'
                  )}
                />
                <div>
                  <div className="text-sm font-medium leading-none">
                    {item.label}
                  </div>
                  <div
                    className={cn(
                      'text-[10px] mt-0.5 leading-none',
                      isActive ? 'text-primary/70' : 'text-muted'
                    )}
                  >
                    {item.description}
                  </div>
                </div>
              </Link>
            )
          })}
        </nav>
      </aside>

      {/* Page content */}
      <div className="flex-1 overflow-auto p-6">{children}</div>
    </div>
  )
}
