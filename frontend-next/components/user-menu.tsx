'use client'

import { useState, useRef, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { LogOut, ChevronDown, User } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export function UserMenu() {
  const router = useRouter()
  const { user, logout } = useAuthStore()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  if (!user) return null

  async function handleLogout() {
    setOpen(false)
    await logout()
    router.push('/login')
  }

  const initials = user.full_name
    ? user.full_name.split(' ').map((n) => n[0]).join('').slice(0, 2).toUpperCase()
    : user.email[0].toUpperCase()

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 hover:bg-bg transition-colors"
      >
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-bold">
          {initials}
        </div>
        <div className="hidden sm:block text-left">
          <div className="text-xs font-medium text-text leading-tight truncate max-w-[120px]">
            {user.full_name || user.email}
          </div>
          <div className="text-[10px] text-muted leading-tight">{user.email}</div>
        </div>
        <ChevronDown
          className={cn('h-3 w-3 text-muted transition-transform', open && 'rotate-180')}
        />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1.5 w-56 rounded-xl border border-border bg-card shadow-xl z-50">
          <div className="px-3 py-2.5 border-b border-border">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-bold shrink-0">
                {initials}
              </div>
              <div className="min-w-0">
                <div className="text-sm font-medium text-text truncate">{user.full_name}</div>
                <div className="text-[11px] text-muted truncate">{user.email}</div>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-1.5">
              <Badge variant={user.is_superadmin ? 'warning' : 'primary'} className="text-[10px]">
                {user.is_superadmin ? 'superadmin' : user.role}
              </Badge>
              {user.org_id && (
                <Badge variant="default" className="text-[10px]">org</Badge>
              )}
            </div>
          </div>

          <div className="p-1">
            <button
              onClick={() => { setOpen(false); router.push('/settings') }}
              className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted hover:text-text hover:bg-bg transition-colors"
            >
              <User className="h-3.5 w-3.5" />
              Profile & Settings
            </button>
            <button
              onClick={() => void handleLogout()}
              className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm text-red hover:bg-red/10 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
