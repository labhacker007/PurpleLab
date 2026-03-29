"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  MessageSquare,
  Server,
  FileText,
  Shield,
  BarChart3,
  Settings,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  Workflow,
  ClipboardCheck,
  Activity,
  ShieldCheck,
  BookOpen,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useUIStore } from "@/stores/ui"
import { useAuthStore } from "@/stores/auth"

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/pipeline", label: "Pipeline", icon: Workflow },
  { href: "/chat", label: "Chat", icon: MessageSquare },
  { href: "/environments", label: "Environments", icon: Server },
  { href: "/sessions", label: "Sessions", icon: Activity },
  { href: "/rules", label: "Rules", icon: FileText },
  { href: "/use-cases", label: "Use Cases", icon: ClipboardCheck },
  { href: "/threat-intel", label: "Threat Intel", icon: Shield },
  { href: "/knowledge", label: "Knowledge", icon: BookOpen },
  { href: "/reports", label: "Reports", icon: BarChart3 },
  { href: "/settings", label: "Settings", icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const { sidebarCollapsed, toggleSidebar } = useUIStore()
  const user = useAuthStore((s) => s.user)

  return (
    <aside
      className={cn(
        "flex flex-col border-r border-border bg-card transition-all duration-200",
        sidebarCollapsed ? "w-16" : "w-[260px]"
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-3 border-b border-border px-4">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-white font-bold text-sm">
          PL
        </div>
        {!sidebarCollapsed && (
          <div>
            <div className="text-sm font-semibold text-text">PurpleLab</div>
            <div className="text-[10px] text-muted">Security Simulator</div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3 overflow-y-auto">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href || pathname.startsWith(item.href + "/")
          const Icon = item.icon
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted hover:text-text hover:bg-bg"
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!sidebarCollapsed && <span>{item.label}</span>}
            </Link>
          )
        })}

        {/* Admin link — only visible to admin role */}
        {user?.role === "admin" && (
          <Link
            href="/admin"
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
              pathname === "/admin" || pathname.startsWith("/admin/")
                ? "bg-violet-500/10 text-violet-400"
                : "text-muted hover:text-text hover:bg-bg"
            )}
          >
            <ShieldCheck className="h-4 w-4 shrink-0" />
            {!sidebarCollapsed && <span>Admin</span>}
          </Link>
        )}
      </nav>

      {/* User info */}
      {user && !sidebarCollapsed && (
        <div className="border-t border-border px-4 py-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/20 text-primary text-xs font-bold">
              {(user.full_name || user.email)[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium text-text truncate">
                {user.full_name || user.email}
              </div>
              <div className="text-[10px] text-muted capitalize">{user.role}</div>
            </div>
          </div>
        </div>
      )}

      {/* Collapse toggle */}
      <div className="border-t border-border p-3">
        <button
          onClick={toggleSidebar}
          className="flex w-full items-center justify-center rounded-lg py-2 text-muted hover:text-text hover:bg-bg transition-colors"
        >
          {sidebarCollapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </button>
      </div>
    </aside>
  )
}
