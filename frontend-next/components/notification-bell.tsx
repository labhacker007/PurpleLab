"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import { Bell, X, CheckCheck, ExternalLink } from "lucide-react"
import Link from "next/link"
import { cn } from "@/lib/utils"
import { API_BASE } from "@/lib/api/client"
import { authFetch, getAccessToken } from "@/lib/auth"

// ─── Types ────────────────────────────────────────────────────────────────────

type NotifType = "info" | "success" | "warning" | "error"

interface Notification {
  id: string
  type: NotifType
  title: string
  message: string
  link: string | null
  read: boolean
  created_at: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const TYPE_BORDER: Record<NotifType, string> = {
  info: "border-l-blue-500",
  success: "border-l-green-500",
  warning: "border-l-amber-500",
  error: "border-l-red-500",
}

const TYPE_DOT: Record<NotifType, string> = {
  info: "bg-blue-500",
  success: "bg-green-500",
  warning: "bg-amber-500",
  error: "bg-red-500",
}

// ─── Component ────────────────────────────────────────────────────────────────

export function NotificationBell() {
  const [open, setOpen] = useState(false)
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [unreadCount, setUnreadCount] = useState(0)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Load existing notifications on mount
  useEffect(() => {
    void fetchNotifications()
  }, [])

  // Connect SSE stream
  useEffect(() => {
    const token = getAccessToken()
    if (!token) return

    // Use fetch-based SSE with Authorization header
    const controller = new AbortController()

    const connectStream = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v2/notifications/stream`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        })

        if (!res.ok || !res.body) return

        const reader = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ""

        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true })

          // Parse SSE lines
          const lines = buffer.split("\n")
          buffer = lines.pop() ?? ""

          let eventType = "message"
          for (const line of lines) {
            if (line.startsWith("event:")) {
              eventType = line.slice(6).trim()
            } else if (line.startsWith("data:")) {
              const data = line.slice(5).trim()
              if (!data || eventType === "connected") {
                eventType = "message"
                continue
              }
              try {
                const notification = JSON.parse(data) as Notification
                if (eventType === "notification") {
                  setNotifications((prev) => [notification, ...prev].slice(0, 50))
                  if (!notification.read) {
                    setUnreadCount((c) => c + 1)
                  }
                }
              } catch {
                // ignore malformed data
              }
              eventType = "message"
            }
          }
        }
      } catch {
        // connection closed or aborted — expected on cleanup
      }
    }

    void connectStream()

    return () => {
      controller.abort()
    }
  }, [])

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    if (open) document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [open])

  const fetchNotifications = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/v2/notifications?limit=50`)
      if (res.ok) {
        const data = (await res.json()) as { notifications: Notification[]; unread_count: number }
        setNotifications(data.notifications)
        setUnreadCount(data.unread_count)
      }
    } catch {
      // non-fatal
    }
  }, [])

  const handleMarkRead = useCallback(async (id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    )
    setUnreadCount((c) => Math.max(0, c - 1))
    try {
      await authFetch(`${API_BASE}/api/v2/notifications/${id}/read`, { method: "POST" })
    } catch {
      // non-fatal
    }
  }, [])

  const handleClearAll = useCallback(async () => {
    setNotifications([])
    setUnreadCount(0)
    try {
      await authFetch(`${API_BASE}/api/v2/notifications/clear`, { method: "DELETE" })
    } catch {
      // non-fatal
    }
  }, [])

  const displayed = notifications.slice(0, 10)

  return (
    <div ref={dropdownRef} className="relative">
      {/* Bell button */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="relative flex h-8 w-8 items-center justify-center rounded-lg text-muted hover:text-text hover:bg-bg transition-colors"
        aria-label="Notifications"
      >
        <Bell className="h-4 w-4" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white leading-none">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown panel */}
      {open && (
        <div className="absolute right-0 top-10 z-50 w-80 rounded-xl border border-border bg-card shadow-xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-center gap-2">
              <Bell className="h-3.5 w-3.5 text-muted" />
              <span className="text-sm font-semibold text-text">Notifications</span>
              {unreadCount > 0 && (
                <span className="flex h-4 min-w-4 items-center justify-center rounded-full bg-primary/20 px-1 text-[10px] font-bold text-primary">
                  {unreadCount}
                </span>
              )}
            </div>
            <button
              onClick={() => setOpen(false)}
              className="text-muted hover:text-text transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Notification list */}
          <div className="max-h-80 overflow-y-auto">
            {displayed.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <Bell className="mx-auto mb-2 h-6 w-6 text-muted/40" />
                <p className="text-xs text-muted">No notifications yet</p>
              </div>
            ) : (
              <div className="divide-y divide-border">
                {displayed.map((n) => {
                  const border = TYPE_BORDER[n.type] ?? "border-l-border"
                  const dot = TYPE_DOT[n.type] ?? "bg-muted"
                  const inner = (
                    <div
                      key={n.id}
                      className={cn(
                        "flex items-start gap-3 border-l-2 px-4 py-3 transition-colors cursor-pointer",
                        border,
                        n.read ? "bg-transparent" : "bg-primary/5",
                        "hover:bg-bg"
                      )}
                      onClick={() => {
                        if (!n.read) void handleMarkRead(n.id)
                      }}
                    >
                      <div className={cn("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", dot)} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-start justify-between gap-1">
                          <p className="text-xs font-medium text-text leading-snug">{n.title}</p>
                          {n.link && (
                            <ExternalLink className="mt-0.5 h-2.5 w-2.5 shrink-0 text-muted" />
                          )}
                        </div>
                        <p className="mt-0.5 text-[11px] text-muted leading-snug line-clamp-2">
                          {n.message}
                        </p>
                        <p className="mt-1 text-[10px] text-muted/70">{timeAgo(n.created_at)}</p>
                      </div>
                    </div>
                  )

                  if (n.link) {
                    return (
                      <Link key={n.id} href={n.link} onClick={() => setOpen(false)}>
                        {inner}
                      </Link>
                    )
                  }
                  return inner
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          {displayed.length > 0 && (
            <div className="border-t border-border px-4 py-2.5">
              <button
                onClick={handleClearAll}
                className="flex items-center gap-1.5 text-xs text-muted hover:text-text transition-colors"
              >
                <CheckCheck className="h-3 w-3" />
                Clear all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
