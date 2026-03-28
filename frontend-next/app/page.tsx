import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"
import { MessageSquare, Server, FileText, Shield } from "lucide-react"

const quickStats = [
  { label: "Environments", value: "0", icon: Server, color: "text-blue" },
  { label: "Rules Imported", value: "0", icon: FileText, color: "text-green" },
  { label: "Test Runs", value: "0", icon: Shield, color: "text-amber" },
  { label: "Threat Actors", value: "0", icon: Shield, color: "text-red" },
]

const quickActions = [
  { label: "Start New Chat", href: "/chat", icon: MessageSquare },
  { label: "Create Environment", href: "/environments", icon: Server },
  { label: "Import Rules", href: "/rules", icon: FileText },
]

export default function DashboardPage() {
  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Welcome */}
      <div>
        <h1 className="text-2xl font-bold text-text">Welcome to PurpleLab</h1>
        <p className="text-muted mt-1">
          Build security lab environments, import detection rules, and test coverage against threat actors.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {quickStats.map((stat) => {
          const Icon = stat.icon
          return (
            <Card key={stat.label}>
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted uppercase tracking-wide">{stat.label}</p>
                    <p className="text-2xl font-bold mt-1">{stat.value}</p>
                  </div>
                  <Icon className={`h-8 w-8 ${stat.color} opacity-60`} />
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Quick Actions */}
      <div>
        <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">
          Quick Actions
        </h2>
        <div className="grid grid-cols-3 gap-4">
          {quickActions.map((action) => {
            const Icon = action.icon
            return (
              <Link key={action.href} href={action.href}>
                <Card className="hover:border-primary transition-colors cursor-pointer">
                  <CardContent className="p-5 flex items-center gap-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                      <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <span className="text-sm font-medium">{action.label}</span>
                  </CardContent>
                </Card>
              </Link>
            )
          })}
        </div>
      </div>

      {/* Recent Activity */}
      <div>
        <h2 className="text-sm font-semibold text-muted uppercase tracking-wide mb-3">
          Recent Activity
        </h2>
        <Card>
          <CardContent className="p-8">
            <div className="text-center text-muted">
              <p className="text-sm">No recent activity</p>
              <p className="text-xs mt-1">Start a chat or create an environment to get going.</p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
