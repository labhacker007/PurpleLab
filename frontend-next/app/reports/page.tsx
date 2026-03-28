"use client"

import { BarChart3, Clock, CheckCircle2, XCircle } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useRulesStore } from "@/stores/rules"
import type { TestRun } from "@/types"

export default function ReportsPage() {
  const { testRuns } = useRulesStore()

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-text">Test Reports</h1>
        <p className="text-sm text-muted mt-1">
          View results from detection coverage test runs.
        </p>
      </div>

      {testRuns.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center">
            <BarChart3 className="h-12 w-12 text-muted mx-auto mb-4" />
            <h2 className="text-lg font-semibold">No test reports yet</h2>
            <p className="text-sm text-muted mt-1">
              Run a detection coverage test from the Chat or Environments page to generate reports.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {testRuns.map((run) => (
            <TestRunCard key={run.id} run={run} />
          ))}
        </div>
      )}
    </div>
  )
}

function TestRunCard({ run }: { run: TestRun }) {
  const total = run.rules_fired + run.rules_missed
  const pct = total > 0 ? Math.round((run.rules_fired / total) * 100) : 0

  return (
    <Card className="hover:border-primary/50 transition-colors cursor-pointer">
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <BarChart3 className="h-5 w-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-medium text-sm">Test Run</span>
                <Badge
                  variant={
                    run.status === "completed"
                      ? "success"
                      : run.status === "failed"
                        ? "destructive"
                        : "warning"
                  }
                >
                  {run.status}
                </Badge>
              </div>
              <div className="flex items-center gap-3 mt-1 text-xs text-muted">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {new Date(run.started_at).toLocaleString()}
                </span>
                {run.threat_actor && <span>Actor: {run.threat_actor}</span>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-6 text-sm">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{pct}%</div>
              <div className="text-[10px] text-muted uppercase">Coverage</div>
            </div>
            <div className="text-center">
              <div className="flex items-center gap-1 text-green">
                <CheckCircle2 className="h-4 w-4" />
                <span className="font-semibold">{run.rules_fired}</span>
              </div>
              <div className="text-[10px] text-muted">Fired</div>
            </div>
            <div className="text-center">
              <div className="flex items-center gap-1 text-red">
                <XCircle className="h-4 w-4" />
                <span className="font-semibold">{run.rules_missed}</span>
              </div>
              <div className="text-[10px] text-muted">Missed</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
