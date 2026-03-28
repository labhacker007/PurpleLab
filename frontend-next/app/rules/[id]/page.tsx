"use client"

import { use, useState } from "react"
import dynamic from "next/dynamic"
import { Play, Loader2, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useRulesStore } from "@/stores/rules"
import type { EvalResult } from "@/types"

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), { ssr: false })

const languageMap: Record<string, string> = {
  sigma: "yaml",
  kql: "plaintext",
  spl: "plaintext",
  "yara-l": "plaintext",
  esql: "plaintext",
  other: "plaintext",
}

export default function RuleDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const { rules } = useRulesStore()
  const rule = rules.find((r) => r.id === id)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<EvalResult | null>(null)

  if (!rule) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <p className="text-muted">Rule not found.</p>
        <Link href="/rules">
          <Button variant="outline">
            <ArrowLeft className="h-4 w-4" />
            Back to Rules
          </Button>
        </Link>
      </div>
    )
  }

  function handleTest() {
    setTesting(true)
    // Placeholder test result
    setTimeout(() => {
      setTestResult({
        rule_id: rule!.id,
        matched: true,
        match_count: 3,
        logs_tested: 100,
        duration_ms: 42,
        details: "Rule matched 3 of 100 sample log events.",
      })
      setTesting(false)
    }, 1500)
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/rules">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-xl font-bold text-text">{rule.name}</h1>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant="primary">{rule.language}</Badge>
              <Badge
                variant={
                  rule.severity === "critical"
                    ? "destructive"
                    : rule.severity === "high"
                      ? "warning"
                      : "info"
                }
              >
                {rule.severity}
              </Badge>
              {rule.mitre_techniques.map((t) => (
                <Badge key={t} variant="default">
                  {t}
                </Badge>
              ))}
            </div>
          </div>
        </div>
        <Button onClick={handleTest} disabled={testing}>
          {testing ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Testing...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Test Rule
            </>
          )}
        </Button>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Editor */}
        <Card className="col-span-1">
          <CardHeader>
            <CardTitle className="text-sm">Rule Content</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="rounded-lg overflow-hidden border border-border">
              <MonacoEditor
                height="400px"
                language={languageMap[rule.language] ?? "plaintext"}
                value={rule.content}
                theme="vs-dark"
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  fontSize: 13,
                  lineNumbers: "on",
                  scrollBeyondLastLine: false,
                  wordWrap: "on",
                }}
              />
            </div>
          </CardContent>
        </Card>

        {/* AST / Test Results */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Parsed AST</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="bg-bg rounded-lg p-4 text-xs text-muted font-mono h-40 overflow-auto">
                <p>AST visualization will be available when the backend parser is connected.</p>
                <p className="mt-2">Rule language: {rule.language}</p>
              </div>
            </CardContent>
          </Card>

          {testResult && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Test Results</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Badge variant={testResult.matched ? "success" : "destructive"}>
                      {testResult.matched ? "MATCHED" : "NO MATCH"}
                    </Badge>
                    <span className="text-xs text-muted">
                      in {testResult.duration_ms}ms
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <span className="text-muted text-xs">Matches</span>
                      <p className="font-semibold">{testResult.match_count}</p>
                    </div>
                    <div>
                      <span className="text-muted text-xs">Logs Tested</span>
                      <p className="font-semibold">{testResult.logs_tested}</p>
                    </div>
                  </div>
                  <p className="text-xs text-muted">{testResult.details}</p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
