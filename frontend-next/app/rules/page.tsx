"use client"

import { useState, useRef } from "react"
import Link from "next/link"
import { FileText, Upload, Search, Filter } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { useRulesStore } from "@/stores/rules"
import type { ImportedRule } from "@/types"

const severityVariant = {
  critical: "destructive",
  high: "warning",
  medium: "info",
  low: "default",
  informational: "default",
} as const

const languageColors: Record<string, string> = {
  sigma: "primary",
  kql: "info",
  spl: "success",
  "yara-l": "warning",
  esql: "destructive",
  other: "default",
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 14)
}

export default function RulesPage() {
  const { rules, addRule } = useRulesStore()
  const [searchQuery, setSearchQuery] = useState("")
  const [filterLang, setFilterLang] = useState<string>("all")
  const [filterSev, setFilterSev] = useState<string>("all")
  const fileInputRef = useRef<HTMLInputElement>(null)

  const filtered = rules.filter((r) => {
    if (searchQuery && !r.name.toLowerCase().includes(searchQuery.toLowerCase())) return false
    if (filterLang !== "all" && r.language !== filterLang) return false
    if (filterSev !== "all" && r.severity !== filterSev) return false
    return true
  })

  function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const content = reader.result as string
      const rule: ImportedRule = {
        id: generateId(),
        name: file.name.replace(/\.(yml|yaml|json|txt)$/, ""),
        language: file.name.endsWith(".yml") || file.name.endsWith(".yaml") ? "sigma" : "other",
        severity: "medium",
        content,
        mitre_techniques: [],
        source: "file_upload",
        created_at: new Date().toISOString(),
      }
      addRule(rule)
    }
    reader.readAsText(file)
    e.target.value = ""
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Rule Library</h1>
          <p className="text-sm text-muted mt-1">
            Import, browse, and test detection rules across multiple languages.
          </p>
        </div>
        <div className="flex gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".yml,.yaml,.json,.txt"
            className="hidden"
            onChange={handleImport}
          />
          <Button onClick={() => fileInputRef.current?.click()}>
            <Upload className="h-4 w-4" />
            Import Rule
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules..."
            className="pl-9"
          />
        </div>
        <select
          value={filterLang}
          onChange={(e) => setFilterLang(e.target.value)}
          className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text"
        >
          <option value="all">All Languages</option>
          <option value="sigma">Sigma</option>
          <option value="kql">KQL</option>
          <option value="spl">SPL</option>
          <option value="yara-l">YARA-L</option>
          <option value="esql">ESQL</option>
        </select>
        <select
          value={filterSev}
          onChange={(e) => setFilterSev(e.target.value)}
          className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Rules Table */}
      {filtered.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center">
            <FileText className="h-12 w-12 text-muted mx-auto mb-4" />
            <h2 className="text-lg font-semibold">No rules found</h2>
            <p className="text-sm text-muted mt-1">
              {rules.length === 0
                ? "Import your first detection rule to get started."
                : "No rules match the current filters."}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-card border-b border-border">
                <th className="text-left px-4 py-3 text-xs text-muted uppercase tracking-wide font-semibold">
                  Name
                </th>
                <th className="text-left px-4 py-3 text-xs text-muted uppercase tracking-wide font-semibold">
                  Language
                </th>
                <th className="text-left px-4 py-3 text-xs text-muted uppercase tracking-wide font-semibold">
                  Severity
                </th>
                <th className="text-left px-4 py-3 text-xs text-muted uppercase tracking-wide font-semibold">
                  MITRE
                </th>
                <th className="text-left px-4 py-3 text-xs text-muted uppercase tracking-wide font-semibold">
                  Source
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule) => (
                <tr
                  key={rule.id}
                  className="border-b border-border hover:bg-card/50 transition-colors"
                >
                  <td className="px-4 py-3">
                    <Link
                      href={`/rules/${rule.id}`}
                      className="font-medium text-text hover:text-primary transition-colors"
                    >
                      {rule.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={languageColors[rule.language] as "primary" | "default" ?? "default"}>
                      {rule.language}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={severityVariant[rule.severity]}>
                      {rule.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1 flex-wrap">
                      {rule.mitre_techniques.length > 0
                        ? rule.mitre_techniques.map((t) => (
                            <Badge key={t} variant="default" className="text-[10px]">
                              {t}
                            </Badge>
                          ))
                        : <span className="text-muted text-xs">--</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted text-xs">{rule.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
