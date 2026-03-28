"use client"

import { useState, useMemo } from "react"
import { Shield, ChevronRight } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { useThreatIntelStore } from "@/stores/threat-intel"
import { cn } from "@/lib/utils"

// MITRE ATT&CK Tactics
const tactics = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
]

// Placeholder technique data for visual layout
const placeholderTechniques: Record<string, Array<{ id: string; name: string; covered: boolean }>> = {
  "Initial Access": [
    { id: "T1566", name: "Phishing", covered: false },
    { id: "T1190", name: "Exploit Public-Facing App", covered: false },
    { id: "T1133", name: "External Remote Services", covered: false },
    { id: "T1078", name: "Valid Accounts", covered: false },
  ],
  Execution: [
    { id: "T1059", name: "Command and Scripting", covered: false },
    { id: "T1204", name: "User Execution", covered: false },
    { id: "T1053", name: "Scheduled Task/Job", covered: false },
  ],
  Persistence: [
    { id: "T1547", name: "Boot or Logon Autostart", covered: false },
    { id: "T1136", name: "Create Account", covered: false },
    { id: "T1543", name: "Create or Modify System Process", covered: false },
  ],
  "Privilege Escalation": [
    { id: "T1548", name: "Abuse Elevation Mechanism", covered: false },
    { id: "T1134", name: "Access Token Manipulation", covered: false },
  ],
  "Defense Evasion": [
    { id: "T1070", name: "Indicator Removal", covered: false },
    { id: "T1036", name: "Masquerading", covered: false },
    { id: "T1027", name: "Obfuscated Files", covered: false },
  ],
  "Credential Access": [
    { id: "T1003", name: "OS Credential Dumping", covered: false },
    { id: "T1110", name: "Brute Force", covered: false },
  ],
  Discovery: [
    { id: "T1087", name: "Account Discovery", covered: false },
    { id: "T1083", name: "File and Directory Discovery", covered: false },
  ],
  "Lateral Movement": [
    { id: "T1021", name: "Remote Services", covered: false },
    { id: "T1570", name: "Lateral Tool Transfer", covered: false },
  ],
  Collection: [
    { id: "T1005", name: "Data from Local System", covered: false },
    { id: "T1114", name: "Email Collection", covered: false },
  ],
  "Command and Control": [
    { id: "T1071", name: "Application Layer Protocol", covered: false },
    { id: "T1105", name: "Ingress Tool Transfer", covered: false },
  ],
  Exfiltration: [
    { id: "T1041", name: "Exfiltration Over C2", covered: false },
    { id: "T1567", name: "Exfiltration Over Web Service", covered: false },
  ],
  Impact: [
    { id: "T1486", name: "Data Encrypted for Impact", covered: false },
    { id: "T1489", name: "Service Stop", covered: false },
  ],
}

export default function ThreatIntelPage() {
  const { actors, techniques, selectedTechniqueId, setSelectedTechnique } = useThreatIntelStore()
  const [selectedActorFilter, setSelectedActorFilter] = useState<string>("all")

  const selectedTechnique = useMemo(() => {
    if (!selectedTechniqueId) return null
    for (const techs of Object.values(placeholderTechniques)) {
      const found = techs.find((t) => t.id === selectedTechniqueId)
      if (found) return found
    }
    return null
  }, [selectedTechniqueId])

  return (
    <div className="flex h-full -m-6">
      {/* Matrix */}
      <div className="flex-1 overflow-auto p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-text">MITRE ATT&CK Navigator</h1>
            <p className="text-sm text-muted mt-1">
              Visualize detection coverage across the MITRE ATT&CK framework.
            </p>
          </div>
          <div className="flex gap-2">
            <select
              value={selectedActorFilter}
              onChange={(e) => setSelectedActorFilter(e.target.value)}
              className="h-9 rounded-lg border border-border bg-bg px-3 text-sm text-text"
            >
              <option value="all">All Threat Actors</option>
              {actors.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 mb-4 text-xs text-muted">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-green/40 border border-green/60" />
            Covered
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-red/40 border border-red/60" />
            Gap
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-border/40 border border-border" />
            Not Tested
          </div>
        </div>

        {/* Matrix Grid */}
        <div className="flex gap-1 overflow-x-auto pb-4">
          {tactics.map((tactic) => (
            <div key={tactic} className="min-w-[140px] flex-shrink-0">
              <div className="bg-card border border-border rounded-t-lg px-2 py-2 text-[10px] font-semibold text-primary uppercase tracking-wide text-center">
                {tactic}
              </div>
              <div className="space-y-1 mt-1">
                {(placeholderTechniques[tactic] ?? []).map((tech) => (
                  <button
                    key={tech.id}
                    onClick={() => setSelectedTechnique(tech.id)}
                    className={cn(
                      "w-full rounded-md border px-2 py-1.5 text-left text-[10px] transition-all",
                      tech.covered
                        ? "bg-green/10 border-green/30 text-green hover:bg-green/20"
                        : "bg-border/10 border-border text-muted hover:border-muted hover:bg-card",
                      selectedTechniqueId === tech.id && "ring-2 ring-primary"
                    )}
                  >
                    <div className="font-mono font-bold">{tech.id}</div>
                    <div className="truncate">{tech.name}</div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail Panel */}
      {selectedTechnique && (
        <div className="w-80 border-l border-border bg-card p-4">
          <h3 className="text-xs uppercase text-muted tracking-wide font-semibold mb-4">
            Technique Detail
          </h3>
          <div className="space-y-4">
            <div>
              <Badge variant="primary" className="mb-2">
                {selectedTechnique.id}
              </Badge>
              <h4 className="text-sm font-semibold">{selectedTechnique.name}</h4>
            </div>
            <div>
              <span className="text-xs text-muted">Coverage Status</span>
              <div className="mt-1">
                <Badge variant={selectedTechnique.covered ? "success" : "destructive"}>
                  {selectedTechnique.covered ? "Covered" : "Not Covered"}
                </Badge>
              </div>
            </div>
            <div>
              <span className="text-xs text-muted">Detection Rules</span>
              <p className="text-xs mt-1 text-muted">
                No rules mapped to this technique yet. Import rules or use the chat to generate
                detections.
              </p>
            </div>
            <Button variant="outline" size="sm" className="w-full">
              <ChevronRight className="h-3 w-3" />
              View in MITRE ATT&CK
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
