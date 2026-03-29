"use client"

import { useState } from "react"
import Link from "next/link"
import { Plus, Server, Clock, Layers, CheckCircle, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { useEnvironmentStore } from "@/stores/environment"
import type { Environment } from "@/types"

function generateId(): string {
  return Math.random().toString(36).slice(2, 14)
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

function getNodeCount(env: Environment): number {
  return env.nodes.length
}

function getRuleCount(env: Environment): number {
  return env.nodes.filter((n) => n.type === "rule_set").length
}

export default function EnvironmentsPage() {
  const { environments, addEnvironment } = useEnvironmentStore()
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState("")
  const [newDesc, setNewDesc] = useState("")

  function handleCreate() {
    if (!newName.trim()) return
    const now = new Date().toISOString()
    const env: Environment = {
      id: generateId(),
      name: newName.trim(),
      description: newDesc.trim(),
      nodes: [],
      created_at: now,
      updated_at: now,
    }
    addEnvironment(env)
    setNewName("")
    setNewDesc("")
    setShowCreate(false)
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text">Environments</h1>
          <p className="text-sm text-muted mt-1">
            Build and manage detection environments with the visual canvas.
          </p>
        </div>
        <Button onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4" />
          New Environment
        </Button>
      </div>

      {environments.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center">
            <Server className="h-12 w-12 text-muted mx-auto mb-4" />
            <h2 className="text-lg font-semibold">No environments yet</h2>
            <p className="text-sm text-muted mt-1">
              Create your first environment to start composing your detection topology.
            </p>
            <Button className="mt-4" onClick={() => setShowCreate(true)}>
              Create Environment
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {environments.map((env) => {
            const nodeCount = getNodeCount(env)
            const ruleCount = getRuleCount(env)
            const lastRun = env.last_tested ? timeAgo(env.last_tested) : null

            return (
              <Card
                key={env.id}
                className="hover:border-primary transition-colors h-full group"
              >
                <CardContent className="p-5 flex flex-col h-full">
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue/10 shrink-0">
                      <Server className="h-5 w-5 text-blue" />
                    </div>
                    <Badge variant="info">{nodeCount} nodes</Badge>
                  </div>

                  {/* Name & description */}
                  <h3 className="font-semibold text-sm">{env.name}</h3>
                  <p className="text-xs text-muted mt-1 line-clamp-2 flex-1">
                    {env.description || "No description"}
                  </p>

                  {/* Stats row */}
                  <div className="flex items-center gap-3 mt-3 text-[10px] text-muted">
                    <div className="flex items-center gap-1">
                      <Layers className="h-3 w-3" />
                      <span>{nodeCount} nodes</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <CheckCircle className="h-3 w-3" />
                      <span>{ruleCount} rules</span>
                    </div>
                    {lastRun ? (
                      <div className="flex items-center gap-1 ml-auto">
                        <Clock className="h-3 w-3" />
                        <span>last run {lastRun}</span>
                      </div>
                    ) : (
                      <span className="ml-auto text-muted/60">never run</span>
                    )}
                  </div>

                  {/* Open Canvas button */}
                  <div className="mt-4 pt-3 border-t border-border">
                    <Link href={`/environments/${env.id}`} className="block">
                      <Button
                        size="sm"
                       
                        className="w-full gap-1.5 group-hover:border-primary group-hover:text-primary transition-colors"
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                        Open Canvas
                      </Button>
                    </Link>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={showCreate} onClose={() => setShowCreate(false)}>
        <DialogHeader>
          <DialogTitle>Create Environment</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-muted block mb-1">Name</label>
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Corp SOC Prod"
              autoFocus
            />
          </div>
          <div>
            <label className="text-xs text-muted block mb-1">Description</label>
            <Input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Testing EDR detection coverage..."
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setShowCreate(false)}>
            Cancel
          </Button>
          <Button onClick={handleCreate} disabled={!newName.trim()}>
            Create
          </Button>
        </DialogFooter>
      </Dialog>
    </div>
  )
}
