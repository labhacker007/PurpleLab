"use client"

import { useState } from "react"
import Link from "next/link"
import { Plus, Server, Clock } from "lucide-react"
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
            Build and manage security lab environments with drag-and-drop canvas.
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
              Create your first environment to start building security lab topologies.
            </p>
            <Button className="mt-4" onClick={() => setShowCreate(true)}>
              Create Environment
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {environments.map((env) => (
            <Link key={env.id} href={`/environments/${env.id}`}>
              <Card className="hover:border-primary transition-colors cursor-pointer h-full">
                <CardContent className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue/10">
                      <Server className="h-5 w-5 text-blue" />
                    </div>
                    <Badge variant="info">{env.nodes.length} nodes</Badge>
                  </div>
                  <h3 className="font-semibold text-sm">{env.name}</h3>
                  <p className="text-xs text-muted mt-1 line-clamp-2">
                    {env.description || "No description"}
                  </p>
                  {env.last_tested && (
                    <div className="flex items-center gap-1 mt-3 text-[10px] text-muted">
                      <Clock className="h-3 w-3" />
                      Last tested: {new Date(env.last_tested).toLocaleDateString()}
                    </div>
                  )}
                </CardContent>
              </Card>
            </Link>
          ))}
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
              placeholder="My Security Lab"
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
