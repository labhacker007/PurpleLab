"use client"

import { use, useMemo, useCallback, useState } from "react"
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Panel,
  useNodesState,
  useEdgesState,
  addEdge,
  type Node,
  type Edge,
  type Connection,
  type NodeTypes,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { Play, Square, Save, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { useEnvironmentStore } from "@/stores/environment"
import { cn } from "@/lib/utils"

// ── Custom Node Components ────────────────────────────────────────────────

function LogSourceNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border-2 border-blue bg-card px-4 py-3 min-w-[160px] shadow-lg">
      <div className="text-[10px] text-blue uppercase font-bold tracking-wide">Log Source</div>
      <div className="text-sm font-semibold text-text mt-1">{String(data.label ?? "")}</div>
    </div>
  )
}

function SIEMNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border-2 border-green bg-card px-4 py-3 min-w-[160px] shadow-lg">
      <div className="text-[10px] text-green uppercase font-bold tracking-wide">SIEM</div>
      <div className="text-sm font-semibold text-text mt-1">{String(data.label ?? "")}</div>
    </div>
  )
}

function RuleSetNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border-2 border-primary bg-card px-4 py-3 min-w-[160px] shadow-lg">
      <div className="text-[10px] text-primary uppercase font-bold tracking-wide">Rule Set</div>
      <div className="text-sm font-semibold text-text mt-1">{String(data.label ?? "")}</div>
    </div>
  )
}

function SimulatorNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border-2 border-amber bg-card px-4 py-3 min-w-[160px] shadow-lg">
      <div className="text-[10px] text-amber uppercase font-bold tracking-wide">Simulator</div>
      <div className="text-sm font-semibold text-text mt-1">{String(data.label ?? "")}</div>
    </div>
  )
}

function TargetNodeComponent({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="rounded-xl border-2 border-primary border-dashed bg-card px-4 py-3 min-w-[160px] shadow-lg">
      <div className="text-[10px] text-primary uppercase font-bold tracking-wide">Target</div>
      <div className="text-sm font-semibold text-text mt-1">{String(data.label ?? "")}</div>
    </div>
  )
}

const nodeTypes: NodeTypes = {
  log_source: LogSourceNode,
  siem: SIEMNode,
  rule_set: RuleSetNode,
  simulator: SimulatorNode,
  target: TargetNodeComponent,
}

// ── Palette Items ─────────────────────────────────────────────────────────

const paletteItems = [
  { type: "log_source", label: "Log Source", color: "border-blue text-blue" },
  { type: "siem", label: "SIEM", color: "border-green text-green" },
  { type: "rule_set", label: "Rule Set", color: "border-primary text-primary" },
  { type: "simulator", label: "Simulator", color: "border-amber text-amber" },
  { type: "target", label: "Target", color: "border-primary text-primary border-dashed" },
]

// ── Page Component ────────────────────────────────────────────────────────

export default function EnvironmentEditorPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const { environments, setSelectedNode, selectedNodeId } = useEnvironmentStore()
  const env = environments.find((e) => e.id === id)

  const initialNodes: Node[] = useMemo(
    () =>
      env?.nodes.map((n) => ({
        id: n.id,
        type: n.type,
        position: { x: n.x, y: n.y },
        data: { label: n.label, config: n.config },
      })) ?? [],
    [env]
  )

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [isRunning, setIsRunning] = useState(false)

  const onConnect = useCallback(
    (connection: Connection) => {
      setEdges((eds) => addEdge({ ...connection, animated: isRunning }, eds))
    },
    [setEdges, isRunning]
  )

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    const nodeType = e.dataTransfer.getData("application/reactflow")
    if (!nodeType) return

    const paletteItem = paletteItems.find((p) => p.type === nodeType)
    const rect = (e.target as HTMLElement).closest(".react-flow")?.getBoundingClientRect()
    if (!rect) return

    const newNode: Node = {
      id: Math.random().toString(36).slice(2, 10),
      type: nodeType,
      position: { x: e.clientX - rect.left - 80, y: e.clientY - rect.top - 30 },
      data: { label: paletteItem?.label ?? nodeType },
    }
    setNodes((nds) => [...nds, newNode])
  }

  function handleDragOver(e: React.DragEvent) {
    e.preventDefault()
    e.dataTransfer.dropEffect = "move"
  }

  if (!env) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted">Environment not found.</p>
      </div>
    )
  }

  return (
    <div className="flex h-full -m-6">
      {/* Node Palette */}
      <div className="w-56 border-r border-border bg-card p-4 space-y-2">
        <h3 className="text-xs uppercase text-muted tracking-wide font-semibold mb-3">
          Node Palette
        </h3>
        {paletteItems.map((item) => (
          <div
            key={item.type}
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData("application/reactflow", item.type)
              e.dataTransfer.effectAllowed = "move"
            }}
            className={cn(
              "flex items-center gap-2 rounded-lg border-2 bg-bg px-3 py-2 text-xs font-medium cursor-grab active:cursor-grabbing transition-colors hover:bg-card",
              item.color
            )}
          >
            <Plus className="h-3 w-3" />
            {item.label}
          </div>
        ))}
      </div>

      {/* Canvas */}
      <div className="flex-1" onDrop={handleDrop} onDragOver={handleDragOver}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={(_, node) => setSelectedNode(node.id)}
          onPaneClick={() => setSelectedNode(null)}
          nodeTypes={nodeTypes}
          fitView
          className="bg-bg"
        >
          <Background color="#2a2d3a" gap={20} size={1} />
          <Controls className="!bg-card !border-border !rounded-lg" />
          <MiniMap
            nodeColor={() => "#6366f1"}
            className="!bg-card !border-border !rounded-lg"
          />
          <Panel position="top-center">
            <div className="flex items-center gap-2 bg-card border border-border rounded-lg px-3 py-2">
              <span className="text-sm font-medium text-text">{env.name}</span>
              <div className="w-px h-5 bg-border" />
              {!isRunning ? (
                <Button size="sm" variant="success" onClick={() => setIsRunning(true)}>
                  <Play className="h-3 w-3" /> Start
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => setIsRunning(false)}
                >
                  <Square className="h-3 w-3" /> Stop
                </Button>
              )}
              <Button size="sm" variant="outline">
                <Save className="h-3 w-3" /> Save
              </Button>
            </div>
          </Panel>
        </ReactFlow>
      </div>

      {/* Properties Panel */}
      {selectedNodeId && (
        <div className="w-72 border-l border-border bg-card p-4">
          <h3 className="text-xs uppercase text-muted tracking-wide font-semibold mb-3">
            Node Properties
          </h3>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-muted block mb-1">Label</label>
              <Input
                defaultValue={
                  String(nodes.find((n) => n.id === selectedNodeId)?.data?.label ?? "")
                }
              />
            </div>
            <div>
              <label className="text-xs text-muted block mb-1">Type</label>
              <Badge variant="primary">
                {nodes.find((n) => n.id === selectedNodeId)?.type ?? "unknown"}
              </Badge>
            </div>
            <div>
              <label className="text-xs text-muted block mb-1">Position</label>
              <div className="flex gap-2">
                <Input
                  type="number"
                  defaultValue={Math.round(
                    nodes.find((n) => n.id === selectedNodeId)?.position?.x ?? 0
                  )}
                  className="w-20"
                />
                <Input
                  type="number"
                  defaultValue={Math.round(
                    nodes.find((n) => n.id === selectedNodeId)?.position?.y ?? 0
                  )}
                  className="w-20"
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
