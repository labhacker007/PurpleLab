"use client"

import { create } from "zustand"
import type { Environment, EnvironmentNode } from "@/types"

interface EnvironmentState {
  environments: Environment[]
  activeEnvironmentId: string | null
  selectedNodeId: string | null

  setEnvironments: (environments: Environment[]) => void
  setActiveEnvironment: (id: string | null) => void
  addEnvironment: (env: Environment) => void
  updateEnvironment: (id: string, updates: Partial<Environment>) => void
  deleteEnvironment: (id: string) => void
  setSelectedNode: (nodeId: string | null) => void
  addNode: (envId: string, node: EnvironmentNode) => void
  updateNode: (envId: string, nodeId: string, updates: Partial<EnvironmentNode>) => void
  removeNode: (envId: string, nodeId: string) => void
}

export const useEnvironmentStore = create<EnvironmentState>((set) => ({
  environments: [],
  activeEnvironmentId: null,
  selectedNodeId: null,

  setEnvironments: (environments) => set({ environments }),
  setActiveEnvironment: (id) => set({ activeEnvironmentId: id }),

  addEnvironment: (env) =>
    set((state) => ({ environments: [...state.environments, env] })),

  updateEnvironment: (id, updates) =>
    set((state) => ({
      environments: state.environments.map((e) =>
        e.id === id ? { ...e, ...updates } : e
      ),
    })),

  deleteEnvironment: (id) =>
    set((state) => ({
      environments: state.environments.filter((e) => e.id !== id),
    })),

  setSelectedNode: (nodeId) => set({ selectedNodeId: nodeId }),

  addNode: (envId, node) =>
    set((state) => ({
      environments: state.environments.map((e) =>
        e.id === envId ? { ...e, nodes: [...e.nodes, node] } : e
      ),
    })),

  updateNode: (envId, nodeId, updates) =>
    set((state) => ({
      environments: state.environments.map((e) =>
        e.id === envId
          ? {
              ...e,
              nodes: e.nodes.map((n) =>
                n.id === nodeId ? { ...n, ...updates } : n
              ),
            }
          : e
      ),
    })),

  removeNode: (envId, nodeId) =>
    set((state) => ({
      environments: state.environments.map((e) =>
        e.id === envId
          ? { ...e, nodes: e.nodes.filter((n) => n.id !== nodeId) }
          : e
      ),
    })),
}))
