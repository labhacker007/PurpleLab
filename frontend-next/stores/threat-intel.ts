"use client"

import { create } from "zustand"
import type { ThreatActor, MITRETechnique } from "@/types"

interface ThreatIntelState {
  actors: ThreatActor[]
  techniques: MITRETechnique[]
  selectedActorId: string | null
  selectedTechniqueId: string | null

  setActors: (actors: ThreatActor[]) => void
  setTechniques: (techniques: MITRETechnique[]) => void
  setSelectedActor: (id: string | null) => void
  setSelectedTechnique: (id: string | null) => void
}

export const useThreatIntelStore = create<ThreatIntelState>((set) => ({
  actors: [],
  techniques: [],
  selectedActorId: null,
  selectedTechniqueId: null,

  setActors: (actors) => set({ actors }),
  setTechniques: (techniques) => set({ techniques }),
  setSelectedActor: (id) => set({ selectedActorId: id }),
  setSelectedTechnique: (id) => set({ selectedTechniqueId: id }),
}))
