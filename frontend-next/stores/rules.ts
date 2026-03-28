"use client"

import { create } from "zustand"
import type { ImportedRule, TestRun } from "@/types"

interface RulesState {
  rules: ImportedRule[]
  testRuns: TestRun[]
  activeRuleId: string | null

  setRules: (rules: ImportedRule[]) => void
  addRule: (rule: ImportedRule) => void
  setActiveRule: (id: string | null) => void
  setTestRuns: (runs: TestRun[]) => void
  addTestRun: (run: TestRun) => void
}

export const useRulesStore = create<RulesState>((set) => ({
  rules: [],
  testRuns: [],
  activeRuleId: null,

  setRules: (rules) => set({ rules }),
  addRule: (rule) => set((state) => ({ rules: [...state.rules, rule] })),
  setActiveRule: (id) => set({ activeRuleId: id }),
  setTestRuns: (runs) => set({ testRuns: runs }),
  addTestRun: (run) => set((state) => ({ testRuns: [run, ...state.testRuns] })),
}))
