/** TypeScript interfaces matching the backend Pydantic models. */

// ── Chat / Conversation ─────────────────────────────────────────────────────

export interface Message {
  id: string
  role: "user" | "assistant" | "system"
  content: string
  tool_calls?: ToolCall[]
  created_at: string
}

export interface ToolCall {
  id: string
  name: string
  arguments: Record<string, unknown>
  result?: string
  status: "pending" | "running" | "completed" | "error"
}

export interface Conversation {
  id: string
  title: string
  messages: Message[]
  environment_id?: string
  created_at: string
  updated_at: string
}

// ── Environment / Canvas ────────────────────────────────────────────────────

export interface EnvironmentNode {
  id: string
  type: "log_source" | "siem" | "rule_set" | "simulator" | "target"
  label: string
  product_type?: string
  x: number
  y: number
  config: Record<string, unknown>
  connected_to?: string[]
}

export interface Environment {
  id: string
  name: string
  description: string
  nodes: EnvironmentNode[]
  created_at: string
  updated_at: string
  last_tested?: string
}

// ── Rules ───────────────────────────────────────────────────────────────────

export interface ImportedRule {
  id: string
  name: string
  language: "sigma" | "kql" | "spl" | "yara-l" | "esql" | "other"
  severity: "critical" | "high" | "medium" | "low" | "informational"
  content: string
  mitre_techniques: string[]
  source: string
  created_at: string
}

export interface ParsedRule {
  id: string
  rule_id: string
  ast: Record<string, unknown>
  field_mappings: Record<string, string>
  conditions: string[]
}

export interface EvalResult {
  rule_id: string
  matched: boolean
  match_count: number
  logs_tested: number
  duration_ms: number
  details: string
}

export interface TestRun {
  id: string
  environment_id: string
  threat_actor?: string
  started_at: string
  completed_at?: string
  status: "running" | "completed" | "failed"
  coverage_score: number
  rules_fired: number
  rules_missed: number
  results: EvalResult[]
}

// ── Threat Intel ────────────────────────────────────────────────────────────

export interface MITRETechnique {
  id: string          // e.g. "T1059.001"
  name: string
  tactic: string
  description: string
  covered: boolean
  rules: string[]     // rule IDs that cover this technique
}

export interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  techniques: string[]  // MITRE technique IDs
  description: string
}

// ── Settings / Connections ──────────────────────────────────────────────────

export interface SIEMConnection {
  id: string
  name: string
  type: "splunk" | "sentinel" | "chronicle" | "elastic" | "crowdstrike"
  base_url: string
  status: "connected" | "disconnected" | "error"
  last_tested?: string
}

// ── API Request/Response ────────────────────────────────────────────────────

export interface ChatRequest {
  conversation_id?: string
  message: string
  environment_id?: string
  model?: string
}

export interface ChatEvent {
  event: "token" | "tool_call" | "tool_result" | "done" | "error"
  data: string
}

// ── Catalog (legacy v1) ────────────────────────────────────────────────────

export interface CatalogProduct {
  id: string
  name: string
  category: string
  description: string
  color: string
}
