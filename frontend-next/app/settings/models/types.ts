export type LLMProvider = 'anthropic' | 'openai' | 'google' | 'ollama' | 'azure_openai'

export type FunctionName =
  | 'AGENT_CHAT'
  | 'LOG_GENERATION'
  | 'THREAT_INTEL'
  | 'RULE_ANALYSIS'
  | 'EMBEDDING'
  | 'SCORING_ASSIST'
  | 'ATTACK_CHAIN_PLAN'
  | 'SIGMA_TRANSLATION'
  | 'HITL_REVIEW'

export interface ModelConfig {
  provider: LLMProvider
  model_id: string
  base_url?: string
  temperature: number
  max_tokens: number
  is_active: boolean
  status?: 'ok' | 'error' | 'untested'
  error_message?: string
}

export interface FunctionModelConfig {
  function_name: FunctionName
  display_name: string
  description: string
  config: ModelConfig
  fallback_config?: ModelConfig
  needs_tools?: boolean
  volume?: string
  updated_at: string
}

export interface TestResult {
  ok: boolean
  latency_ms: number
  error?: string
}

export type ProviderModels = Record<LLMProvider, string[]>

export const PROVIDER_MODELS: ProviderModels = {
  anthropic: [
    'claude-opus-4-6',
    'claude-sonnet-4-6',
    'claude-haiku-4-5-20251001',
  ],
  openai: ['gpt-4o', 'gpt-4o-mini', 'o1', 'o3-mini'],
  google: ['gemini-2.0-flash', 'gemini-1.5-pro', 'gemini-1.5-flash'],
  ollama: [
    'llama3.2',
    'llama3',
    'llama3.1:70b',
    'mistral',
    'qwen2.5',
    'phi4',
    'codellama',
    'deepseek-r1',
    'deepseek-r1:32b',
    'nomic-embed-text',
  ],
  azure_openai: ['gpt-4o', 'gpt-4o-mini'],
}

export const PROVIDER_LABELS: Record<LLMProvider, string> = {
  anthropic: 'Anthropic',
  openai: 'OpenAI',
  google: 'Google Gemini',
  ollama: 'Ollama (Local)',
  azure_openai: 'Azure OpenAI',
}

export const PROVIDER_COLORS: Record<LLMProvider, { dot: string; ring: string; label: string; bg: string }> = {
  anthropic: { dot: 'bg-amber-400', ring: 'ring-amber-400/40', label: 'text-amber-400', bg: 'bg-amber-400/10' },
  openai: { dot: 'bg-green', ring: 'ring-green/40', label: 'text-green', bg: 'bg-green/10' },
  google: { dot: 'bg-blue', ring: 'ring-blue/40', label: 'text-blue', bg: 'bg-blue/10' },
  ollama: { dot: 'bg-purple-400', ring: 'ring-purple-400/40', label: 'text-purple-400', bg: 'bg-purple-400/10' },
  azure_openai: { dot: 'bg-cyan-400', ring: 'ring-cyan-400/40', label: 'text-cyan-400', bg: 'bg-cyan-400/10' },
}

export const FUNCTION_DESCRIPTIONS: Record<FunctionName, string> = {
  AGENT_CHAT: 'Powers the interactive AI assistant for purple team operations',
  LOG_GENERATION: 'Generates realistic log data for SIEM testing scenarios',
  THREAT_INTEL: 'Enriches indicators with threat intelligence context',
  RULE_ANALYSIS: 'Analyzes and improves detection rules (Sigma, KQL, SPL)',
  EMBEDDING: 'Generates vector embeddings for semantic search',
  SCORING_ASSIST: 'Bayesian scoring engine for detection coverage',
  ATTACK_CHAIN_PLAN: 'Plans multi-stage attack chains for simulation',
  SIGMA_TRANSLATION: 'Translates Sigma rules to SPL, KQL, ES|QL, YARA-L',
  HITL_REVIEW: 'Summarizes pending approvals and suggests decisions',
}

export const FUNCTION_ICONS: Record<FunctionName, string> = {
  AGENT_CHAT: 'MessageSquare',
  LOG_GENERATION: 'FileText',
  THREAT_INTEL: 'Shield',
  RULE_ANALYSIS: 'Search',
  EMBEDDING: 'Layers',
  SCORING_ASSIST: 'BarChart3',
  ATTACK_CHAIN_PLAN: 'GitBranch',
  SIGMA_TRANSLATION: 'ArrowLeftRight',
  HITL_REVIEW: 'UserCheck',
}

export const COST_PER_MILLION: Record<string, number> = {
  'claude-opus-4-6': 15,
  'claude-sonnet-4-6': 3,
  'claude-haiku-4-5-20251001': 0.8,
  'gpt-4o': 5,
  'gpt-4o-mini': 0.6,
  'o1': 15,
  'o3-mini': 2,
  'gemini-2.0-flash': 0.075,
  'gemini-1.5-pro': 3.5,
  'gemini-1.5-flash': 0.075,
}
