export type LLMProvider = 'anthropic' | 'openai' | 'google' | 'ollama'

export type FunctionName =
  | 'AGENT_CHAT'
  | 'LOG_GENERATION'
  | 'THREAT_INTEL'
  | 'RULE_ANALYSIS'
  | 'EMBEDDING'
  | 'SCORING_ASSIST'
  | 'ATTACK_CHAIN_PLAN'

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
    'llama3.1:70b',
    'mistral',
    'qwen2.5',
    'phi4',
    'codellama',
    'deepseek-r1',
  ],
}

export const PROVIDER_LABELS: Record<LLMProvider, string> = {
  anthropic: 'Anthropic',
  openai: 'OpenAI',
  google: 'Google Gemini',
  ollama: 'Ollama (local)',
}

export const FUNCTION_DESCRIPTIONS: Record<FunctionName, string> = {
  AGENT_CHAT: 'Powers the interactive AI assistant for purple team operations',
  LOG_GENERATION: 'Generates realistic log data for SIEM testing scenarios',
  THREAT_INTEL: 'Enriches indicators with threat intelligence context',
  RULE_ANALYSIS: 'Analyzes and improves detection rules (Sigma, KQL, SPL)',
  EMBEDDING: 'Generates vector embeddings for semantic search',
  SCORING_ASSIST: 'Bayesian scoring engine for detection coverage',
  ATTACK_CHAIN_PLAN: 'Plans multi-stage attack chains for simulation',
}
