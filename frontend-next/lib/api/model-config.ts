import { authFetch } from '@/lib/auth'
import type {
  FunctionModelConfig,
  FunctionName,
  ModelConfig,
  TestResult,
} from '@/app/settings/models/types'

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let message = `HTTP ${res.status}: ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.detail) message = body.detail
      else if (body?.error) message = body.error
      else if (body?.message) message = body.message
    } catch {
      // ignore parse errors
    }
    throw new Error(message)
  }
  return res.json() as Promise<T>
}

export async function getModelConfigs(): Promise<FunctionModelConfig[]> {
  const res = await authFetch('/api/v2/model-config/')
  return handleResponse<FunctionModelConfig[]>(res)
}

export async function getProviders() {
  const res = await authFetch('/api/v2/model-config/providers')
  return handleResponse<{ providers: ProviderInfo[] }>(res)
}

export interface ProviderInfo {
  provider: string
  display_name: string
  models: ModelSpec[]
  requires_api_key: boolean
  env_var: string
}

export interface ModelSpec {
  model_id: string
  display_name: string
  context_window: number
  max_output_tokens: number
  supports_tools: boolean
  supports_vision: boolean
  cost_per_1k_input: number
  cost_per_1k_output: number
  is_reasoning: boolean
  tags: string[]
}

export async function updateModelConfig(
  fn: FunctionName,
  config: ModelConfig
): Promise<FunctionModelConfig> {
  const res = await authFetch(`/api/v2/model-config/${fn}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  })
  return handleResponse<FunctionModelConfig>(res)
}

export async function testModelConfig(fn: FunctionName): Promise<TestResult> {
  const res = await authFetch(`/api/v2/model-config/${fn}/test`, {
    method: 'POST',
  })
  return handleResponse<TestResult>(res)
}

export async function testAllModelConfigs(): Promise<Record<FunctionName, TestResult>> {
  const res = await authFetch('/api/v2/model-config/test-all', {
    method: 'POST',
  })
  return handleResponse<Record<FunctionName, TestResult>>(res)
}

export async function resetToDefaults(): Promise<void> {
  const res = await authFetch('/api/v2/model-config/reset-defaults', {
    method: 'POST',
  })
  await handleResponse<{ status: string }>(res)
}

// ── Provider API Keys ─────────────────────────────────────────────────────────

export async function getApiKeyStatus(): Promise<Record<string, { configured: boolean; source: string }>> {
  const res = await authFetch('/api/v2/model-config/api-keys/status')
  return handleResponse<Record<string, { configured: boolean; source: string }>>(res)
}

export async function saveApiKey(provider: string, apiKey: string): Promise<{ ok: boolean }> {
  const res = await authFetch('/api/v2/model-config/api-keys', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, api_key: apiKey }),
  })
  return handleResponse<{ ok: boolean }>(res)
}

export async function deleteApiKey(provider: string): Promise<{ ok: boolean }> {
  const res = await authFetch(`/api/v2/model-config/api-keys/${provider}`, {
    method: 'DELETE',
  })
  return handleResponse<{ ok: boolean }>(res)
}

// ── Ollama ────────────────────────────────────────────────────────────────────

export interface OllamaModel {
  model_id: string
  display_name: string
  size_gb: number
  modified_at: string
  family?: string
  parameter_size?: string
  quantization?: string
}

export async function getOllamaModels(baseUrl?: string): Promise<{
  available: boolean
  base_url: string
  models: OllamaModel[]
  error?: string
}> {
  const params = baseUrl ? `?base_url=${encodeURIComponent(baseUrl)}` : ''
  const res = await authFetch(`/api/v2/model-config/ollama/models${params}`)
  return handleResponse<{ available: boolean; base_url: string; models: OllamaModel[]; error?: string }>(res)
}

export async function pullOllamaModel(modelName: string): Promise<{ ok: boolean; message: string }> {
  const res = await authFetch('/api/v2/model-config/ollama/pull', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: modelName }),
  })
  return handleResponse<{ ok: boolean; message: string }>(res)
}

export interface ModelSearchResult {
  model: string
  name: string
  description?: string
  source: string
  type?: string
  size?: string
  domain?: string
  use_cases?: string[]
  tags?: string[]
  use_case?: string
  vram_gb?: number
  relevance: number
}

export async function searchModels(query: string): Promise<{ query: string; results: ModelSearchResult[]; total: number }> {
  const res = await authFetch(`/api/v2/model-config/ollama/search?q=${encodeURIComponent(query)}`)
  return handleResponse<{ query: string; results: ModelSearchResult[]; total: number }>(res)
}
