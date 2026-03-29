import type {
  FunctionModelConfig,
  FunctionName,
  ModelConfig,
  TestResult,
} from '@/app/settings/models/types'

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000'

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let message = `HTTP ${res.status}: ${res.statusText}`
    try {
      const body = await res.json()
      if (body?.error) message = body.error
      else if (body?.message) message = body.message
    } catch {
      // ignore parse errors
    }
    throw new Error(message)
  }
  return res.json() as Promise<T>
}

export async function getModelConfigs(): Promise<FunctionModelConfig[]> {
  try {
    const res = await fetch(`${API_BASE}/api/v2/model-config`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
    return handleResponse<FunctionModelConfig[]>(res)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error('Failed to fetch model configs')
  }
}

export async function updateModelConfig(
  fn: FunctionName,
  config: ModelConfig
): Promise<FunctionModelConfig> {
  try {
    const res = await fetch(`${API_BASE}/api/v2/model-config/${fn}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    })
    return handleResponse<FunctionModelConfig>(res)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error(`Failed to update config for ${fn}`)
  }
}

export async function testModelConfig(fn: FunctionName): Promise<TestResult> {
  try {
    const res = await fetch(`${API_BASE}/api/v2/model-config/${fn}/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    return handleResponse<TestResult>(res)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error(`Failed to test config for ${fn}`)
  }
}

export async function testAllModelConfigs(): Promise<
  Record<FunctionName, TestResult>
> {
  try {
    const res = await fetch(`${API_BASE}/api/v2/model-config/test-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    return handleResponse<Record<FunctionName, TestResult>>(res)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error('Failed to test all model configs')
  }
}

export async function resetToDefaults(): Promise<void> {
  try {
    const res = await fetch(`${API_BASE}/api/v2/model-config/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    })
    await handleResponse<{ ok: boolean }>(res)
  } catch (err) {
    if (err instanceof Error) throw err
    throw new Error('Failed to reset model configs')
  }
}
