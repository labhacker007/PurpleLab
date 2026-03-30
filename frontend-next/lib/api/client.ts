/**
 * PurpleLab base API client with typed helpers and SSE streaming.
 */

// Always use relative URLs — Next.js rewrites proxy /api/* to the backend
export const API_BASE = ''

// ─── Error type ───────────────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// ─── Response handler ─────────────────────────────────────────────────────────

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`
    try {
      const body = (await response.json()) as { error?: string }
      if (body.error) message = body.error
    } catch {
      // ignore JSON parse error
    }
    throw new ApiError(message, response.status)
  }
  return response.json() as Promise<T>
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`)
  return handleResponse<T>(response)
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return handleResponse<T>(response)
}

export async function apiDelete(path: string): Promise<void> {
  const response = await fetch(`${API_BASE}${path}`, { method: 'DELETE' })
  if (!response.ok) {
    let message = `Delete failed with status ${response.status}`
    try {
      const body = (await response.json()) as { error?: string }
      if (body.error) message = body.error
    } catch {
      // ignore
    }
    throw new ApiError(message, response.status)
  }
}

// ─── SSE chunk type ───────────────────────────────────────────────────────────

export interface SSEChunk {
  type: string
  content: string
  metadata: Record<string, unknown>
}

// ─── SSE streaming helper ─────────────────────────────────────────────────────
/**
 * Opens a streaming POST request and yields parsed SSE chunks.
 * Each SSE data line is expected to be JSON with { type, content, metadata? }.
 *
 * Usage:
 *   for await (const chunk of streamSSE('/api/v2/chat', payload)) {
 *     if (chunk.type === 'text') appendText(chunk.content)
 *     if (chunk.type === 'done') break
 *   }
 *
 * Pass an AbortSignal to allow cancellation:
 *   const controller = new AbortController()
 *   streamSSE('/api/v2/chat', payload, controller.signal)
 */
export async function* streamSSE(
  path: string,
  body: unknown,
  signal?: AbortSignal
): AsyncGenerator<SSEChunk> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'text/event-stream',
    },
    body: JSON.stringify(body),
    signal,
  })

  if (!response.ok) {
    let message = `Stream request failed: ${response.status}`
    try {
      const errBody = (await response.json()) as { error?: string }
      if (errBody.error) message = errBody.error
    } catch {
      // ignore
    }
    throw new ApiError(message, response.status)
  }

  const reader = response.body?.getReader()
  if (!reader) throw new Error('No response body for SSE stream')

  const decoder = new TextDecoder()
  let buffer = ''

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue
        const raw = line.slice(6).trim()
        if (raw === '[DONE]') return
        try {
          const parsed = JSON.parse(raw) as Partial<SSEChunk>
          yield {
            type: parsed.type ?? 'text',
            content: parsed.content ?? '',
            metadata: parsed.metadata ?? {},
          }
        } catch {
          // skip malformed lines
        }
      }
    }
  } finally {
    reader.releaseLock()
  }
}
