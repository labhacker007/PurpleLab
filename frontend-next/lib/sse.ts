/**
 * SSE (Server-Sent Events) client for chat streaming.
 */

export interface SSEMessage {
  event: string
  data: string
}

export type SSECallback = (message: SSEMessage) => void

export function createSSEStream(
  url: string,
  body: unknown,
  onMessage: SSECallback,
  onError?: (error: Error) => void,
  onDone?: () => void
): AbortController {
  const controller = new AbortController()

  async function start() {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })

      if (!response.ok) {
        throw new Error(`SSE request failed: ${response.status}`)
      }

      const reader = response.body?.getReader()
      if (!reader) throw new Error("No response body")

      const decoder = new TextDecoder()
      let buffer = ""

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split("\n")
        buffer = lines.pop() || ""

        let currentEvent = "message"
        for (const line of lines) {
          if (line.startsWith("event: ")) {
            currentEvent = line.slice(7).trim()
          } else if (line.startsWith("data: ")) {
            const data = line.slice(6)
            onMessage({ event: currentEvent, data })
            currentEvent = "message"
          }
        }
      }

      onDone?.()
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        onError?.(err as Error)
      }
    }
  }

  start()
  return controller
}
