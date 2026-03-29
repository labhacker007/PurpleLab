'use client'

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  type KeyboardEvent,
  type ChangeEvent,
} from 'react'
import {
  Plus,
  Send,
  Square,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Trash2,
  Pencil,
  AlertCircle,
  RefreshCw,
  Terminal,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { streamSSE, apiGet, apiDelete, API_BASE } from '@/lib/api/client'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToolCall {
  id: string
  name: string
  args: Record<string, unknown>
}

interface ToolResult {
  tool_call_id: string
  content: unknown
}

interface Message {
  id: string
  role: 'user' | 'assistant' | 'tool_call' | 'tool_result'
  content: string
  type?: string
  tool_call?: ToolCall
  tool_result?: ToolResult
  timestamp: number
}

interface Conversation {
  id: string
  title: string
  created_at: string
  updated_at: string
  message_count: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateId(): string {
  return Math.random().toString(36).slice(2, 11)
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

const ENVIRONMENTS = ['production', 'staging', 'dev', 'isolated'] as const
type Environment = (typeof ENVIRONMENTS)[number]

// ─── Typing indicator ─────────────────────────────────────────────────────────

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1.5 px-4 py-3">
      {[0, 1, 2].map((i) => (
        <span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce"
          style={{ animationDelay: `${i * 150}ms` }}
        />
      ))}
    </div>
  )
}

// ─── Tool call card ───────────────────────────────────────────────────────────

function ToolCallCard({ tool }: { tool: ToolCall }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-xs font-mono overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-yellow-400 hover:bg-yellow-500/10 transition-colors"
      >
        <Terminal className="h-3 w-3 shrink-0" />
        <span className="font-semibold">{tool.name}</span>
        <ChevronDown
          className={cn('h-3 w-3 ml-auto transition-transform', open && 'rotate-180')}
        />
      </button>
      {open && (
        <pre className="border-t border-yellow-500/20 bg-black/30 p-3 text-yellow-300/80 overflow-x-auto whitespace-pre-wrap break-all">
          {JSON.stringify(tool.args, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ─── Tool result card ─────────────────────────────────────────────────────────

function ToolResultCard({ result }: { result: ToolResult }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-xs font-mono overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-emerald-400 hover:bg-emerald-500/10 transition-colors"
      >
        <Check className="h-3 w-3 shrink-0" />
        <span className="font-semibold">Result</span>
        <span className="ml-2 text-emerald-400/60 truncate">— {result.tool_call_id}</span>
        <ChevronDown
          className={cn('h-3 w-3 ml-auto shrink-0 transition-transform', open && 'rotate-180')}
        />
      </button>
      {open && (
        <pre className="border-t border-emerald-500/20 bg-black/30 p-3 text-emerald-300/80 overflow-x-auto whitespace-pre-wrap break-all">
          {typeof result.content === 'string'
            ? result.content
            : JSON.stringify(result.content, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ─── Message bubble ───────────────────────────────────────────────────────────

function MessageBubble({ msg }: { msg: Message }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    void navigator.clipboard.writeText(msg.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  if (msg.role === 'tool_call' && msg.tool_call) {
    return (
      <div className="flex justify-start px-4 py-1">
        <div className="max-w-[80%] w-full">
          <ToolCallCard tool={msg.tool_call} />
        </div>
      </div>
    )
  }

  if (msg.role === 'tool_result' && msg.tool_result) {
    return (
      <div className="flex justify-start px-4 py-1">
        <div className="max-w-[80%] w-full">
          <ToolResultCard result={msg.tool_result} />
        </div>
      </div>
    )
  }

  const isUser = msg.role === 'user'

  return (
    <div className={cn('flex px-4 py-1 group', isUser ? 'justify-end' : 'justify-start')}>
      <div className={cn('max-w-[80%] space-y-1', isUser ? 'items-end flex flex-col' : '')}>
        <div
          className={cn(
            'rounded-2xl px-4 py-2.5 text-sm leading-relaxed whitespace-pre-wrap break-words',
            isUser
              ? 'bg-cyan-600 text-white rounded-br-sm'
              : 'bg-slate-800 text-slate-100 border border-slate-700 rounded-bl-sm'
          )}
        >
          {msg.content}
        </div>
        <div className={cn('flex items-center gap-2', isUser ? 'flex-row-reverse' : '')}>
          <span className="text-[10px] text-slate-500">{formatTime(msg.timestamp)}</span>
          {!isUser && (
            <button
              onClick={handleCopy}
              className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300"
            >
              {copied ? (
                <Check className="h-3 w-3 text-emerald-400" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
              {copied ? 'Copied' : 'Copy'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Conversation sidebar item ────────────────────────────────────────────────

function ConvItem({
  conv,
  active,
  onSelect,
  onDelete,
}: {
  conv: Conversation
  active: boolean
  onSelect: () => void
  onDelete: () => void
}) {
  return (
    <div
      className={cn(
        'group flex items-center gap-2 rounded-lg px-3 py-2 cursor-pointer transition-colors',
        active
          ? 'bg-slate-700 text-white'
          : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
      )}
      onClick={onSelect}
    >
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium truncate">{conv.title || 'Untitled chat'}</div>
        <div className="text-[10px] text-slate-500 mt-0.5">{conv.message_count} msgs</div>
      </div>
      <button
        onClick={(e) => {
          e.stopPropagation()
          onDelete()
        }}
        className="opacity-0 group-hover:opacity-100 shrink-0 rounded p-1 hover:bg-slate-600 text-slate-400 hover:text-red-400 transition-colors"
      >
        <Trash2 className="h-3 w-3" />
      </button>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ChatPage() {
  // Sidebar
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [currentConvId, setCurrentConvId] = useState<string | null>(null)

  // Messages
  const [messages, setMessages] = useState<Message[]>([])
  const [isStreaming, setIsStreaming] = useState(false)
  const [isWaiting, setIsWaiting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Input
  const [input, setInput] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Title editing
  const [editingTitle, setEditingTitle] = useState(false)
  const [titleDraft, setTitleDraft] = useState('')

  // Environment
  const [environment, setEnvironment] = useState<Environment>('dev')

  // Abort controller for stopping stream
  const abortRef = useRef<AbortController | null>(null)

  // Scroll anchor
  const bottomRef = useRef<HTMLDivElement>(null)

  // ── Load conversations ──────────────────────────────────────────────────────

  const loadConversations = useCallback(async () => {
    try {
      const data = await apiGet<Conversation[]>('/api/v2/chat/conversations')
      setConversations(data)
    } catch {
      // API may not be running — silently ignore
    }
  }, [])

  useEffect(() => {
    void loadConversations()
    const saved = localStorage.getItem('purplelab_conv_id')
    if (saved) setCurrentConvId(saved)
  }, [loadConversations])

  // ── Auto-scroll ─────────────────────────────────────────────────────────────

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isWaiting])

  // ── Persist conv ID ─────────────────────────────────────────────────────────

  useEffect(() => {
    if (currentConvId) {
      localStorage.setItem('purplelab_conv_id', currentConvId)
    }
  }, [currentConvId])

  // ── Auto-resize textarea ────────────────────────────────────────────────────

  function resizeTextarea() {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    const lineHeight = 24
    const maxHeight = lineHeight * 6
    el.style.height = `${Math.min(el.scrollHeight, maxHeight)}px`
  }

  function handleInputChange(e: ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value)
    resizeTextarea()
  }

  // ── Send message ────────────────────────────────────────────────────────────

  async function sendMessage() {
    const text = input.trim()
    if (!text || isStreaming) return

    setInput('')
    if (textareaRef.current) textareaRef.current.style.height = 'auto'
    setError(null)

    const userMsg: Message = {
      id: generateId(),
      role: 'user',
      content: text,
      timestamp: Date.now(),
    }
    setMessages((prev) => [...prev, userMsg])
    setIsWaiting(true)
    setIsStreaming(true)

    const controller = new AbortController()
    abortRef.current = controller

    let assistantId = generateId()
    let assistantBuffer = ''
    let firstToken = true
    let newConvId = currentConvId

    try {
      const stream = streamSSE(
        '/api/v2/chat',
        { message: text, conversation_id: currentConvId, environment },
        controller.signal
      )

      for await (const chunk of stream) {
        if (firstToken) {
          setIsWaiting(false)
          firstToken = false
        }

        switch (chunk.type) {
          case 'conversation_id': {
            newConvId = chunk.content
            setCurrentConvId(chunk.content)
            break
          }

          case 'text': {
            assistantBuffer += chunk.content
            const buffered = assistantBuffer
            const aid = assistantId
            setMessages((prev) => {
              const existing = prev.find((m) => m.id === aid)
              if (existing) {
                return prev.map((m) =>
                  m.id === aid ? { ...m, content: buffered } : m
                )
              }
              return [
                ...prev,
                {
                  id: aid,
                  role: 'assistant' as const,
                  content: buffered,
                  timestamp: Date.now(),
                },
              ]
            })
            break
          }

          case 'tool_call': {
            if (assistantBuffer) {
              assistantId = generateId()
              assistantBuffer = ''
            }
            const toolData = chunk.metadata as {
              id?: string
              name?: string
              args?: Record<string, unknown>
            }
            const tc: ToolCall = {
              id: toolData.id ?? generateId(),
              name: toolData.name ?? chunk.content,
              args: toolData.args ?? {},
            }
            setMessages((prev) => [
              ...prev,
              {
                id: generateId(),
                role: 'tool_call' as const,
                content: chunk.content,
                tool_call: tc,
                timestamp: Date.now(),
              },
            ])
            assistantId = generateId()
            break
          }

          case 'tool_result': {
            const trData = chunk.metadata as {
              tool_call_id?: string
              content?: unknown
            }
            const tr: ToolResult = {
              tool_call_id: trData.tool_call_id ?? '',
              content: trData.content ?? chunk.content,
            }
            setMessages((prev) => [
              ...prev,
              {
                id: generateId(),
                role: 'tool_result' as const,
                content: chunk.content,
                tool_result: tr,
                timestamp: Date.now(),
              },
            ])
            assistantId = generateId()
            assistantBuffer = ''
            break
          }

          case 'error': {
            setError(chunk.content || 'An error occurred during streaming.')
            break
          }

          case 'done':
            break
        }
      }
    } catch (err) {
      if ((err as Error).name !== 'AbortError') {
        setError(err instanceof Error ? err.message : 'Stream failed')
      }
    } finally {
      setIsWaiting(false)
      setIsStreaming(false)
      abortRef.current = null
      if (newConvId) void loadConversations()
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      void sendMessage()
    }
  }

  function stopStreaming() {
    abortRef.current?.abort()
  }

  // ── New chat ─────────────────────────────────────────────────────────────────

  function startNewChat() {
    setCurrentConvId(null)
    setMessages([])
    setError(null)
    localStorage.removeItem('purplelab_conv_id')
  }

  // ── Select conversation ───────────────────────────────────────────────────────

  async function selectConversation(id: string) {
    setCurrentConvId(id)
    setMessages([])
    setError(null)
    try {
      const data = await apiGet<{ messages: Message[] }>(
        `/api/v2/chat/conversations/${id}`
      )
      setMessages(
        data.messages.map((m) => ({ ...m, id: m.id ?? generateId() }))
      )
    } catch {
      // ignore if API unavailable
    }
  }

  // ── Delete conversation ───────────────────────────────────────────────────────

  async function deleteConversation(id: string) {
    try {
      await apiDelete(`/api/v2/chat/conversations/${id}`)
    } catch {
      // ignore
    }
    setConversations((prev) => prev.filter((c) => c.id !== id))
    if (currentConvId === id) startNewChat()
  }

  // ── Title editing ─────────────────────────────────────────────────────────────

  function startEditTitle() {
    const conv = conversations.find((c) => c.id === currentConvId)
    setTitleDraft(conv?.title ?? 'Untitled chat')
    setEditingTitle(true)
  }

  function commitTitle() {
    if (!currentConvId) return
    setConversations((prev) =>
      prev.map((c) => (c.id === currentConvId ? { ...c, title: titleDraft } : c))
    )
    setEditingTitle(false)
    void fetch(`${API_BASE}/api/v2/chat/conversations/${currentConvId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: titleDraft }),
    }).catch(() => null)
  }

  const currentTitle =
    conversations.find((c) => c.id === currentConvId)?.title ?? 'New Chat'

  return (
    <div className="flex h-full overflow-hidden bg-slate-950">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside
        className={cn(
          'flex flex-col border-r border-slate-800 bg-slate-900 transition-all duration-300 shrink-0',
          sidebarOpen ? 'w-64' : 'w-0 overflow-hidden'
        )}
      >
        <div className="flex h-12 items-center justify-between border-b border-slate-800 px-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Conversations
          </span>
          <button
            onClick={startNewChat}
            className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-cyan-400 hover:bg-slate-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            New
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
          {conversations.length === 0 ? (
            <p className="px-3 py-4 text-xs text-slate-600 text-center">
              No conversations yet
            </p>
          ) : (
            conversations.map((conv) => (
              <ConvItem
                key={conv.id}
                conv={conv}
                active={conv.id === currentConvId}
                onSelect={() => void selectConversation(conv.id)}
                onDelete={() => void deleteConversation(conv.id)}
              />
            ))
          )}
        </div>
      </aside>

      {/* ── Main area ───────────────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col min-w-0">
        {/* Top bar */}
        <header className="flex h-12 shrink-0 items-center gap-2 border-b border-slate-800 bg-slate-900 px-4">
          <button
            onClick={() => setSidebarOpen((v) => !v)}
            className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          >
            {sidebarOpen ? (
              <ChevronLeft className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>

          {editingTitle ? (
            <input
              autoFocus
              value={titleDraft}
              onChange={(e) => setTitleDraft(e.target.value)}
              onBlur={commitTitle}
              onKeyDown={(e) => {
                if (e.key === 'Enter') commitTitle()
                if (e.key === 'Escape') setEditingTitle(false)
              }}
              className="flex-1 bg-slate-800 text-sm text-slate-100 rounded-md px-2 py-0.5 border border-slate-600 focus:outline-none focus:border-cyan-500"
            />
          ) : (
            <button
              onClick={startEditTitle}
              className="flex items-center gap-1.5 text-sm font-medium text-slate-200 hover:text-white group"
            >
              <span>{currentTitle}</span>
              <Pencil className="h-3 w-3 text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>
          )}

          <div className="ml-auto flex items-center gap-2">
            <select
              value={environment}
              onChange={(e) => setEnvironment(e.target.value as Environment)}
              className="h-7 rounded-md border border-slate-700 bg-slate-800 px-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              {ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>

            <button
              onClick={() => void loadConversations()}
              className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
        </header>

        {/* Message area */}
        <div className="flex-1 overflow-y-auto py-4 space-y-1">
          {messages.length === 0 && !isWaiting && (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-center px-8">
              <div className="h-12 w-12 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                <Terminal className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-300">PurpleLab Agent</p>
                <p className="text-xs text-slate-500 mt-1">
                  Ask about threats, generate simulations, analyze logs, or run detections.
                </p>
              </div>
            </div>
          )}

          {messages.map((msg) => (
            <MessageBubble key={msg.id} msg={msg} />
          ))}

          {isWaiting && (
            <div className="flex justify-start px-4 py-1">
              <div className="bg-slate-800 border border-slate-700 rounded-2xl rounded-bl-sm">
                <TypingIndicator />
              </div>
            </div>
          )}

          {error && (
            <div className="mx-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-xs text-red-300">{error}</p>
              </div>
              <button
                onClick={() => {
                  setError(null)
                  void sendMessage()
                }}
                className="text-xs text-red-400 hover:text-red-300 shrink-0 flex items-center gap-1"
              >
                <RefreshCw className="h-3 w-3" />
                Retry
              </button>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Input bar */}
        <div className="shrink-0 border-t border-slate-800 bg-slate-900 p-4">
          <div className="flex items-end gap-2 rounded-xl border border-slate-700 bg-slate-800 px-3 py-2 focus-within:border-cyan-500/50 transition-colors">
            <textarea
              ref={textareaRef}
              rows={1}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              placeholder="Message the agent… (Enter to send, Shift+Enter for newline)"
              disabled={isStreaming}
              className="flex-1 resize-none bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none min-h-[24px] max-h-[144px]"
              style={{ lineHeight: '24px' }}
            />
            {isStreaming ? (
              <button
                onClick={stopStreaming}
                className="mb-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
                title="Stop generation"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
              </button>
            ) : (
              <button
                onClick={() => void sendMessage()}
                disabled={!input.trim()}
                className="mb-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                title="Send message"
              >
                {isWaiting ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Send className="h-3.5 w-3.5" />
                )}
              </button>
            )}
          </div>
          <p className="mt-1.5 text-[10px] text-slate-600 text-center">
            Environment: <span className="text-slate-500">{environment}</span>
            {currentConvId && (
              <>
                {' '}· Conv:{' '}
                <span className="font-mono text-slate-500">
                  {currentConvId.slice(0, 8)}…
                </span>
              </>
            )}
          </p>
        </div>
      </div>
    </div>
  )
}
