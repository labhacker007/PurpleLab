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
  X,
  Wrench,
  Clock,
  Zap,
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

function timeAgo(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000)
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function approxTokens(text: string): number {
  return Math.max(1, Math.round(text.length / 4))
}

const ENVIRONMENTS = ['production', 'staging', 'dev', 'isolated'] as const
type Environment = (typeof ENVIRONMENTS)[number]

const SUGGESTED_PROMPTS = [
  'Run Mimikatz simulation',
  'Show my coverage gaps',
  'Generate Sigma rule for T1059.001',
  'List active sessions',
  'What use cases are failing?',
  'Research APT29 TTPs',
]

// ─── Inline markdown renderer ─────────────────────────────────────────────────
// Renders **bold**, *italic*, `inline code` without a library.

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = []
  // Split on bold (**...**), italic (*...*), inline code (`...`)
  const regex = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g
  let last = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) {
      parts.push(text.slice(last, match.index))
    }
    const raw = match[0]
    if (raw.startsWith('**')) {
      parts.push(<strong key={match.index} className="font-semibold text-white">{raw.slice(2, -2)}</strong>)
    } else if (raw.startsWith('*')) {
      parts.push(<em key={match.index} className="italic text-slate-200">{raw.slice(1, -1)}</em>)
    } else {
      parts.push(
        <code key={match.index} className="bg-slate-700 text-cyan-300 rounded px-1 py-0.5 text-[11px] font-mono">
          {raw.slice(1, -1)}
        </code>
      )
    }
    last = match.index + raw.length
  }

  if (last < text.length) {
    parts.push(text.slice(last))
  }

  return parts
}

// ─── Code block renderer ──────────────────────────────────────────────────────

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    void navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="my-2 rounded-lg border border-slate-700 overflow-hidden">
      <div className="flex items-center justify-between bg-slate-800 px-3 py-1.5 border-b border-slate-700">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
          {lang || 'code'}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="bg-slate-900 p-3 overflow-x-auto text-[12px] text-slate-200 font-mono whitespace-pre-wrap break-all">
        {code}
      </pre>
    </div>
  )
}

// ─── Message content renderer (handles code fences + inline markdown) ─────────

function MessageContent({ content }: { content: string }) {
  // Split out ```lang\n...\n``` blocks
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g
  const segments: React.ReactNode[] = []
  let last = 0
  let match: RegExpExecArray | null

  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > last) {
      const textPart = content.slice(last, match.index)
      segments.push(
        <span key={`text-${last}`}>{renderInlineMarkdown(textPart)}</span>
      )
    }
    segments.push(
      <CodeBlock key={`code-${match.index}`} lang={match[1]} code={match[2].trimEnd()} />
    )
    last = match.index + match[0].length
  }

  if (last < content.length) {
    segments.push(
      <span key={`text-${last}`}>{renderInlineMarkdown(content.slice(last))}</span>
    )
  }

  return <>{segments}</>
}

// ─── Typing indicator ─────────────────────────────────────────────────────────

function TypingIndicator({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-3">
      <div className="flex items-center gap-1.5">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce"
            style={{ animationDelay: `${i * 150}ms` }}
          />
        ))}
      </div>
      {label && <span className="text-[11px] text-slate-500 italic">{label}</span>}
    </div>
  )
}

// ─── Tool call card ───────────────────────────────────────────────────────────

function ToolCallCard({ tool, inFlight }: { tool: ToolCall; inFlight?: boolean }) {
  const [open, setOpen] = useState(false)

  const argsStr = JSON.stringify(tool.args, null, 2)
  const preview = `${tool.name}(${JSON.stringify(tool.args).slice(0, 60)}${JSON.stringify(tool.args).length > 60 ? '…' : ''})`

  return (
    <div className="rounded-lg border border-violet-500/30 bg-slate-800 text-xs font-mono overflow-hidden border-l-2 border-l-violet-500">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-violet-300 hover:bg-slate-700/50 transition-colors"
      >
        <Wrench className={cn('h-3 w-3 shrink-0', inFlight && 'animate-pulse text-yellow-400')} />
        <span className="text-violet-200 font-semibold">
          {inFlight ? 'Using tool: ' : ''}
          <span className="text-yellow-300">🔧</span>{' '}
          {preview}
        </span>
        <ChevronDown
          className={cn('h-3 w-3 ml-auto shrink-0 transition-transform text-slate-500', open && 'rotate-180')}
        />
      </button>
      {open && (
        <pre className="border-t border-violet-500/20 bg-black/30 p-3 text-violet-200/80 overflow-x-auto whitespace-pre-wrap break-all">
          {argsStr}
        </pre>
      )}
    </div>
  )
}

// ─── Tool result card ─────────────────────────────────────────────────────────

function ToolResultCard({ result }: { result: ToolResult }) {
  const [open, setOpen] = useState(false)

  const raw =
    typeof result.content === 'string'
      ? result.content
      : JSON.stringify(result.content, null, 2)

  const isError = raw.toLowerCase().startsWith('error')
  const preview = raw.slice(0, 200)
  const needsExpand = raw.length > 200

  return (
    <div
      className={cn(
        'rounded-lg border text-xs font-mono overflow-hidden border-l-2',
        isError
          ? 'border-red-500/30 bg-slate-800 border-l-red-500'
          : 'border-emerald-500/30 bg-slate-800 border-l-emerald-500'
      )}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'flex w-full items-center gap-2 px-3 py-2 transition-colors',
          isError
            ? 'text-red-400 hover:bg-red-500/10'
            : 'text-emerald-400 hover:bg-emerald-500/10'
        )}
      >
        {isError ? (
          <AlertCircle className="h-3 w-3 shrink-0" />
        ) : (
          <Check className="h-3 w-3 shrink-0" />
        )}
        <span
          className={cn(
            'font-semibold',
            isError ? 'text-red-400' : 'text-emerald-400'
          )}
        >
          {isError ? 'Error' : 'Result'}
        </span>
        <span
          className={cn(
            'ml-2 truncate max-w-[40ch]',
            isError ? 'text-red-300/60' : 'text-emerald-300/60'
          )}
        >
          — {preview}{needsExpand && !open ? '…' : ''}
        </span>
        <ChevronDown
          className={cn(
            'h-3 w-3 ml-auto shrink-0 transition-transform text-slate-500',
            open && 'rotate-180'
          )}
        />
      </button>
      {open && (
        <pre
          className={cn(
            'border-t bg-black/30 p-3 overflow-x-auto whitespace-pre-wrap break-all',
            isError
              ? 'border-red-500/20 text-red-300/80'
              : 'border-emerald-500/20 text-emerald-300/80'
          )}
        >
          {raw}
        </pre>
      )}
    </div>
  )
}

// ─── Message bubble ───────────────────────────────────────────────────────────

function MessageBubble({
  msg,
  isLast,
  onRegenerate,
}: {
  msg: Message
  isLast: boolean
  onRegenerate?: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [showTime, setShowTime] = useState(false)

  function handleCopy() {
    void navigator.clipboard.writeText(msg.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  if (msg.role === 'tool_call' && msg.tool_call) {
    return (
      <div className="flex justify-start px-4 py-1">
        <div className="max-w-[85%] w-full">
          <ToolCallCard tool={msg.tool_call} />
        </div>
      </div>
    )
  }

  if (msg.role === 'tool_result' && msg.tool_result) {
    return (
      <div className="flex justify-start px-4 py-1">
        <div className="max-w-[85%] w-full">
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
            'rounded-2xl px-4 py-2.5 text-sm leading-relaxed break-words',
            isUser
              ? 'bg-cyan-600 text-white rounded-br-sm whitespace-pre-wrap'
              : 'bg-slate-800 text-slate-100 border border-slate-700 rounded-bl-sm'
          )}
        >
          {isUser ? (
            msg.content
          ) : (
            <MessageContent content={msg.content} />
          )}
        </div>

        {/* Footer row: timestamp + actions */}
        <div
          className={cn(
            'flex items-center gap-2',
            isUser ? 'flex-row-reverse' : ''
          )}
        >
          <button
            onClick={() => setShowTime((v) => !v)}
            className="flex items-center gap-1 text-[10px] text-slate-600 hover:text-slate-400 transition-colors"
          >
            <Clock className="h-2.5 w-2.5" />
            <span>{showTime ? formatTime(msg.timestamp) : timeAgo(msg.timestamp)}</span>
          </button>

          {!isUser && (
            <>
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

              {isLast && onRegenerate && (
                <button
                  onClick={onRegenerate}
                  className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-[10px] text-slate-500 hover:text-cyan-400"
                >
                  <RefreshCw className="h-3 w-3" />
                  Regenerate
                </button>
              )}

              <span className="opacity-0 group-hover:opacity-100 text-[10px] text-slate-600 transition-opacity">
                ~{approxTokens(msg.content)} tokens
              </span>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Suggested prompts ────────────────────────────────────────────────────────

function SuggestedPrompts({ onSelect }: { onSelect: (p: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2 justify-center px-4 pb-3">
      {SUGGESTED_PROMPTS.map((prompt) => (
        <button
          key={prompt}
          onClick={() => onSelect(prompt)}
          className="flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-[11px] text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 hover:bg-slate-700/60 transition-all"
        >
          <Zap className="h-2.5 w-2.5 text-cyan-500/60" />
          {prompt}
        </button>
      ))}
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
        <div className="text-[10px] text-slate-500 mt-0.5">
          {conv.message_count} msgs
          {conv.updated_at && (
            <> · {timeAgo(new Date(conv.updated_at).getTime())}</>
          )}
        </div>
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
  const [activeTool, setActiveTool] = useState<string | null>(null)
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

  // Last user message for regenerate
  const lastUserMsgRef = useRef<string>('')

  // Scroll anchor
  const bottomRef = useRef<HTMLDivElement>(null)

  // Token counter for footer
  const totalTokens = messages
    .filter((m) => m.role === 'assistant')
    .reduce((acc, m) => acc + approxTokens(m.content), 0)

  // ── Load conversations ──────────────────────────────────────────────────────

  const loadConversations = useCallback(async () => {
    try {
      const raw = await apiGet<Conversation[] | { conversations: Conversation[] }>('/api/v2/chat/conversations')
      const list = Array.isArray(raw) ? raw : (raw.conversations ?? [])
      setConversations(list)
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
  }, [messages, isWaiting, activeTool])

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

  // ── Core send / stream ──────────────────────────────────────────────────────

  async function sendMessage(overrideText?: string) {
    const text = (overrideText ?? input).trim()
    if (!text || isStreaming) return

    if (!overrideText) {
      setInput('')
      if (textareaRef.current) textareaRef.current.style.height = 'auto'
    }
    setError(null)
    lastUserMsgRef.current = text

    const userMsg: Message = {
      id: generateId(),
      role: 'user',
      content: text,
      timestamp: Date.now(),
    }
    setMessages((prev) => [...prev, userMsg])
    setIsWaiting(true)
    setIsStreaming(true)
    setActiveTool(null)

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
            setActiveTool(null)
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
            // Backend sends: metadata.tool_name, metadata.arguments, metadata.tool_use_id
            const meta = chunk.metadata as {
              tool_name?: string
              arguments?: Record<string, unknown>
              tool_use_id?: string
              // Legacy field names for compatibility
              id?: string
              name?: string
              args?: Record<string, unknown>
            }
            const toolName = meta.tool_name ?? meta.name ?? chunk.content ?? 'unknown'
            const toolArgs = meta.arguments ?? meta.args ?? {}
            const toolId = meta.tool_use_id ?? meta.id ?? generateId()

            const tc: ToolCall = {
              id: toolId,
              name: toolName,
              args: toolArgs,
            }
            setActiveTool(toolName)
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
            setActiveTool(null)
            const trMeta = chunk.metadata as {
              tool_use_id?: string
              result?: unknown
              tool_name?: string
              // Legacy
              tool_call_id?: string
              content?: unknown
            }
            const tr: ToolResult = {
              tool_call_id: trMeta.tool_use_id ?? trMeta.tool_call_id ?? '',
              content: trMeta.result ?? trMeta.content ?? chunk.content,
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
            setActiveTool(null)
            break
          }

          case 'done':
            setActiveTool(null)
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
      setActiveTool(null)
      abortRef.current = null
      if (newConvId) void loadConversations()
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    // Ctrl+Enter or plain Enter (without Shift) submits
    if (e.key === 'Enter' && (e.ctrlKey || !e.shiftKey)) {
      e.preventDefault()
      void sendMessage()
    }
    // Shift+Enter → natural newline (default behavior, no override needed)
  }

  function stopStreaming() {
    abortRef.current?.abort()
  }

  function handleSuggestedPrompt(prompt: string) {
    setInput(prompt)
    // Small delay so textarea renders before submit
    setTimeout(() => void sendMessage(prompt), 0)
  }

  function handleRegenerate() {
    if (!lastUserMsgRef.current || isStreaming) return
    // Remove last assistant message(s) up to last user message
    setMessages((prev) => {
      const lastUserIdx = [...prev].reverse().findIndex((m) => m.role === 'user')
      if (lastUserIdx === -1) return prev
      return prev.slice(0, prev.length - lastUserIdx)
    })
    void sendMessage(lastUserMsgRef.current)
  }

  // ── New chat ─────────────────────────────────────────────────────────────────

  function startNewChat() {
    setCurrentConvId(null)
    setMessages([])
    setError(null)
    setActiveTool(null)
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

  const hasMessages = messages.length > 0

  // Index of last assistant message for regenerate button
  const lastAssistantIdx = [...messages].reverse().findIndex((m) => m.role === 'assistant')
  const lastAssistantId =
    lastAssistantIdx !== -1 ? messages[messages.length - 1 - lastAssistantIdx].id : null

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
          {!hasMessages && !isWaiting && (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-8">
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

          {messages.map((msg) => {
            const isLastAssistant = msg.id === lastAssistantId
            return (
              <MessageBubble
                key={msg.id}
                msg={msg}
                isLast={isLastAssistant && !isStreaming}
                onRegenerate={isLastAssistant && !isStreaming ? handleRegenerate : undefined}
              />
            )
          })}

          {/* Waiting for first token */}
          {isWaiting && (
            <div className="flex justify-start px-4 py-1">
              <div className="bg-slate-800 border border-slate-700 rounded-2xl rounded-bl-sm">
                <TypingIndicator label="Agent is thinking…" />
              </div>
            </div>
          )}

          {/* Active tool in-flight indicator */}
          {activeTool && !isWaiting && (
            <div className="flex justify-start px-4 py-1">
              <div className="flex items-center gap-2 rounded-lg border border-violet-500/20 bg-slate-800/60 px-3 py-2 text-xs text-violet-300">
                <Wrench className="h-3 w-3 animate-pulse text-yellow-400" />
                <span>Using tool: <span className="font-mono font-semibold text-yellow-300">{activeTool}</span></span>
                <Loader2 className="h-3 w-3 animate-spin text-slate-500 ml-1" />
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
                  if (lastUserMsgRef.current) void sendMessage(lastUserMsgRef.current)
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

        {/* Suggested prompts — only shown before first message */}
        {!hasMessages && !isStreaming && (
          <SuggestedPrompts onSelect={handleSuggestedPrompt} />
        )}

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

            {/* Clear button */}
            {input && !isStreaming && (
              <button
                onClick={() => {
                  setInput('')
                  if (textareaRef.current) textareaRef.current.style.height = 'auto'
                  textareaRef.current?.focus()
                }}
                className="mb-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-700 text-slate-400 hover:bg-slate-600 hover:text-slate-200 transition-colors"
                title="Clear input"
              >
                <X className="h-3 w-3" />
              </button>
            )}

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
                title="Send message (Ctrl+Enter)"
              >
                {isWaiting ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Send className="h-3.5 w-3.5" />
                )}
              </button>
            )}
          </div>

          {/* Footer status line */}
          <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-600">
            <span>
              Environment: <span className="text-slate-500">{environment}</span>
              {currentConvId && (
                <>
                  {' '}· Conv:{' '}
                  <span className="font-mono text-slate-500">
                    {currentConvId.slice(0, 8)}…
                  </span>
                </>
              )}
              {totalTokens > 0 && (
                <> · ~{totalTokens} tokens</>
              )}
            </span>
            {input.length > 500 && (
              <span className={cn(
                'font-mono',
                input.length > 2000 ? 'text-red-400' : input.length > 1000 ? 'text-yellow-500' : 'text-slate-500'
              )}>
                {input.length} chars
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
