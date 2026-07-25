'use client'

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  Suspense,
  type KeyboardEvent,
  type ChangeEvent,
} from 'react'
import { useSearchParams } from 'next/navigation'
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
  Target,
  Shield,
  Users,
  BarChart2,
  ChevronRight as ArrowRight,
  PanelRight,
  MapPin,
  Cpu,
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
  goal?: string
  context_state?: ContextState
  created_at: string
  updated_at: string
  message_count: number
}

interface WorkingSet {
  session_ids?: string[]
  rule_ids?: string[]
  use_case_ids?: string[]
  technique_ids?: string[]
  scenario_ids?: string[]
}

interface ContextState {
  environment_id?: string
  environment_name?: string
  goal?: string
  active_session_id?: string
  working_set?: WorkingSet
  last_tool?: string
  suggested_followups?: string[]
}

interface ActionLogEntry {
  id: string
  type: 'tool_call' | 'tool_result'
  name: string
  data: unknown
  timestamp: number
}

// ─── Goal config ──────────────────────────────────────────────────────────────

const GOAL_PRESETS = [
  {
    id: 'red_team',
    label: 'Red Team Exercise',
    description: 'Simulate an APT attack and measure detection coverage end-to-end',
    icon: Target,
    color: 'text-red-400',
    border: 'border-red-500/30 hover:border-red-500/60',
    bg: 'bg-red-500/5 hover:bg-red-500/10',
    bootstrapMessage: 'I want to run a red team exercise. Help me pick a threat profile and simulate an attack to test our detections.',
  },
  {
    id: 'detection_validation',
    label: 'Validate Detections',
    description: 'Test specific detection rules against simulated traffic to find gaps',
    icon: Shield,
    color: 'text-cyan-400',
    border: 'border-cyan-500/30 hover:border-cyan-500/60',
    bg: 'bg-cyan-500/5 hover:bg-cyan-500/10',
    bootstrapMessage: 'I want to validate my detection rules. Show me what use cases are failing and help me fix coverage gaps.',
  },
  {
    id: 'tabletop',
    label: 'Tabletop Exercise',
    description: 'Walk through an adversary scenario interactively, step by step',
    icon: Users,
    color: 'text-violet-400',
    border: 'border-violet-500/30 hover:border-violet-500/60',
    bg: 'bg-violet-500/5 hover:bg-violet-500/10',
    bootstrapMessage: 'Let\'s run a tabletop exercise. I want to walk through an adversary scenario step-by-step and identify detection and response gaps.',
  },
  {
    id: 'coverage',
    label: 'Coverage Analysis',
    description: 'Measure your MITRE ATT&CK coverage and prioritise what to build next',
    icon: BarChart2,
    color: 'text-amber-400',
    border: 'border-amber-500/30 hover:border-amber-500/60',
    bg: 'bg-amber-500/5 hover:bg-amber-500/10',
    bootstrapMessage: 'Show me my current detection coverage. I want to see my DES and IHDS scores, the biggest gaps, and a prioritised plan to improve coverage.',
  },
]

const GOAL_LABELS: Record<string, string> = {
  red_team: 'Red Team',
  detection_validation: 'Validate Detections',
  tabletop: 'Tabletop',
  coverage: 'Coverage Analysis',
  free: 'Open Exploration',
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

// ─── Inline markdown renderer ─────────────────────────────────────────────────

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = []
  const regex = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g
  let last = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index))
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
  if (last < text.length) parts.push(text.slice(last))
  return parts
}

// ─── Code block ───────────────────────────────────────────────────────────────

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="my-2 rounded-lg border border-slate-700 overflow-hidden">
      <div className="flex items-center justify-between bg-slate-800 px-3 py-1.5 border-b border-slate-700">
        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">{lang || 'code'}</span>
        <button
          onClick={() => { void navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
          className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="bg-slate-900 p-3 overflow-x-auto text-[12px] text-slate-200 font-mono whitespace-pre-wrap break-all">{code}</pre>
    </div>
  )
}

function MessageContent({ content }: { content: string }) {
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/g
  const segments: React.ReactNode[] = []
  let last = 0
  let match: RegExpExecArray | null
  while ((match = codeBlockRegex.exec(content)) !== null) {
    if (match.index > last) segments.push(<span key={`t-${last}`}>{renderInlineMarkdown(content.slice(last, match.index))}</span>)
    segments.push(<CodeBlock key={`c-${match.index}`} lang={match[1]} code={match[2].trimEnd()} />)
    last = match.index + match[0].length
  }
  if (last < content.length) segments.push(<span key={`t-${last}`}>{renderInlineMarkdown(content.slice(last))}</span>)
  return <>{segments}</>
}

// ─── Typing indicator ─────────────────────────────────────────────────────────

function TypingIndicator({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-3">
      <div className="flex items-center gap-1.5">
        {[0, 1, 2].map((i) => (
          <span key={i} className="h-1.5 w-1.5 rounded-full bg-slate-400 animate-bounce" style={{ animationDelay: `${i * 150}ms` }} />
        ))}
      </div>
      {label && <span className="text-[11px] text-slate-500 italic">{label}</span>}
    </div>
  )
}

// ─── Evidence chain ──────────────────────────────────────────────────────────

interface EvidenceStep {
  callId: string
  toolName: string
  args: Record<string, unknown>
  result: unknown
  isError: boolean
  timestamp: number
}

interface DisplayGroup {
  id: string
  kind: 'user' | 'assistant'
  msg: Message
  evidenceSteps: EvidenceStep[]
}

/** Map tool function names to short human-readable labels. */
const TOOL_LABELS: Record<string, string> = {
  list_environments: 'Listed environments',
  get_environment: 'Fetched environment',
  create_environment: 'Created environment',
  quick_environment_setup: 'Set up environment',
  list_environment_templates: 'Listed templates',
  configure_environment: 'Configured environment',
  apply_threat_profile: 'Applied threat profile',
  list_scenarios: 'Searched scenarios',
  run_scenario: 'Ran scenario',
  list_use_cases: 'Listed use cases',
  get_use_case_coverage: 'Checked coverage',
  get_failing_use_cases: 'Found failing detections',
  create_use_case: 'Created use case',
  run_use_case: 'Ran detection test',
  run_all_use_cases: 'Ran all detection tests',
  get_des_score: 'Fetched DES score',
  get_ihds_score: 'Fetched IHDS score',
  get_scoring_gap_analysis: 'Analysed coverage gaps',
  get_scoring_breakdown: 'Got scoring breakdown',
  generate_report: 'Generated report',
  get_session_report: 'Fetched session report',
  list_pipelines: 'Listed pipelines',
  run_pipeline: 'Ran pipeline',
  get_pipeline_coverage_gaps: 'Found pipeline gaps',
  list_threat_profiles: 'Listed threat profiles',
  tip_search: 'Searched threat intel',
  list_siem_connections: 'Listed SIEM connections',
  connect_siem: 'Connected SIEM',
  save_context: 'Saved context',
  list_sessions: 'Listed sessions',
  get_session: 'Fetched session',
}

function extractResultSummary(toolName: string, result: unknown): string {
  if (result == null) return ''
  let d: Record<string, unknown>
  try {
    d = typeof result === 'string' ? JSON.parse(result) : (result as Record<string, unknown>)
    d = (d?.data as Record<string, unknown>) ?? d
  } catch { return '' }

  switch (toolName) {
    case 'quick_environment_setup':
      return `"${d?.environment_name ?? ''}" · ${d?.technique_count ?? 0} TTPs`
    case 'create_environment':
      return `"${d?.name ?? ''}"`
    case 'list_environments':
      return `${d?.total ?? 0} environment${(d?.total as number) !== 1 ? 's' : ''}`
    case 'apply_threat_profile':
      return `${d?.technique_count ?? (Array.isArray(d?.technique_ids) ? d.technique_ids.length : 0)} TTPs`
    case 'run_scenario':
    case 'get_session':
      return d?.id ? `session ${String(d.id).slice(0, 8)}` : ''
    case 'get_des_score':
      return `DES ${d?.score ?? '?'}%`
    case 'get_ihds_score':
      return `IHDS ${d?.score ?? '?'}%`
    case 'get_scoring_gap_analysis': {
      const gaps = Array.isArray(d?.gaps) ? d.gaps.length : d?.gap_count ?? '?'
      return `${gaps} gaps found`
    }
    case 'list_use_cases':
    case 'get_failing_use_cases': {
      const items = Array.isArray(d?.use_cases) ? d.use_cases.length : d?.total ?? '?'
      return `${items} use case${items !== 1 ? 's' : ''}`
    }
    case 'run_use_case':
      return d?.status === 'passed' ? 'Passed ✓' : d?.status === 'failed' ? 'Failed ✗' : ''
    case 'generate_report':
      return d?.report_id ? `ID ${String(d.report_id).slice(0, 8)}` : ''
    case 'list_environment_templates':
      return `${d?.total ?? 0} templates`
    default:
      if (d?.status === 'error' || d?.message?.toString().toLowerCase().startsWith('error')) return ''
      if (typeof d?.name === 'string') return `"${d.name}"`
      if (typeof d?.total === 'number') return `${d.total} results`
      return ''
  }
}

/**
 * Group the flat messages array into display groups:
 * consecutive tool_call / tool_result messages are bundled
 * with the assistant message that follows them.
 */
function groupMessages(messages: Message[]): DisplayGroup[] {
  const groups: DisplayGroup[] = []
  let i = 0
  while (i < messages.length) {
    const msg = messages[i]
    if (msg.role === 'user') {
      groups.push({ id: msg.id, kind: 'user', msg, evidenceSteps: [] })
      i++
      continue
    }
    if (msg.role === 'tool_call' || msg.role === 'tool_result') {
      // Collect the entire tool exchange for this turn
      const callMap = new Map<string, { toolName: string; args: Record<string, unknown>; ts: number }>()
      const resultMap = new Map<string, { content: unknown; ts: number }>()
      const order: string[] = []
      while (i < messages.length && (messages[i].role === 'tool_call' || messages[i].role === 'tool_result')) {
        const m = messages[i]
        if (m.role === 'tool_call' && m.tool_call) {
          callMap.set(m.tool_call.id, { toolName: m.tool_call.name, args: m.tool_call.args, ts: m.timestamp })
          if (!order.includes(m.tool_call.id)) order.push(m.tool_call.id)
        } else if (m.role === 'tool_result' && m.tool_result) {
          resultMap.set(m.tool_result.tool_call_id, { content: m.tool_result.content, ts: m.timestamp })
          if (!order.includes(m.tool_result.tool_call_id)) order.push(m.tool_result.tool_call_id)
        }
        i++
      }
      const evidenceSteps: EvidenceStep[] = order.map(id => {
        const call = callMap.get(id)
        const res = resultMap.get(id)
        const raw = res?.content
        const rawStr = typeof raw === 'string' ? raw : JSON.stringify(raw ?? {})
        return {
          callId: id,
          toolName: call?.toolName ?? '?',
          args: call?.args ?? {},
          result: raw,
          isError: rawStr.toLowerCase().startsWith('error'),
          timestamp: call?.ts ?? res?.ts ?? 0,
        }
      })
      // Associate with the next assistant message (if already arrived)
      if (i < messages.length && messages[i].role === 'assistant') {
        groups.push({ id: messages[i].id, kind: 'assistant', msg: messages[i], evidenceSteps })
        i++
      } else {
        // Still streaming — show evidence without the final text yet
        const placeholder: Message = { id: `pending-${Date.now()}`, role: 'assistant', content: '', timestamp: Date.now() }
        groups.push({ id: placeholder.id, kind: 'assistant', msg: placeholder, evidenceSteps })
      }
      continue
    }
    if (msg.role === 'assistant') {
      groups.push({ id: msg.id, kind: 'assistant', msg, evidenceSteps: [] })
      i++
    } else {
      i++ // skip unknown
    }
  }
  return groups
}

// ── Evidence step row ─────────────────────────────────────────────────────────

function EvidenceStepRow({ step, index }: { step: EvidenceStep; index: number }) {
  const [expanded, setExpanded] = useState(false)
  const label = TOOL_LABELS[step.toolName] ?? step.toolName.replace(/_/g, ' ')
  const summary = extractResultSummary(step.toolName, step.result)
  const rawStr = typeof step.result === 'string' ? step.result : JSON.stringify(step.result ?? {}, null, 2)
  const argsStr = JSON.stringify(step.args, null, 2)

  return (
    <div className={cn(
      'rounded border-l-2 overflow-hidden text-[11px] font-mono',
      step.isError ? 'border-l-red-500/60 bg-red-500/5' : 'border-l-violet-500/40 bg-slate-800/30'
    )}>
      <button
        onClick={() => setExpanded(v => !v)}
        className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left hover:bg-slate-700/30 transition-colors"
      >
        <span className="text-slate-600 shrink-0 w-4 text-center">{index + 1}.</span>
        {step.isError
          ? <AlertCircle className="h-3 w-3 text-red-400 shrink-0" />
          : <Check className="h-3 w-3 text-emerald-400 shrink-0" />
        }
        <span className={cn('font-medium', step.isError ? 'text-red-300' : 'text-slate-200')}>{label}</span>
        {summary && !step.isError && (
          <span className="text-slate-500 truncate">— {summary}</span>
        )}
        <ChevronDown className={cn('h-3 w-3 ml-auto shrink-0 text-slate-600 transition-transform', expanded && 'rotate-180')} />
      </button>
      {expanded && (
        <div className="border-t border-slate-700/40 px-2.5 py-2 space-y-2">
          {Object.keys(step.args).length > 0 && (
            <div>
              <p className="text-[10px] text-slate-600 mb-1 uppercase tracking-wide">Input</p>
              <pre className="text-slate-400 whitespace-pre-wrap break-all text-[10px] bg-black/20 rounded p-1.5 overflow-x-auto">{argsStr}</pre>
            </div>
          )}
          <div>
            <p className="text-[10px] text-slate-600 mb-1 uppercase tracking-wide">Output</p>
            <pre className={cn('whitespace-pre-wrap break-all text-[10px] bg-black/20 rounded p-1.5 overflow-x-auto max-h-48', step.isError ? 'text-red-300/80' : 'text-emerald-300/70')}>{rawStr}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Turn evidence chain ───────────────────────────────────────────────────────

function TurnEvidenceChain({ steps }: { steps: EvidenceStep[] }) {
  const [open, setOpen] = useState(false)
  if (!steps.length) return null
  const errorCount = steps.filter(s => s.isError).length
  return (
    <div className="mb-1.5 w-full max-w-[80%]">
      <button
        onClick={() => setOpen(v => !v)}
        className={cn(
          'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition-colors',
          errorCount > 0
            ? 'border-red-500/30 bg-red-500/5 text-red-400 hover:bg-red-500/10'
            : 'border-violet-500/20 bg-violet-500/5 text-slate-400 hover:bg-violet-500/10 hover:text-slate-300'
        )}
      >
        <Cpu className="h-3 w-3 text-violet-400 shrink-0" />
        <span>
          {steps.length} action{steps.length !== 1 ? 's' : ''} taken
          {errorCount > 0 && <span className="text-red-400 ml-1">· {errorCount} error{errorCount > 1 ? 's' : ''}</span>}
        </span>
        <ChevronDown className={cn('h-3 w-3 ml-1 transition-transform text-slate-600', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="mt-1.5 space-y-0.5 pl-1">
          {steps.map((step, i) => (
            <EvidenceStepRow key={step.callId} step={step} index={i} />
          ))}
        </div>
      )}
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
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2 px-3 py-2 text-violet-300 hover:bg-slate-700/50 transition-colors">
        <Wrench className={cn('h-3 w-3 shrink-0', inFlight && 'animate-pulse text-yellow-400')} />
        <span className="text-violet-200 font-semibold">{inFlight ? 'Using tool: ' : ''}<span className="text-yellow-300">🔧</span> {preview}</span>
        <ChevronDown className={cn('h-3 w-3 ml-auto shrink-0 transition-transform text-slate-500', open && 'rotate-180')} />
      </button>
      {open && <pre className="border-t border-violet-500/20 bg-black/30 p-3 text-violet-200/80 overflow-x-auto whitespace-pre-wrap break-all">{argsStr}</pre>}
    </div>
  )
}

// ─── Tool result card ─────────────────────────────────────────────────────────

function ToolResultCard({ result }: { result: ToolResult }) {
  const [open, setOpen] = useState(false)
  const raw = typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2)
  const isError = raw.toLowerCase().startsWith('error')
  const preview = raw.slice(0, 200)
  return (
    <div className={cn('rounded-lg border text-xs font-mono overflow-hidden border-l-2', isError ? 'border-red-500/30 bg-slate-800 border-l-red-500' : 'border-emerald-500/30 bg-slate-800 border-l-emerald-500')}>
      <button onClick={() => setOpen((v) => !v)} className={cn('flex w-full items-center gap-2 px-3 py-2 transition-colors', isError ? 'text-red-400 hover:bg-red-500/10' : 'text-emerald-400 hover:bg-emerald-500/10')}>
        {isError ? <AlertCircle className="h-3 w-3 shrink-0" /> : <Check className="h-3 w-3 shrink-0" />}
        <span className={cn('font-semibold', isError ? 'text-red-400' : 'text-emerald-400')}>{isError ? 'Error' : 'Result'}</span>
        <span className={cn('ml-2 truncate max-w-[40ch]', isError ? 'text-red-300/60' : 'text-emerald-300/60')}>— {preview}{raw.length > 200 && !open ? '…' : ''}</span>
        <ChevronDown className={cn('h-3 w-3 ml-auto shrink-0 transition-transform text-slate-500', open && 'rotate-180')} />
      </button>
      {open && <pre className={cn('border-t bg-black/30 p-3 overflow-x-auto whitespace-pre-wrap break-all', isError ? 'border-red-500/20 text-red-300/80' : 'border-emerald-500/20 text-emerald-300/80')}>{raw}</pre>}
    </div>
  )
}

// ─── Context bar ──────────────────────────────────────────────────────────────

function ContextBar({
  ctx,
  onSetGoal,
}: {
  ctx: ContextState | null
  onSetGoal: (goal: string) => void
}) {
  const goal = ctx?.goal
  const goalLabel = goal ? (GOAL_LABELS[goal] ?? goal) : null
  const envName = ctx?.environment_name
  const sessionId = ctx?.active_session_id
  const ws = ctx?.working_set
  const hasWorkingSet = ws && Object.values(ws).some((v) => Array.isArray(v) && v.length > 0)

  if (!goal && !envName) return null

  return (
    <div className="flex items-center gap-2 px-4 py-1.5 border-b border-slate-800 bg-slate-900/60 text-[11px] flex-wrap">
      <MapPin className="h-3 w-3 text-slate-500 shrink-0" />
      {goalLabel && (
        <span className="flex items-center gap-1 rounded-full bg-slate-800 border border-slate-700 px-2 py-0.5 text-slate-300">
          <Target className="h-2.5 w-2.5 text-cyan-400" />
          {goalLabel}
        </span>
      )}
      {envName && (
        <span className="flex items-center gap-1 rounded-full bg-slate-800 border border-slate-700 px-2 py-0.5 text-slate-300">
          <Terminal className="h-2.5 w-2.5 text-violet-400" />
          {envName}
        </span>
      )}
      {sessionId && (
        <span className="flex items-center gap-1 rounded-full bg-slate-800 border border-slate-700 px-2 py-0.5 text-slate-400 font-mono">
          Session {sessionId.slice(0, 8)}
        </span>
      )}
      {hasWorkingSet && (
        <span className="text-slate-600">
          {[
            ws.session_ids?.length && `${ws.session_ids.length} session${ws.session_ids.length > 1 ? 's' : ''}`,
            ws.rule_ids?.length && `${ws.rule_ids.length} rule${ws.rule_ids.length > 1 ? 's' : ''}`,
            ws.use_case_ids?.length && `${ws.use_case_ids.length} use case${ws.use_case_ids.length > 1 ? 's' : ''}`,
            ws.technique_ids?.length && `${ws.technique_ids.length} technique${ws.technique_ids.length > 1 ? 's' : ''}`,
          ].filter(Boolean).join(' · ')}
        </span>
      )}
      <button
        onClick={() => onSetGoal('')}
        className="ml-auto text-slate-600 hover:text-slate-400 transition-colors"
        title="Change goal"
      >
        change goal
      </button>
    </div>
  )
}

// ─── Goal presets (empty state) ───────────────────────────────────────────────

function GoalPresets({ onSelect }: { onSelect: (goal: typeof GOAL_PRESETS[0]) => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 px-8">
      <div>
        <p className="text-sm font-semibold text-slate-200 text-center">What do you want to do today?</p>
        <p className="text-xs text-slate-500 mt-1 text-center">Choose a goal or just start typing</p>
      </div>
      <div className="grid grid-cols-2 gap-3 w-full max-w-xl">
        {GOAL_PRESETS.map((preset) => {
          const Icon = preset.icon
          return (
            <button
              key={preset.id}
              onClick={() => onSelect(preset)}
              className={cn(
                'flex flex-col items-start gap-2 rounded-xl border p-4 text-left transition-all',
                preset.border,
                preset.bg
              )}
            >
              <Icon className={cn('h-5 w-5', preset.color)} />
              <div>
                <p className="text-xs font-semibold text-slate-200">{preset.label}</p>
                <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">{preset.description}</p>
              </div>
            </button>
          )
        })}
      </div>
      <p className="text-[10px] text-slate-600">Or just type anything to start a free conversation</p>
    </div>
  )
}

// ─── Follow-up chips ──────────────────────────────────────────────────────────

function FollowUpChips({ suggestions, onSelect }: { suggestions: string[]; onSelect: (s: string) => void }) {
  if (!suggestions.length) return null
  return (
    <div className="flex flex-wrap gap-2 px-4 pt-1 pb-2">
      {suggestions.slice(0, 3).map((s, i) => (
        <button
          key={i}
          onClick={() => onSelect(s)}
          className="flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800/60 px-3 py-1 text-[11px] text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 hover:bg-slate-700/60 transition-all"
        >
          <ArrowRight className="h-2.5 w-2.5 text-cyan-500/60" />
          {s}
        </button>
      ))}
    </div>
  )
}

// ─── Action log panel ─────────────────────────────────────────────────────────

function ActionLogPanel({ entries, onClose }: { entries: ActionLogEntry[]; onClose: () => void }) {
  return (
    <aside className="flex flex-col w-72 shrink-0 border-l border-slate-800 bg-slate-900 overflow-hidden">
      <div className="flex h-10 items-center justify-between border-b border-slate-800 px-3 shrink-0">
        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Action Log</span>
        <button onClick={onClose} className="rounded p-1 text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        {entries.length === 0 ? (
          <p className="text-[11px] text-slate-600 text-center py-4">No tool actions yet</p>
        ) : (
          entries.map((entry) => (
            <ActionLogEntry key={entry.id} entry={entry} />
          ))
        )}
      </div>
    </aside>
  )
}

function ActionLogEntry({ entry }: { entry: ActionLogEntry }) {
  const [open, setOpen] = useState(false)
  const isCall = entry.type === 'tool_call'
  const dataStr = typeof entry.data === 'string' ? entry.data : JSON.stringify(entry.data, null, 2)
  const preview = dataStr.slice(0, 80) + (dataStr.length > 80 ? '…' : '')

  return (
    <div
      className={cn(
        'rounded border border-l-2 text-[11px] font-mono overflow-hidden cursor-pointer',
        isCall ? 'border-violet-500/20 border-l-violet-500 bg-slate-800/50' : 'border-emerald-500/20 border-l-emerald-500 bg-slate-800/50'
      )}
      onClick={() => setOpen((v) => !v)}
    >
      <div className="flex items-center gap-1.5 px-2 py-1.5">
        {isCall
          ? <Wrench className="h-2.5 w-2.5 text-violet-400 shrink-0" />
          : <Check className="h-2.5 w-2.5 text-emerald-400 shrink-0" />
        }
        <span className={cn('font-semibold truncate', isCall ? 'text-violet-300' : 'text-emerald-300')}>
          {entry.name}
        </span>
        <span className="ml-auto text-[10px] text-slate-600 shrink-0">
          {formatTime(entry.timestamp)}
        </span>
      </div>
      {open && (
        <pre className="border-t border-slate-700 bg-black/30 px-2 py-1.5 text-slate-400 overflow-x-auto whitespace-pre-wrap break-all text-[10px]">
          {preview}
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
  followUpSuggestions,
  onFollowUp,
}: {
  msg: Message
  isLast: boolean
  onRegenerate?: () => void
  followUpSuggestions?: string[]
  onFollowUp?: (s: string) => void
}) {
  const [copied, setCopied] = useState(false)
  const [showTime, setShowTime] = useState(false)

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
  const showChips = isLast && !isUser && followUpSuggestions && followUpSuggestions.length > 0

  return (
    <div className={cn('flex flex-col px-4 py-1 group', isUser ? 'items-end' : 'items-start')}>
      <div className={cn('max-w-[80%]', isUser ? 'items-end flex flex-col' : '')}>
        <div
          className={cn(
            'rounded-2xl px-4 py-2.5 text-sm leading-relaxed break-words',
            isUser
              ? 'bg-cyan-600 text-white rounded-br-sm whitespace-pre-wrap'
              : 'bg-slate-800 text-slate-100 border border-slate-700 rounded-bl-sm'
          )}
        >
          {isUser ? msg.content : <MessageContent content={msg.content} />}
        </div>

        <div className={cn('flex items-center gap-2 mt-0.5', isUser ? 'flex-row-reverse' : '')}>
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
                onClick={() => { void navigator.clipboard.writeText(msg.content); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
                className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300"
              >
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
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

      {showChips && onFollowUp && (
        <div className="mt-1 max-w-[80%]">
          <FollowUpChips suggestions={followUpSuggestions!} onSelect={onFollowUp} />
        </div>
      )}
    </div>
  )
}

// ─── Conversation sidebar item ────────────────────────────────────────────────

function ConvItem({ conv, active, onSelect, onDelete }: {
  conv: Conversation; active: boolean; onSelect: () => void; onDelete: () => void
}) {
  const goalLabel = conv.goal ? GOAL_LABELS[conv.goal] : null
  return (
    <div
      className={cn('group flex items-center gap-2 rounded-lg px-3 py-2 cursor-pointer transition-colors', active ? 'bg-slate-700 text-white' : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200')}
      onClick={onSelect}
    >
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium truncate">{conv.title || 'Untitled chat'}</div>
        <div className="text-[10px] text-slate-500 mt-0.5">
          {goalLabel && <span className="text-cyan-600 mr-1">{goalLabel}</span>}
          {conv.message_count} msgs
          {conv.updated_at && <> · {timeAgo(new Date(conv.updated_at).getTime())}</>}
        </div>
      </div>
      <button
        onClick={(e) => { e.stopPropagation(); onDelete() }}
        className="opacity-0 group-hover:opacity-100 shrink-0 rounded p-1 hover:bg-slate-600 text-slate-400 hover:text-red-400 transition-colors"
      >
        <Trash2 className="h-3 w-3" />
      </button>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ChatPage() {
  return (
    <Suspense>
      <ChatPageInner />
    </Suspense>
  )
}

function ChatPageInner() {
  const searchParams = useSearchParams()
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

  // Sticky context
  const [contextState, setContextState] = useState<ContextState | null>(null)
  const [pendingGoal, setPendingGoal] = useState<string | null>(null)

  // Action log
  const [actionLogOpen, setActionLogOpen] = useState(false)
  const [actionLog, setActionLog] = useState<ActionLogEntry[]>([])

  // Input
  const [input, setInput] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Title editing
  const [editingTitle, setEditingTitle] = useState(false)
  const [titleDraft, setTitleDraft] = useState('')

  const abortRef = useRef<AbortController | null>(null)
  const lastUserMsgRef = useRef<string>('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const totalTokens = messages.filter((m) => m.role === 'assistant').reduce((acc, m) => acc + approxTokens(m.content), 0)

  // ── Load conversations ────────────────────────────────────────────────────

  const loadConversations = useCallback(async () => {
    try {
      const raw = await apiGet<Conversation[] | { conversations: Conversation[] }>('/api/v2/chat/conversations')
      const list = Array.isArray(raw) ? raw : (raw.conversations ?? [])
      setConversations(list)
    } catch { /* silently ignore */ }
  }, [])

  useEffect(() => {
    void loadConversations()
    const saved = localStorage.getItem('purplelab_conv_id')
    if (saved) setCurrentConvId(saved)
  }, [loadConversations])

  // Handle deep-link URL params: ?goal=X&env_id=Y&env_name=Z&session_id=W&message=M
  useEffect(() => {
    const goal = searchParams.get('goal')
    const envId = searchParams.get('env_id')
    const envName = searchParams.get('env_name')
    const sessionId = searchParams.get('session_id')
    const message = searchParams.get('message')

    if (goal) setPendingGoal(goal)
    if (envId || envName || sessionId) {
      setContextState((prev) => ({
        ...(prev ?? {}),
        ...(envId ? { environment_id: envId } : {}),
        ...(envName ? { environment_name: envName } : {}),
        ...(sessionId ? { active_session_id: sessionId } : {}),
      }))
    }
    if (message) {
      // Auto-send the message after a short delay to let state settle
      const timer = setTimeout(() => {
        void sendMessage(message, goal ?? undefined)
      }, 300)
      return () => clearTimeout(timer)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, isWaiting, activeTool])

  useEffect(() => {
    if (currentConvId) localStorage.setItem('purplelab_conv_id', currentConvId)
  }, [currentConvId])

  // ── Textarea resize ───────────────────────────────────────────────────────

  function handleInputChange(e: ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value)
    const el = textareaRef.current
    if (el) { el.style.height = 'auto'; el.style.height = `${Math.min(el.scrollHeight, 144)}px` }
  }

  // ── Core send / stream ────────────────────────────────────────────────────

  async function sendMessage(overrideText?: string, overrideGoal?: string) {
    const text = (overrideText ?? input).trim()
    if (!text || isStreaming) return

    if (!overrideText) {
      setInput('')
      if (textareaRef.current) textareaRef.current.style.height = 'auto'
    }
    setError(null)
    lastUserMsgRef.current = text

    const userMsg: Message = { id: generateId(), role: 'user', content: text, timestamp: Date.now() }
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
    const goal = overrideGoal ?? pendingGoal ?? contextState?.goal

    try {
      const stream = streamSSE(
        '/api/v2/chat',
        { message: text, conversation_id: currentConvId, goal },
        controller.signal
      )

      for await (const chunk of stream) {
        if (firstToken) { setIsWaiting(false); firstToken = false }

        switch (chunk.type) {
          case 'conversation_id': {
            newConvId = chunk.content
            setCurrentConvId(chunk.content)
            if (goal) setPendingGoal(null)
            break
          }

          case 'text': {
            setActiveTool(null)
            assistantBuffer += chunk.content
            const buffered = assistantBuffer
            const aid = assistantId
            setMessages((prev) => {
              const existing = prev.find((m) => m.id === aid)
              if (existing) return prev.map((m) => m.id === aid ? { ...m, content: buffered } : m)
              return [...prev, { id: aid, role: 'assistant' as const, content: buffered, timestamp: Date.now() }]
            })
            break
          }

          case 'tool_call': {
            if (assistantBuffer) { assistantId = generateId(); assistantBuffer = '' }
            const meta = chunk.metadata as { tool_name?: string; arguments?: Record<string, unknown>; tool_use_id?: string; id?: string; name?: string; args?: Record<string, unknown> }
            const toolName = meta.tool_name ?? meta.name ?? chunk.content ?? 'unknown'
            const toolArgs = meta.arguments ?? meta.args ?? {}
            const toolId = meta.tool_use_id ?? meta.id ?? generateId()
            const tc: ToolCall = { id: toolId, name: toolName, args: toolArgs }
            setActiveTool(toolName)
            setMessages((prev) => [...prev, { id: generateId(), role: 'tool_call' as const, content: chunk.content, tool_call: tc, timestamp: Date.now() }])
            setActionLog((prev) => [...prev, { id: generateId(), type: 'tool_call', name: toolName, data: toolArgs, timestamp: Date.now() }])
            assistantId = generateId()
            break
          }

          case 'tool_result': {
            setActiveTool(null)
            const trMeta = chunk.metadata as { tool_use_id?: string; result?: unknown; tool_name?: string; tool_call_id?: string; content?: unknown }
            const tr: ToolResult = { tool_call_id: trMeta.tool_use_id ?? trMeta.tool_call_id ?? '', content: trMeta.result ?? trMeta.content ?? chunk.content }
            setMessages((prev) => [...prev, { id: generateId(), role: 'tool_result' as const, content: chunk.content, tool_result: tr, timestamp: Date.now() }])
            setActionLog((prev) => [...prev, { id: generateId(), type: 'tool_result', name: trMeta.tool_name ?? 'result', data: tr.content, timestamp: Date.now() }])
            assistantId = generateId()
            assistantBuffer = ''
            break
          }

          case 'context_state': {
            const cs = chunk.metadata as ContextState
            setContextState(cs)
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
      if ((err as Error).name !== 'AbortError') setError(err instanceof Error ? err.message : 'Stream failed')
    } finally {
      setIsWaiting(false)
      setIsStreaming(false)
      setActiveTool(null)
      abortRef.current = null
      if (newConvId) void loadConversations()
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && (e.ctrlKey || !e.shiftKey)) { e.preventDefault(); void sendMessage() }
  }

  function stopStreaming() { abortRef.current?.abort() }

  function handleGoalPreset(preset: typeof GOAL_PRESETS[0]) {
    setPendingGoal(preset.id)
    setContextState((prev) => ({ ...prev, goal: preset.id }))
    void sendMessage(preset.bootstrapMessage, preset.id)
  }

  function handleRegenerate() {
    if (!lastUserMsgRef.current || isStreaming) return
    setMessages((prev) => {
      const lastUserIdx = [...prev].reverse().findIndex((m) => m.role === 'user')
      if (lastUserIdx === -1) return prev
      return prev.slice(0, prev.length - lastUserIdx)
    })
    void sendMessage(lastUserMsgRef.current)
  }

  // ── New chat ─────────────────────────────────────────────────────────────

  function startNewChat() {
    setCurrentConvId(null)
    setMessages([])
    setError(null)
    setActiveTool(null)
    setContextState(null)
    setPendingGoal(null)
    setActionLog([])
    localStorage.removeItem('purplelab_conv_id')
  }

  // ── Select conversation ───────────────────────────────────────────────────

  async function selectConversation(id: string) {
    setCurrentConvId(id)
    setMessages([])
    setError(null)
    setActionLog([])
    try {
      const data = await apiGet<{ messages: Message[]; context_state?: ContextState; goal?: string }>(
        `/api/v2/chat/conversations/${id}`
      )
      setMessages(data.messages.map((m) => ({ ...m, id: (m as { id?: string }).id ?? generateId() })))
      if (data.context_state) setContextState(data.context_state)
    } catch { /* ignore */ }
  }

  // ── Delete conversation ───────────────────────────────────────────────────

  async function deleteConversation(id: string) {
    try { await apiDelete(`/api/v2/chat/conversations/${id}`) } catch { /* ignore */ }
    setConversations((prev) => prev.filter((c) => c.id !== id))
    if (currentConvId === id) startNewChat()
  }

  // ── Title editing ─────────────────────────────────────────────────────────

  function startEditTitle() {
    const conv = conversations.find((c) => c.id === currentConvId)
    setTitleDraft(conv?.title ?? 'Untitled chat')
    setEditingTitle(true)
  }

  function commitTitle() {
    if (!currentConvId) return
    setConversations((prev) => prev.map((c) => (c.id === currentConvId ? { ...c, title: titleDraft } : c)))
    setEditingTitle(false)
    void fetch(`${API_BASE}/api/v2/chat/conversations/${currentConvId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: titleDraft }),
    }).catch(() => null)
  }

  const currentTitle = conversations.find((c) => c.id === currentConvId)?.title ?? 'New Chat'
  const hasMessages = messages.length > 0
  const lastAssistantIdx = [...messages].reverse().findIndex((m) => m.role === 'assistant')
  const lastAssistantId = lastAssistantIdx !== -1 ? messages[messages.length - 1 - lastAssistantIdx].id : null
  const followUps = contextState?.suggested_followups ?? []

  return (
    <div className="flex h-full overflow-hidden bg-slate-950">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside className={cn('flex flex-col border-r border-slate-800 bg-slate-900 transition-all duration-300 shrink-0', sidebarOpen ? 'w-64' : 'w-0 overflow-hidden')}>
        <div className="flex h-12 items-center justify-between border-b border-slate-800 px-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Conversations</span>
          <button onClick={startNewChat} className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-cyan-400 hover:bg-slate-800 transition-colors">
            <Plus className="h-3.5 w-3.5" />
            New
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
          {conversations.length === 0 ? (
            <p className="px-3 py-4 text-xs text-slate-600 text-center">No conversations yet</p>
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
          <button onClick={() => setSidebarOpen((v) => !v)} className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
            {sidebarOpen ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>

          {editingTitle ? (
            <input
              autoFocus
              value={titleDraft}
              onChange={(e) => setTitleDraft(e.target.value)}
              onBlur={commitTitle}
              onKeyDown={(e) => { if (e.key === 'Enter') commitTitle(); if (e.key === 'Escape') setEditingTitle(false) }}
              className="flex-1 bg-slate-800 text-sm text-slate-100 rounded-md px-2 py-0.5 border border-slate-600 focus:outline-none focus:border-cyan-500"
            />
          ) : (
            <button onClick={startEditTitle} className="flex items-center gap-1.5 text-sm font-medium text-slate-200 hover:text-white group">
              <span>{currentTitle}</span>
              <Pencil className="h-3 w-3 text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>
          )}

          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => setActionLogOpen((v) => !v)}
              title="Action log"
              className={cn('flex h-7 w-7 items-center justify-center rounded-md transition-colors', actionLogOpen ? 'bg-slate-700 text-slate-200' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800')}
            >
              <PanelRight className="h-3.5 w-3.5" />
            </button>
            <button onClick={() => void loadConversations()} className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors">
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
        </header>

        {/* Context bar */}
        <ContextBar ctx={contextState} onSetGoal={(g) => setContextState((prev) => ({ ...prev, goal: g || undefined }))} />

        {/* Message area */}
        <div className="flex-1 overflow-y-auto py-4 space-y-1">
          {!hasMessages && !isWaiting && (
            <GoalPresets onSelect={handleGoalPreset} />
          )}

          {groupMessages(messages).map((group) => {
            if (group.kind === 'user') {
              return (
                <MessageBubble
                  key={group.id}
                  msg={group.msg}
                  isLast={false}
                />
              )
            }
            // Assistant turn — show evidence chain above the response
            const isLastAssistant = group.msg.id === lastAssistantId
            return (
              <div key={group.id} className="flex flex-col items-start px-4 py-1">
                {/* Evidence chain (collapsed by default) */}
                <TurnEvidenceChain steps={group.evidenceSteps} />
                {/* Assistant response text */}
                {group.msg.content ? (
                  <MessageBubble
                    msg={group.msg}
                    isLast={isLastAssistant && !isStreaming}
                    onRegenerate={isLastAssistant && !isStreaming ? handleRegenerate : undefined}
                    followUpSuggestions={isLastAssistant && !isStreaming ? followUps : undefined}
                    onFollowUp={isLastAssistant && !isStreaming ? (s) => void sendMessage(s) : undefined}
                  />
                ) : null}
              </div>
            )
          })}

          {isWaiting && (
            <div className="flex justify-start px-4 py-1">
              <div className="bg-slate-800 border border-slate-700 rounded-2xl rounded-bl-sm">
                <TypingIndicator label="Agent is thinking…" />
              </div>
            </div>
          )}

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
              <div className="flex-1 min-w-0"><p className="text-xs text-red-300">{error}</p></div>
              <button
                onClick={() => { setError(null); if (lastUserMsgRef.current) void sendMessage(lastUserMsgRef.current) }}
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

            {input && !isStreaming && (
              <button
                onClick={() => { setInput(''); if (textareaRef.current) textareaRef.current.style.height = 'auto'; textareaRef.current?.focus() }}
                className="mb-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-700 text-slate-400 hover:bg-slate-600 hover:text-slate-200 transition-colors"
              >
                <X className="h-3 w-3" />
              </button>
            )}

            {isStreaming ? (
              <button onClick={stopStreaming} className="mb-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors">
                <Square className="h-3.5 w-3.5 fill-current" />
              </button>
            ) : (
              <button
                onClick={() => void sendMessage()}
                disabled={!input.trim()}
                className="mb-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-cyan-600 text-white hover:bg-cyan-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                {isWaiting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
              </button>
            )}
          </div>

          <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-600">
            <span>
              {contextState?.environment_name && <><span className="text-slate-500">{contextState.environment_name}</span> · </>}
              {currentConvId && <>Conv: <span className="font-mono text-slate-500">{currentConvId.slice(0, 8)}…</span></>}
              {totalTokens > 0 && <> · ~{totalTokens} tokens</>}
            </span>
            {input.length > 500 && (
              <span className={cn('font-mono', input.length > 2000 ? 'text-red-400' : input.length > 1000 ? 'text-yellow-500' : 'text-slate-500')}>
                {input.length} chars
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Action log panel ─────────────────────────────────────────────── */}
      {actionLogOpen && (
        <ActionLogPanel entries={actionLog} onClose={() => setActionLogOpen(false)} />
      )}
    </div>
  )
}
