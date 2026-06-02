'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Brain,
  Shield,
  BarChart3,
  Code2,
  RefreshCw,
  Save,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  Zap,
  DollarSign,
  Clock,
  Activity,
  Eye,
  EyeOff,
  Info,
} from 'lucide-react'
import { apiGet, apiPut } from '@/lib/api/client'
import { cn } from '@/lib/utils'

// ─── Types ───────────────────────────────────────────────────────────────────

interface LLMFunctionConfig {
  function_name: string
  display_name: string
  description: string
  needs_tools: boolean
  volume: 'low' | 'medium' | 'high'
  recommended_tags: string[]
  config: {
    provider: string
    model_id: string
    temperature: number
    max_tokens: number
    has_api_key_override: boolean
  }
  is_active: boolean
  updated_at: string | null
  usage: {
    calls_7d: number
    input_tokens_7d: number
    output_tokens_7d: number
    avg_latency_ms: number
    estimated_cost_usd_7d: number
  }
}

interface GuardrailConfig {
  function_name: string
  display_name: string
  enabled: boolean
  max_input_tokens: number
  max_output_tokens: number
  rate_limit_per_minute: number
  block_patterns: string[]
  require_json_output: boolean
  pii_masking_enabled: boolean
  system_prompt_override: string | null
  notes: string
  updated_at: string | null
  from_db: boolean
}

interface UsageSummary {
  function_name: string
  provider: string
  model_id: string
  calls: number
  input_tokens: number
  output_tokens: number
  avg_latency_ms: number
  estimated_cost_usd: number
}

interface UsageTimeline {
  date: string
  calls: number
  tokens: number
}

interface SkillPrompt {
  function_name: string
  display_name: string
  system_prompt: string
  has_custom_prompt: boolean
}

// ─── Tab types ───────────────────────────────────────────────────────────────

type Tab = 'functions' | 'guardrails' | 'usage' | 'skills'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function volumeBadge(v: string) {
  if (v === 'high') return 'bg-red-500/15 text-red-400 border border-red-500/30'
  if (v === 'medium') return 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
  return 'bg-green-500/15 text-green-400 border border-green-500/30'
}

function providerColor(p: string) {
  if (p === 'anthropic') return 'text-orange-400'
  if (p === 'openai') return 'text-teal-400'
  if (p === 'google') return 'text-blue-400'
  if (p === 'ollama') return 'text-purple-400'
  return 'text-muted-foreground'
}

function fmtNumber(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

// ─── Functions Tab ───────────────────────────────────────────────────────────

function FunctionsTab() {
  const [functions, setFunctions] = useState<LLMFunctionConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ functions: LLMFunctionConfig[] }>('/api/v2/ai-engine/functions')
      setFunctions(data.functions ?? [])
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  if (loading) return (
    <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
      <RefreshCw className="w-4 h-4 animate-spin" />
      <span className="text-sm">Loading function configs...</span>
    </div>
  )

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {functions.length} AI functions — configure which model handles each task
        </p>
        <button onClick={load} className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {functions.map(fn => (
        <div key={fn.function_name} className="rounded-lg border border-border bg-card">
          <button
            className="w-full flex items-center gap-3 px-4 py-3 text-left"
            onClick={() => setExpanded(expanded === fn.function_name ? null : fn.function_name)}
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium text-foreground">{fn.display_name}</span>
                <span className={cn('rounded px-1.5 py-0.5 text-[10px] uppercase font-medium', volumeBadge(fn.volume))}>
                  {fn.volume} vol
                </span>
                {fn.needs_tools && (
                  <span className="rounded bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 text-[10px] text-blue-400">
                    tools
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5 truncate">{fn.description}</p>
            </div>

            {/* Quick stats */}
            <div className="hidden sm:flex items-center gap-4 text-xs text-muted-foreground shrink-0">
              <span className={cn('font-mono', providerColor(fn.config.provider))}>
                {fn.config.provider}/{fn.config.model_id.split('-').slice(-1)[0]}
              </span>
              <span>{fn.usage.calls_7d} calls/7d</span>
              <span className="text-green-400">${fn.usage.estimated_cost_usd_7d.toFixed(3)}</span>
            </div>

            {expanded === fn.function_name ? (
              <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" />
            ) : (
              <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />
            )}
          </button>

          {expanded === fn.function_name && (
            <div className="border-t border-border px-4 py-3 space-y-3">
              {/* Config row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div>
                  <div className="text-muted-foreground mb-1">Provider</div>
                  <div className={cn('font-medium', providerColor(fn.config.provider))}>
                    {fn.config.provider}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Model</div>
                  <div className="font-mono text-foreground">{fn.config.model_id}</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Temperature</div>
                  <div className="text-foreground">{fn.config.temperature}</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Max tokens</div>
                  <div className="text-foreground">{fmtNumber(fn.config.max_tokens)}</div>
                </div>
              </div>

              {/* Usage row */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs bg-muted/30 rounded p-2">
                <div>
                  <div className="text-muted-foreground mb-1">Calls (7d)</div>
                  <div className="text-foreground font-medium">{fn.usage.calls_7d}</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Input tokens</div>
                  <div className="text-foreground">{fmtNumber(fn.usage.input_tokens_7d)}</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Output tokens</div>
                  <div className="text-foreground">{fmtNumber(fn.usage.output_tokens_7d)}</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Avg latency</div>
                  <div className="text-foreground">{fn.usage.avg_latency_ms}ms</div>
                </div>
                <div>
                  <div className="text-muted-foreground mb-1">Est. cost (7d)</div>
                  <div className="text-green-400 font-medium">${fn.usage.estimated_cost_usd_7d.toFixed(4)}</div>
                </div>
              </div>

              {/* Tags */}
              {fn.recommended_tags.length > 0 && (
                <div className="flex items-center gap-1 flex-wrap">
                  <span className="text-xs text-muted-foreground">Recommended for:</span>
                  {fn.recommended_tags.map(t => (
                    <span key={t} className="rounded bg-primary/10 border border-primary/20 px-1.5 py-0.5 text-[10px] text-primary">
                      {t}
                    </span>
                  ))}
                </div>
              )}

              <p className="text-xs text-muted-foreground">
                Model assignment is managed via <span className="text-foreground font-medium">/settings → AI Model Config</span>.
                {fn.updated_at && ` Last updated: ${new Date(fn.updated_at).toLocaleDateString()}`}
              </p>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ─── Guardrails Tab ──────────────────────────────────────────────────────────

function GuardrailsTab() {
  const [guardrails, setGuardrails] = useState<GuardrailConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState<string | null>(null)
  const [form, setForm] = useState<Partial<GuardrailConfig>>({})
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ guardrails: GuardrailConfig[] }>('/api/v2/ai-engine/guardrails')
      setGuardrails(data.guardrails ?? [])
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const startEdit = (g: GuardrailConfig) => {
    setEditing(g.function_name)
    setForm({ ...g })
    setSaveMsg('')
  }

  const save = async () => {
    if (!editing) return
    setSaving(true)
    try {
      await apiPut(`/api/v2/ai-engine/guardrails/${editing}`, form)
      setSaveMsg('Saved')
      await load()
      setTimeout(() => { setEditing(null); setSaveMsg('') }, 800)
    } catch (e: any) {
      setSaveMsg(`Error: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return (
    <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
      <RefreshCw className="w-4 h-4 animate-spin" />
    </div>
  )

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Configure content filters, rate limits, and safety controls per AI function.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-muted-foreground">
              <th className="px-3 py-2 text-left font-medium">Function</th>
              <th className="px-3 py-2 text-center font-medium">Enabled</th>
              <th className="px-3 py-2 text-right font-medium">Rate/min</th>
              <th className="px-3 py-2 text-right font-medium">Max in tokens</th>
              <th className="px-3 py-2 text-right font-medium">Max out tokens</th>
              <th className="px-3 py-2 text-center font-medium">PII mask</th>
              <th className="px-3 py-2 text-center font-medium">JSON out</th>
              <th className="px-3 py-2 text-left font-medium">Source</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {guardrails.map(g => (
              <tr key={g.function_name} className={cn('border-b border-border', editing === g.function_name ? 'bg-primary/5' : 'hover:bg-muted/30')}>
                <td className="px-3 py-2 font-medium text-foreground">{g.display_name}</td>
                <td className="px-3 py-2 text-center">
                  {g.enabled
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 inline" />
                    : <AlertTriangle className="w-3.5 h-3.5 text-red-400 inline" />}
                </td>
                <td className="px-3 py-2 text-right text-muted-foreground">{g.rate_limit_per_minute || '∞'}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(g.max_input_tokens)}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(g.max_output_tokens)}</td>
                <td className="px-3 py-2 text-center">
                  {g.pii_masking_enabled ? <Eye className="w-3.5 h-3.5 text-amber-400 inline" /> : <EyeOff className="w-3.5 h-3.5 text-muted-foreground/40 inline" />}
                </td>
                <td className="px-3 py-2 text-center">
                  {g.require_json_output ? <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 inline" /> : <span className="text-muted-foreground/40">—</span>}
                </td>
                <td className="px-3 py-2">
                  {g.from_db
                    ? <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-400">DB</span>
                    : <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">default</span>}
                </td>
                <td className="px-3 py-2">
                  <button onClick={() => startEdit(g)} className="rounded px-2 py-1 text-[10px] border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">
                    Edit
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Edit panel */}
      {editing && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-foreground">
              Editing: {guardrails.find(g => g.function_name === editing)?.display_name}
            </h3>
            <button onClick={() => setEditing(null)} className="text-muted-foreground hover:text-foreground text-xs">Cancel</button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Rate limit / min (0 = unlimited)</span>
              <input
                type="number" min={0} max={1000}
                value={form.rate_limit_per_minute ?? 60}
                onChange={e => setForm(f => ({ ...f, rate_limit_per_minute: +e.target.value }))}
                className="field px-2 py-1 text-xs w-full"
              />
            </label>
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Max input tokens</span>
              <input
                type="number" min={256} max={200000}
                value={form.max_input_tokens ?? 32000}
                onChange={e => setForm(f => ({ ...f, max_input_tokens: +e.target.value }))}
                className="field px-2 py-1 text-xs w-full"
              />
            </label>
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Max output tokens</span>
              <input
                type="number" min={256} max={32000}
                value={form.max_output_tokens ?? 8192}
                onChange={e => setForm(f => ({ ...f, max_output_tokens: +e.target.value }))}
                className="field px-2 py-1 text-xs w-full"
              />
            </label>
          </div>

          <div className="flex items-center gap-4 flex-wrap">
            <label className="flex items-center gap-2 text-xs text-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled ?? true}
                onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
              />
              Enabled
            </label>
            <label className="flex items-center gap-2 text-xs text-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={form.pii_masking_enabled ?? false}
                onChange={e => setForm(f => ({ ...f, pii_masking_enabled: e.target.checked }))}
              />
              PII Masking
            </label>
            <label className="flex items-center gap-2 text-xs text-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={form.require_json_output ?? false}
                onChange={e => setForm(f => ({ ...f, require_json_output: e.target.checked }))}
              />
              Require JSON Output
            </label>
          </div>

          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">Block patterns (one regex per line)</span>
            <textarea
              rows={3}
              value={(form.block_patterns ?? []).join('\n')}
              onChange={e => setForm(f => ({ ...f, block_patterns: e.target.value.split('\n').filter(Boolean) }))}
              className="field px-2 py-1 text-xs w-full font-mono"
              placeholder="e.g. (?i)drop table"
            />
          </label>

          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">System prompt override (leave blank to use default)</span>
            <textarea
              rows={4}
              value={form.system_prompt_override ?? ''}
              onChange={e => setForm(f => ({ ...f, system_prompt_override: e.target.value || null }))}
              className="field px-2 py-1 text-xs w-full"
            />
          </label>

          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">Notes</span>
            <input
              value={form.notes ?? ''}
              onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
              className="field px-2 py-1 text-xs w-full"
            />
          </label>

          <div className="flex items-center gap-3">
            <button
              onClick={save}
              disabled={saving}
              className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/90 disabled:opacity-50"
            >
              {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
              Save guardrail
            </button>
            {saveMsg && (
              <span className={cn('text-xs', saveMsg.startsWith('Error') ? 'text-red-400' : 'text-green-400')}>
                {saveMsg}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Usage Tab ───────────────────────────────────────────────────────────────

function UsageTab() {
  const [summary, setSummary] = useState<UsageSummary[]>([])
  const [timeline, setTimeline] = useState<UsageTimeline[]>([])
  const [totals, setTotals] = useState<{ calls: number; tokens: number; estimated_cost_usd: number } | null>(null)
  const [days, setDays] = useState(7)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ summary: UsageSummary[]; timeline: UsageTimeline[]; totals: any }>(`/api/v2/ai-engine/usage?days=${days}`)
      setSummary(data.summary ?? [])
      setTimeline(data.timeline ?? [])
      setTotals(data.totals ?? null)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [days])

  useEffect(() => { load() }, [load])

  if (loading) return (
    <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
      <RefreshCw className="w-4 h-4 animate-spin" />
    </div>
  )

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted-foreground">Period:</span>
        {[7, 14, 30, 90].map(d => (
          <button
            key={d}
            onClick={() => setDays(d)}
            className={cn(
              'rounded px-2.5 py-1 text-xs transition-colors',
              days === d ? 'bg-primary text-white' : 'border border-border text-muted-foreground hover:text-foreground hover:bg-muted'
            )}
          >
            {d}d
          </button>
        ))}
        <button onClick={load} className="ml-auto rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted">
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Totals */}
      {totals && (
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-lg border border-border bg-card p-3">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <Activity className="w-3.5 h-3.5" />
              Total calls
            </div>
            <div className="text-xl font-bold text-foreground">{fmtNumber(totals.calls)}</div>
          </div>
          <div className="rounded-lg border border-border bg-card p-3">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <Cpu className="w-3.5 h-3.5" />
              Total tokens
            </div>
            <div className="text-xl font-bold text-foreground">{fmtNumber(totals.tokens)}</div>
          </div>
          <div className="rounded-lg border border-border bg-card p-3">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <DollarSign className="w-3.5 h-3.5" />
              Estimated cost
            </div>
            <div className="text-xl font-bold text-green-400">${totals.estimated_cost_usd.toFixed(4)}</div>
          </div>
        </div>
      )}

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="text-xs font-medium text-muted-foreground mb-3">Daily calls ({days}d)</h3>
          <div className="flex items-end gap-1 h-16">
            {timeline.map((day, i) => {
              const maxCalls = Math.max(...timeline.map(d => d.calls), 1)
              const height = Math.max((day.calls / maxCalls) * 100, 4)
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1 group">
                  <div
                    className="w-full rounded-t bg-primary/60 hover:bg-primary transition-colors relative"
                    style={{ height: `${height}%` }}
                    title={`${day.date}: ${day.calls} calls`}
                  />
                  {timeline.length <= 14 && (
                    <span className="text-[8px] text-muted-foreground rotate-45 origin-left hidden group-hover:block">
                      {day.date.slice(5)}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Per-function breakdown */}
      {summary.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-6 text-center text-sm text-muted-foreground">
          No usage data for the selected period. Make some AI calls to see stats here.
        </div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-muted-foreground">
              <th className="px-3 py-2 text-left font-medium">Function</th>
              <th className="px-3 py-2 text-left font-medium">Provider / Model</th>
              <th className="px-3 py-2 text-right font-medium">Calls</th>
              <th className="px-3 py-2 text-right font-medium">Input tokens</th>
              <th className="px-3 py-2 text-right font-medium">Output tokens</th>
              <th className="px-3 py-2 text-right font-medium">Avg latency</th>
              <th className="px-3 py-2 text-right font-medium">Est. cost</th>
            </tr>
          </thead>
          <tbody>
            {summary.sort((a, b) => b.estimated_cost_usd - a.estimated_cost_usd).map(row => (
              <tr key={row.function_name} className="border-b border-border hover:bg-muted/30">
                <td className="px-3 py-2 font-medium text-foreground">{row.function_name}</td>
                <td className="px-3 py-2">
                  <span className={cn('font-mono', providerColor(row.provider))}>{row.provider}</span>
                  <span className="text-muted-foreground">/{row.model_id.split('-').slice(-1)[0]}</span>
                </td>
                <td className="px-3 py-2 text-right text-foreground">{row.calls}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(row.input_tokens)}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(row.output_tokens)}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{row.avg_latency_ms}ms</td>
                <td className="px-3 py-2 text-right text-green-400">${row.estimated_cost_usd.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

// ─── Skills Tab ───────────────────────────────────────────────────────────────

function SkillsTab() {
  const [skills, setSkills] = useState<SkillPrompt[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ skill_prompts: SkillPrompt[] }>('/api/v2/ai-engine/skill-prompts')
      setSkills(data.skill_prompts ?? [])
      if (!selected && data.skill_prompts?.length) {
        setSelected(data.skill_prompts.find(s => s.has_custom_prompt)?.function_name ?? data.skill_prompts[0].function_name)
      }
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [selected])

  useEffect(() => { load() }, [load])

  const selectedSkill = skills.find(s => s.function_name === selected)

  if (loading) return (
    <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center">
      <RefreshCw className="w-4 h-4 animate-spin" />
    </div>
  )

  return (
    <div className="flex gap-4 h-[500px]">
      {/* Left list */}
      <div className="w-48 shrink-0 space-y-1 overflow-y-auto">
        {skills.map(s => (
          <button
            key={s.function_name}
            onClick={() => setSelected(s.function_name)}
            className={cn(
              'w-full text-left rounded px-2.5 py-2 text-xs transition-colors',
              selected === s.function_name
                ? 'bg-primary/15 text-primary border border-primary/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            )}
          >
            <div className="font-medium truncate">{s.display_name}</div>
            {s.has_custom_prompt && (
              <span className="text-[9px] text-primary/70">custom prompt</span>
            )}
          </button>
        ))}
      </div>

      {/* Right prompt viewer */}
      <div className="flex-1 min-w-0">
        {selectedSkill ? (
          <div className="h-full flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-medium text-foreground">{selectedSkill.display_name}</h3>
              {selectedSkill.has_custom_prompt && (
                <span className="rounded bg-primary/10 border border-primary/20 px-1.5 py-0.5 text-[10px] text-primary">custom</span>
              )}
            </div>
            {selectedSkill.system_prompt ? (
              <pre className="flex-1 overflow-y-auto rounded border border-border bg-muted/30 p-3 text-xs font-mono text-foreground whitespace-pre-wrap">
                {selectedSkill.system_prompt}
              </pre>
            ) : (
              <div className="flex-1 flex items-center justify-center rounded border border-border bg-muted/20 text-sm text-muted-foreground">
                No custom system prompt — using model defaults.
                <br />
                Override via the Guardrails tab (system_prompt_override field).
              </div>
            )}
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <Info className="w-3 h-3" />
              Override per-function system prompts in the Guardrails tab → system_prompt_override field.
            </p>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            Select a function to view its system prompt.
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: React.ElementType }[] = [
  { key: 'functions', label: 'Functions', icon: Brain },
  { key: 'guardrails', label: 'Guardrails', icon: Shield },
  { key: 'usage', label: 'Usage & Cost', icon: BarChart3 },
  { key: 'skills', label: 'Skill Prompts', icon: Code2 },
]

export default function AIEnginePage() {
  const [tab, setTab] = useState<Tab>('functions')

  return (
    <div className="space-y-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            AI Engine
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure AI functions, guardrails, usage tracking, and system prompts
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-xs text-muted-foreground">14 AI functions registered</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px',
              tab === t.key
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            )}
          >
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {tab === 'functions' && <FunctionsTab />}
        {tab === 'guardrails' && <GuardrailsTab />}
        {tab === 'usage' && <UsageTab />}
        {tab === 'skills' && <SkillsTab />}
      </div>
    </div>
  )
}
