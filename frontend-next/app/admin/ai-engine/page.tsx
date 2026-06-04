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
  Activity,
  Eye,
  EyeOff,
  Pencil,
  X,
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

interface SkillPrompt {
  function_name: string
  display_name: string
  system_prompt: string
  has_custom_prompt: boolean
}

type Tab = 'functions' | 'guardrails' | 'usage' | 'skills'

// ─── Provider / model catalogue ─────────────────────────────────────────────

const PROVIDER_MODELS: Record<string, string[]> = {
  anthropic: [
    'claude-opus-4-7',
    'claude-sonnet-4-6',
    'claude-haiku-4-5-20251001',
  ],
  openai: [
    'gpt-4o',
    'gpt-4o-mini',
    'gpt-4-turbo',
    'gpt-3.5-turbo',
  ],
  google: [
    'gemini-2.0-flash',
    'gemini-1.5-pro',
    'gemini-1.5-flash',
  ],
  ollama: [
    'llama3.2',
    'llama3.1',
    'llama3.1:70b',
    'mistral',
    'codellama',
    'deepseek-r1:7b',
  ],
}

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
  const [editing, setEditing] = useState<string | null>(null)
  const [form, setForm] = useState<{ provider: string; model_id: string; temperature: number; max_tokens: number; base_url: string }>({
    provider: 'anthropic', model_id: 'claude-sonnet-4-6', temperature: 0.3, max_tokens: 4096, base_url: '',
  })
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ functions: LLMFunctionConfig[] }>('/api/v2/ai-engine/functions')
      setFunctions(data.functions ?? [])
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  function startEdit(fn: LLMFunctionConfig) {
    setEditing(fn.function_name)
    setForm({
      provider: fn.config.provider,
      model_id: fn.config.model_id,
      temperature: fn.config.temperature,
      max_tokens: fn.config.max_tokens,
      base_url: '',
    })
    setMsg('')
  }

  async function save() {
    if (!editing) return
    setSaving(true)
    setMsg('')
    try {
      await apiPut(`/api/v2/ai-engine/functions/${editing}`, form)
      setMsg('Saved ✓')
      await load()
      setTimeout(() => { setEditing(null); setMsg('') }, 900)
    } catch (e: unknown) {
      setMsg(`Error: ${e instanceof Error ? e.message : 'Failed'}`)
    } finally {
      setSaving(false)
    }
  }

  const modelsForProvider = PROVIDER_MODELS[form.provider] ?? []

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
          {/* Header row */}
          <div className="flex items-center gap-2 px-4 py-3">
            <button
              className="flex-1 flex items-center gap-3 text-left min-w-0"
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
              <div className="hidden sm:flex items-center gap-4 text-xs text-muted-foreground shrink-0">
                <span className={cn('font-mono', providerColor(fn.config.provider))}>
                  {fn.config.provider}/{fn.config.model_id.split('-').slice(-1)[0]}
                </span>
                <span>{fn.usage.calls_7d} calls/7d</span>
                <span className="text-green-400">${fn.usage.estimated_cost_usd_7d.toFixed(3)}</span>
              </div>
            </button>
            {/* Configure button */}
            <button
              onClick={() => editing === fn.function_name ? setEditing(null) : startEdit(fn)}
              className={cn(
                "rounded px-2 py-1 text-[10px] border transition-colors shrink-0",
                editing === fn.function_name
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border hover:bg-muted text-muted-foreground hover:text-foreground"
              )}
            >
              {editing === fn.function_name ? <><X className="w-3 h-3 inline mr-0.5" />Cancel</> : <><Pencil className="w-3 h-3 inline mr-0.5" />Configure</>}
            </button>
            <button
              onClick={() => setExpanded(expanded === fn.function_name ? null : fn.function_name)}
              className="shrink-0 text-muted-foreground hover:text-foreground"
            >
              {expanded === fn.function_name ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>

          {/* Expanded details */}
          {expanded === fn.function_name && (
            <div className="border-t border-border px-4 py-3 space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div><div className="text-muted-foreground mb-1">Provider</div><div className={cn('font-medium', providerColor(fn.config.provider))}>{fn.config.provider}</div></div>
                <div><div className="text-muted-foreground mb-1">Model</div><div className="font-mono text-foreground">{fn.config.model_id}</div></div>
                <div><div className="text-muted-foreground mb-1">Temperature</div><div className="text-foreground">{fn.config.temperature}</div></div>
                <div><div className="text-muted-foreground mb-1">Max tokens</div><div className="text-foreground">{fmtNumber(fn.config.max_tokens)}</div></div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs bg-muted/30 rounded p-2">
                <div><div className="text-muted-foreground mb-1">Calls (7d)</div><div className="text-foreground font-medium">{fn.usage.calls_7d}</div></div>
                <div><div className="text-muted-foreground mb-1">Input tokens</div><div className="text-foreground">{fmtNumber(fn.usage.input_tokens_7d)}</div></div>
                <div><div className="text-muted-foreground mb-1">Output tokens</div><div className="text-foreground">{fmtNumber(fn.usage.output_tokens_7d)}</div></div>
                <div><div className="text-muted-foreground mb-1">Est. cost (7d)</div><div className="text-green-400 font-medium">${fn.usage.estimated_cost_usd_7d.toFixed(4)}</div></div>
              </div>
              {fn.recommended_tags.length > 0 && (
                <div className="flex items-center gap-1 flex-wrap">
                  <span className="text-xs text-muted-foreground">Tags:</span>
                  {fn.recommended_tags.map(t => (
                    <span key={t} className="rounded bg-primary/10 border border-primary/20 px-1.5 py-0.5 text-[10px] text-primary">{t}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Inline edit panel */}
          {editing === fn.function_name && (
            <div className="border-t border-primary/20 bg-primary/5 px-4 py-4 space-y-3">
              <h4 className="text-xs font-semibold text-foreground">Configure model assignment for {fn.display_name}</h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {/* Provider */}
                <label className="space-y-1">
                  <span className="text-xs text-muted-foreground">Provider</span>
                  <select
                    value={form.provider}
                    onChange={e => {
                      const p = e.target.value
                      const firstModel = PROVIDER_MODELS[p]?.[0] ?? ''
                      setForm(f => ({ ...f, provider: p, model_id: firstModel }))
                    }}
                    className="field px-2 py-1 text-xs w-full"
                  >
                    <option value="anthropic">Anthropic</option>
                    <option value="openai">OpenAI</option>
                    <option value="google">Google</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </label>
                {/* Model */}
                <label className="space-y-1">
                  <span className="text-xs text-muted-foreground">Model</span>
                  <select
                    value={form.model_id}
                    onChange={e => setForm(f => ({ ...f, model_id: e.target.value }))}
                    className="field px-2 py-1 text-xs w-full"
                  >
                    {modelsForProvider.map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                    {/* Allow typing a custom model not in the list */}
                    {!modelsForProvider.includes(form.model_id) && form.model_id && (
                      <option value={form.model_id}>{form.model_id} (custom)</option>
                    )}
                  </select>
                </label>
                {/* Temperature */}
                <label className="space-y-1">
                  <span className="text-xs text-muted-foreground">Temperature ({form.temperature})</span>
                  <input
                    type="range" min={0} max={2} step={0.05}
                    value={form.temperature}
                    onChange={e => setForm(f => ({ ...f, temperature: +e.target.value }))}
                    className="w-full accent-primary"
                  />
                </label>
                {/* Max tokens */}
                <label className="space-y-1">
                  <span className="text-xs text-muted-foreground">Max tokens</span>
                  <input
                    type="number" min={256} max={200000} step={256}
                    value={form.max_tokens}
                    onChange={e => setForm(f => ({ ...f, max_tokens: +e.target.value }))}
                    className="field px-2 py-1 text-xs w-full"
                  />
                </label>
              </div>
              {/* Ollama base URL */}
              {form.provider === 'ollama' && (
                <label className="block space-y-1">
                  <span className="text-xs text-muted-foreground">Ollama Base URL</span>
                  <input
                    type="url"
                    value={form.base_url}
                    onChange={e => setForm(f => ({ ...f, base_url: e.target.value }))}
                    placeholder="http://host.docker.internal:11434"
                    className="field px-2 py-1 text-xs w-full"
                  />
                </label>
              )}
              <div className="flex items-center gap-3">
                <button
                  onClick={save}
                  disabled={saving}
                  className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/90 disabled:opacity-50"
                >
                  {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                  Save config
                </button>
                {msg && <span className={cn('text-xs', msg.startsWith('Error') ? 'text-red-400' : 'text-green-400')}>{msg}</span>}
              </div>
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

  const startEdit = (g: GuardrailConfig) => { setEditing(g.function_name); setForm({ ...g }); setSaveMsg('') }

  const save = async () => {
    if (!editing) return
    setSaving(true)
    try {
      await apiPut(`/api/v2/ai-engine/guardrails/${editing}`, form)
      setSaveMsg('Saved ✓')
      await load()
      setTimeout(() => { setEditing(null); setSaveMsg('') }, 800)
    } catch (e: unknown) {
      setSaveMsg(`Error: ${e instanceof Error ? e.message : 'Failed'}`)
    } finally { setSaving(false) }
  }

  if (loading) return <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center"><RefreshCw className="w-4 h-4 animate-spin" /></div>

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">Configure content filters, rate limits, and safety controls per AI function.</p>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-muted-foreground">
              <th className="px-3 py-2 text-left font-medium">Function</th>
              <th className="px-3 py-2 text-center font-medium">Enabled</th>
              <th className="px-3 py-2 text-right font-medium">Rate/min</th>
              <th className="px-3 py-2 text-right font-medium">Max in</th>
              <th className="px-3 py-2 text-right font-medium">Max out</th>
              <th className="px-3 py-2 text-center font-medium">PII</th>
              <th className="px-3 py-2 text-center font-medium">JSON</th>
              <th className="px-3 py-2 text-left font-medium">Source</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {guardrails.map(g => (
              <tr key={g.function_name} className={cn('border-b border-border', editing === g.function_name ? 'bg-primary/5' : 'hover:bg-muted/30')}>
                <td className="px-3 py-2 font-medium text-foreground">{g.display_name}</td>
                <td className="px-3 py-2 text-center">{g.enabled ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 inline" /> : <AlertTriangle className="w-3.5 h-3.5 text-red-400 inline" />}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{g.rate_limit_per_minute || '∞'}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(g.max_input_tokens)}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(g.max_output_tokens)}</td>
                <td className="px-3 py-2 text-center">{g.pii_masking_enabled ? <Eye className="w-3.5 h-3.5 text-amber-400 inline" /> : <EyeOff className="w-3.5 h-3.5 text-muted-foreground/40 inline" />}</td>
                <td className="px-3 py-2 text-center">{g.require_json_output ? <CheckCircle2 className="w-3.5 h-3.5 text-blue-400 inline" /> : <span className="text-muted-foreground/40">—</span>}</td>
                <td className="px-3 py-2">{g.from_db ? <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] text-blue-400">DB</span> : <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">default</span>}</td>
                <td className="px-3 py-2">
                  <button onClick={() => startEdit(g)} className="rounded px-2 py-1 text-[10px] border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors">Edit</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && (
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-foreground">Editing: {guardrails.find(g => g.function_name === editing)?.display_name}</h3>
            <button onClick={() => setEditing(null)} className="text-muted-foreground hover:text-foreground text-xs">Cancel</button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Rate limit / min</span>
              <input type="number" min={0} max={1000} value={form.rate_limit_per_minute ?? 60} onChange={e => setForm(f => ({ ...f, rate_limit_per_minute: +e.target.value }))} className="field px-2 py-1 text-xs w-full" />
            </label>
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Max input tokens</span>
              <input type="number" min={256} max={200000} value={form.max_input_tokens ?? 32000} onChange={e => setForm(f => ({ ...f, max_input_tokens: +e.target.value }))} className="field px-2 py-1 text-xs w-full" />
            </label>
            <label className="space-y-1">
              <span className="text-xs text-muted-foreground">Max output tokens</span>
              <input type="number" min={256} max={32000} value={form.max_output_tokens ?? 8192} onChange={e => setForm(f => ({ ...f, max_output_tokens: +e.target.value }))} className="field px-2 py-1 text-xs w-full" />
            </label>
          </div>
          <div className="flex items-center gap-4 flex-wrap">
            <label className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={form.enabled ?? true} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
              <span className="text-foreground">Enabled</span>
            </label>
            <label className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={form.pii_masking_enabled ?? false} onChange={e => setForm(f => ({ ...f, pii_masking_enabled: e.target.checked }))} />
              <span className="text-foreground">PII Masking</span>
            </label>
            <label className="flex items-center gap-2 text-xs cursor-pointer">
              <input type="checkbox" checked={form.require_json_output ?? false} onChange={e => setForm(f => ({ ...f, require_json_output: e.target.checked }))} />
              <span className="text-foreground">Require JSON Output</span>
            </label>
          </div>
          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">Block patterns (one regex per line)</span>
            <textarea rows={3} value={(form.block_patterns ?? []).join('\n')} onChange={e => setForm(f => ({ ...f, block_patterns: e.target.value.split('\n').filter(Boolean) }))} className="field px-2 py-1 text-xs w-full font-mono" placeholder="e.g. (?i)drop table" />
          </label>
          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">System prompt override</span>
            <textarea rows={4} value={form.system_prompt_override ?? ''} onChange={e => setForm(f => ({ ...f, system_prompt_override: e.target.value || null }))} className="field px-2 py-1 text-xs w-full" />
          </label>
          <label className="block space-y-1">
            <span className="text-xs text-muted-foreground">Notes</span>
            <input value={form.notes ?? ''} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} className="field px-2 py-1 text-xs w-full" />
          </label>
          <div className="flex items-center gap-3">
            <button onClick={save} disabled={saving} className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/90 disabled:opacity-50">
              {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
              Save guardrail
            </button>
            {saveMsg && <span className={cn('text-xs', saveMsg.startsWith('Error') ? 'text-red-400' : 'text-green-400')}>{saveMsg}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Usage Tab ───────────────────────────────────────────────────────────────

function UsageTab() {
  const [byFn, setByFn] = useState<{ function_name: string; calls: number; input_tokens: number; output_tokens: number; errors: number; cost_usd: number }[]>([])
  const [timeline, setTimeline] = useState<{ time: string; calls: number; tokens: number; cost_usd: number }[]>([])
  const [totals, setTotals] = useState<{ total_calls: number; total_tokens: number; total_cost_usd: number } | null>(null)
  const [period, setPeriod] = useState('24h')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ by_function: typeof byFn; timeline: typeof timeline; total_calls: number; total_tokens: number; total_cost_usd: number }>(`/api/v2/ai-engine/usage?period=${period}`)
      setByFn(data.by_function ?? [])
      setTimeline(data.timeline ?? [])
      setTotals({ total_calls: data.total_calls ?? 0, total_tokens: data.total_tokens ?? 0, total_cost_usd: data.total_cost_usd ?? 0 })
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [period])

  useEffect(() => { load() }, [load])

  if (loading) return <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center"><RefreshCw className="w-4 h-4 animate-spin" /></div>

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted-foreground">Period:</span>
        {['24h', '7d', '30d'].map(p => (
          <button key={p} onClick={() => setPeriod(p)} className={cn('rounded px-2.5 py-1 text-xs transition-colors', period === p ? 'bg-primary text-white' : 'border border-border text-muted-foreground hover:text-foreground hover:bg-muted')}>{p}</button>
        ))}
        <button onClick={load} className="ml-auto rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted"><RefreshCw className="w-3.5 h-3.5" /></button>
      </div>

      {totals && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { icon: Activity, label: 'Total calls', value: fmtNumber(totals.total_calls), color: 'text-foreground' },
            { icon: Cpu, label: 'Total tokens', value: fmtNumber(totals.total_tokens), color: 'text-foreground' },
            { icon: DollarSign, label: 'Est. cost', value: `$${totals.total_cost_usd.toFixed(4)}`, color: 'text-green-400' },
          ].map(({ icon: Icon, label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-card p-3">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1"><Icon className="w-3.5 h-3.5" />{label}</div>
              <div className={cn('text-xl font-bold', color)}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {timeline.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="text-xs font-medium text-muted-foreground mb-3">Calls over time</h3>
          <div className="flex items-end gap-1 h-16">
            {timeline.map((bucket, i) => {
              const max = Math.max(...timeline.map(b => b.calls), 1)
              const height = Math.max((bucket.calls / max) * 100, 4)
              return (
                <div key={i} className="flex-1 rounded-t bg-primary/60 hover:bg-primary transition-colors" style={{ height: `${height}%` }} title={`${bucket.time}: ${bucket.calls} calls`} />
              )
            })}
          </div>
        </div>
      )}

      {byFn.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-6 text-center text-sm text-muted-foreground">No usage data for this period.</div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/40 text-muted-foreground">
              <th className="px-3 py-2 text-left font-medium">Function</th>
              <th className="px-3 py-2 text-right font-medium">Calls</th>
              <th className="px-3 py-2 text-right font-medium">In tokens</th>
              <th className="px-3 py-2 text-right font-medium">Out tokens</th>
              <th className="px-3 py-2 text-right font-medium">Errors</th>
              <th className="px-3 py-2 text-right font-medium">Cost</th>
            </tr>
          </thead>
          <tbody>
            {byFn.sort((a, b) => b.cost_usd - a.cost_usd).map(row => (
              <tr key={row.function_name} className="border-b border-border hover:bg-muted/30">
                <td className="px-3 py-2 font-medium text-foreground">{row.function_name}</td>
                <td className="px-3 py-2 text-right text-foreground">{row.calls}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(row.input_tokens)}</td>
                <td className="px-3 py-2 text-right text-muted-foreground">{fmtNumber(row.output_tokens)}</td>
                <td className="px-3 py-2 text-right">{row.errors > 0 ? <span className="text-red-400">{row.errors}</span> : <span className="text-muted-foreground/40">—</span>}</td>
                <td className="px-3 py-2 text-right text-green-400">${row.cost_usd.toFixed(4)}</td>
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
  const [editText, setEditText] = useState('')
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiGet<{ skill_prompts: SkillPrompt[] }>('/api/v2/ai-engine/skill-prompts')
      setSkills(data.skill_prompts ?? [])
      if (!selected && data.skill_prompts?.length) {
        const first = data.skill_prompts.find(s => s.has_custom_prompt) ?? data.skill_prompts[0]
        setSelected(first.function_name)
        setEditText(first.system_prompt)
      }
    } catch { /* silent */ }
    finally { setLoading(false) }
  }, [selected])

  useEffect(() => { load() }, [load])

  function selectSkill(s: SkillPrompt) {
    setSelected(s.function_name)
    setEditText(s.system_prompt)
    setMsg('')
  }

  async function savePrompt() {
    if (!selected) return
    setSaving(true)
    setMsg('')
    try {
      // Save via guardrail's system_prompt_override field
      await apiPut(`/api/v2/ai-engine/guardrails/${selected}`, {
        system_prompt_override: editText || null,
        // Keep defaults for the other fields
        enabled: true,
        max_input_tokens: 32000,
        max_output_tokens: 8192,
        rate_limit_per_minute: 60,
        block_patterns: [],
        require_json_output: false,
        pii_masking_enabled: false,
        notes: '',
      })
      setMsg('Prompt saved ✓')
      // Update local list
      setSkills(prev => prev.map(s => s.function_name === selected ? { ...s, system_prompt: editText, has_custom_prompt: !!editText } : s))
      setTimeout(() => setMsg(''), 2000)
    } catch (e: unknown) {
      setMsg(`Error: ${e instanceof Error ? e.message : 'Failed'}`)
    } finally {
      setSaving(false)
    }
  }

  const selectedSkill = skills.find(s => s.function_name === selected)

  if (loading) return <div className="flex items-center gap-2 text-muted-foreground py-12 justify-center"><RefreshCw className="w-4 h-4 animate-spin" /></div>

  return (
    <div className="flex gap-4 h-[560px]">
      {/* Left list */}
      <div className="w-48 shrink-0 space-y-0.5 overflow-y-auto">
        {skills.map(s => (
          <button
            key={s.function_name}
            onClick={() => selectSkill(s)}
            className={cn(
              'w-full text-left rounded px-2.5 py-2 text-xs transition-colors',
              selected === s.function_name
                ? 'bg-primary/15 text-primary border border-primary/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
            )}
          >
            <div className="font-medium truncate">{s.display_name}</div>
            {s.has_custom_prompt && <span className="text-[9px] text-primary/70">custom prompt</span>}
          </button>
        ))}
      </div>

      {/* Right editor */}
      <div className="flex-1 min-w-0 flex flex-col gap-2">
        {selectedSkill ? (
          <>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-medium text-foreground">{selectedSkill.display_name}</h3>
                {selectedSkill.has_custom_prompt && (
                  <span className="rounded bg-primary/10 border border-primary/20 px-1.5 py-0.5 text-[10px] text-primary">custom</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {msg && <span className={cn('text-xs', msg.startsWith('Error') ? 'text-red-400' : 'text-green-400')}>{msg}</span>}
                <button
                  onClick={savePrompt}
                  disabled={saving}
                  className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/90 disabled:opacity-50"
                >
                  {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
                  Save
                </button>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Edit the system prompt for this function. Leave blank to use the model default.
            </p>
            <textarea
              value={editText}
              onChange={e => setEditText(e.target.value)}
              className="flex-1 field px-3 py-2 text-xs font-mono resize-none"
              placeholder="Enter a custom system prompt for this AI function…"
            />
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">Select a function to edit its system prompt.</div>
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            AI Engine
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure provider/model per function, guardrails, usage, and system prompts
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-1.5">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-xs text-muted-foreground">14 AI functions</span>
        </div>
      </div>

      <div className="flex gap-1 border-b border-border">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px',
              tab === t.key ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'
            )}
          >
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'functions' && <FunctionsTab />}
        {tab === 'guardrails' && <GuardrailsTab />}
        {tab === 'usage' && <UsageTab />}
        {tab === 'skills' && <SkillsTab />}
      </div>
    </div>
  )
}
