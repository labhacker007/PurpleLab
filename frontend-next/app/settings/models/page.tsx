'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle2,
  XCircle,
  Minus,
  RefreshCw,
  Zap,
  Loader2,
  RotateCcw,
  Eye,
  EyeOff,
  Save,
  DollarSign,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { authFetch } from '@/lib/auth'
import { API_BASE } from '@/lib/api/client'
import {
  getModelConfigs,
  updateModelConfig,
  testModelConfig,
  testAllModelConfigs,
  resetToDefaults,
} from '@/lib/api/model-config'
import type {
  FunctionModelConfig,
  FunctionName,
  LLMProvider,
  ModelConfig,
  TestResult,
} from './types'
import {
  PROVIDER_MODELS,
  PROVIDER_LABELS,
  FUNCTION_DESCRIPTIONS,
} from './types'

// ─── Constants ────────────────────────────────────────────────────────────────

const ALL_FUNCTIONS: FunctionName[] = [
  'AGENT_CHAT',
  'LOG_GENERATION',
  'RULE_ANALYSIS',
  'THREAT_INTEL',
  'SCORING_ASSIST',
  'ATTACK_CHAIN_PLAN',
  'EMBEDDING',
]

// Rough cost per 1M tokens in USD (input+output blended)
const COST_PER_MILLION: Record<string, number> = {
  'claude-opus-4-6': 15,
  'claude-sonnet-4-6': 3,
  'claude-haiku-4-5-20251001': 0.8,
  'gpt-4o': 5,
  'gpt-4o-mini': 0.6,
  'o1': 15,
  'o3-mini': 2,
  'gemini-2.0-flash': 0.075,
  'gemini-1.5-pro': 3.5,
  'gemini-1.5-flash': 0.075,
}

// Estimated daily tokens per function (rough)
const DAILY_TOKENS: Record<FunctionName, number> = {
  AGENT_CHAT: 200_000,
  LOG_GENERATION: 500_000,
  RULE_ANALYSIS: 150_000,
  THREAT_INTEL: 100_000,
  SCORING_ASSIST: 80_000,
  ATTACK_CHAIN_PLAN: 120_000,
  EMBEDDING: 300_000,
}

const PROVIDER_COLORS: Record<LLMProvider, { dot: string; ring: string; label: string }> = {
  anthropic: { dot: 'bg-amber-400', ring: 'ring-amber-400/40', label: 'text-amber-400' },
  openai: { dot: 'bg-green', ring: 'ring-green/40', label: 'text-green' },
  google: { dot: 'bg-blue', ring: 'ring-blue/40', label: 'text-blue' },
  ollama: { dot: 'bg-purple-400', ring: 'ring-purple-400/40', label: 'text-purple-400' },
}

const ENV_VARS: Record<LLMProvider, string | null> = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  google: 'GOOGLE_API_KEY',
  ollama: null,
}

// Default seed configs
const DEFAULT_CONFIG: ModelConfig = {
  provider: 'anthropic',
  model_id: 'claude-sonnet-4-6',
  temperature: 0.7,
  max_tokens: 4096,
  is_active: true,
  status: 'untested',
}

const SEED_CONFIGS: FunctionModelConfig[] = [
  { function_name: 'AGENT_CHAT', display_name: 'Agent Chat', description: FUNCTION_DESCRIPTIONS['AGENT_CHAT'], config: { ...DEFAULT_CONFIG, model_id: 'claude-sonnet-4-6' }, updated_at: new Date().toISOString() },
  { function_name: 'LOG_GENERATION', display_name: 'Log Generation', description: FUNCTION_DESCRIPTIONS['LOG_GENERATION'], config: { ...DEFAULT_CONFIG, model_id: 'claude-haiku-4-5-20251001', temperature: 0.9 }, updated_at: new Date().toISOString() },
  { function_name: 'RULE_ANALYSIS', display_name: 'Rule Analysis', description: FUNCTION_DESCRIPTIONS['RULE_ANALYSIS'], config: { ...DEFAULT_CONFIG, model_id: 'claude-opus-4-6', temperature: 0.3 }, updated_at: new Date().toISOString() },
  { function_name: 'THREAT_INTEL', display_name: 'Threat Intel', description: FUNCTION_DESCRIPTIONS['THREAT_INTEL'], config: { ...DEFAULT_CONFIG, model_id: 'claude-sonnet-4-6' }, updated_at: new Date().toISOString() },
  { function_name: 'SCORING_ASSIST', display_name: 'Scoring Assist', description: FUNCTION_DESCRIPTIONS['SCORING_ASSIST'], config: { ...DEFAULT_CONFIG, model_id: 'claude-haiku-4-5-20251001', temperature: 0.4 }, updated_at: new Date().toISOString() },
  { function_name: 'ATTACK_CHAIN_PLAN', display_name: 'Attack Chain Plan', description: FUNCTION_DESCRIPTIONS['ATTACK_CHAIN_PLAN'], config: { ...DEFAULT_CONFIG, model_id: 'claude-opus-4-6', temperature: 0.8 }, updated_at: new Date().toISOString() },
  { function_name: 'EMBEDDING', display_name: 'Embedding', description: FUNCTION_DESCRIPTIONS['EMBEDDING'], config: { ...DEFAULT_CONFIG, provider: 'openai', model_id: 'gpt-4o-mini', temperature: 0, max_tokens: 512 }, updated_at: new Date().toISOString() },
]

// ─── Status icon ──────────────────────────────────────────────────────────────

function StatusIcon({ status, testing }: { status?: 'ok' | 'error' | 'untested'; testing?: boolean }) {
  if (testing) return <Loader2 className="h-4 w-4 animate-spin text-primary" />
  if (status === 'ok') return <CheckCircle2 className="h-4 w-4 text-green" />
  if (status === 'error') return <XCircle className="h-4 w-4 text-red" />
  return <Minus className="h-4 w-4 text-muted" />
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ type, message }: { type: 'success' | 'error'; message: string }) {
  return (
    <div
      className={cn(
        'fixed bottom-5 right-5 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-xl transition-all duration-300',
        type === 'success' ? 'border-green/40 bg-green/10 text-green' : 'border-red/40 bg-red/10 text-red'
      )}
    >
      {type === 'success' ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <XCircle className="h-4 w-4 shrink-0" />}
      {message}
    </div>
  )
}

// ─── Temperature Slider ───────────────────────────────────────────────────────

function TemperatureSlider({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  const pct = (value / 2) * 100
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <label className="text-[10px] text-muted uppercase tracking-wider">Temp</label>
        <span className="text-[11px] font-mono text-text">{value.toFixed(2)}</span>
      </div>
      <div className="relative h-4 flex items-center">
        <div className="absolute inset-x-0 h-1 rounded-full bg-border" />
        <div className="absolute left-0 h-1 rounded-full bg-primary" style={{ width: `${pct}%` }} />
        <input
          type="range"
          min={0}
          max={2}
          step={0.05}
          value={value}
          onChange={(e) => onChange(parseFloat(e.target.value))}
          className="absolute inset-x-0 h-1 appearance-none bg-transparent cursor-pointer
            [&::-webkit-slider-thumb]:appearance-none
            [&::-webkit-slider-thumb]:h-3.5
            [&::-webkit-slider-thumb]:w-3.5
            [&::-webkit-slider-thumb]:rounded-full
            [&::-webkit-slider-thumb]:bg-primary
            [&::-webkit-slider-thumb]:border-2
            [&::-webkit-slider-thumb]:border-bg
            [&::-webkit-slider-thumb]:shadow
            [&::-webkit-slider-thumb]:hover:scale-110
            [&::-webkit-slider-thumb]:transition-transform"
        />
      </div>
    </div>
  )
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-lg bg-border/60', className)} />
}

// ─── Provider Cards ────────────────────────────────────────────────────────────

interface ProviderKeyState {
  key: string
  show: boolean
  testing: boolean
  status: 'idle' | 'ok' | 'error'
  error?: string
}

function ProviderCards() {
  const providers: LLMProvider[] = ['anthropic', 'openai', 'google', 'ollama']
  const [state, setState] = useState<Record<LLMProvider, ProviderKeyState>>(
    () =>
      Object.fromEntries(
        providers.map((p) => [
          p,
          { key: '', show: false, testing: false, status: 'idle' as const },
        ])
      ) as Record<LLMProvider, ProviderKeyState>
  )

  function update(provider: LLMProvider, patch: Partial<ProviderKeyState>) {
    setState((s) => ({ ...s, [provider]: { ...s[provider], ...patch } }))
  }

  async function testProvider(provider: LLMProvider) {
    update(provider, { testing: true, status: 'idle' })
    try {
      const res = await authFetch(`${API_BASE}/api/v2/model-config/test-all`, {
        method: 'POST',
      })
      if (res.ok) {
        update(provider, { testing: false, status: 'ok' })
      } else {
        update(provider, { testing: false, status: 'error', error: `HTTP ${res.status}` })
      }
    } catch (err) {
      update(provider, {
        testing: false,
        status: 'error',
        error: err instanceof Error ? err.message : 'Connection failed',
      })
    }
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {providers.map((provider) => {
        const colors = PROVIDER_COLORS[provider]
        const s = state[provider]
        const isConfigured = provider === 'ollama' || s.key.length > 0
        const envVar = ENV_VARS[provider]

        return (
          <Card key={provider} className={cn('transition-all', s.status === 'ok' && 'border-green/30', s.status === 'error' && 'border-red/30')}>
            <CardContent className="p-4 space-y-3">
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={cn('h-2.5 w-2.5 rounded-full', colors.dot)} />
                  <span className="text-sm font-semibold text-text">
                    {PROVIDER_LABELS[provider]}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  {s.status === 'ok' && <CheckCircle2 className="h-4 w-4 text-green" />}
                  {s.status === 'error' && <XCircle className="h-4 w-4 text-red" />}
                  <span
                    className={cn(
                      'text-[10px] font-medium rounded-full px-2 py-0.5 border',
                      isConfigured
                        ? 'border-green/30 bg-green/10 text-green'
                        : 'border-border bg-bg text-muted'
                    )}
                  >
                    {isConfigured ? 'configured' : 'not set'}
                  </span>
                </div>
              </div>

              {/* API Key input */}
              {provider !== 'ollama' ? (
                <div className="space-y-1">
                  <label className="text-[10px] text-muted">{envVar ?? 'API Key'}</label>
                  <div className="relative">
                    <Input
                      type={s.show ? 'text' : 'password'}
                      value={s.key}
                      onChange={(e) => update(provider, { key: e.target.value })}
                      placeholder={`Leave blank to use ${envVar}`}
                      className="pr-8 text-xs h-8"
                    />
                    <button
                      onClick={() => update(provider, { show: !s.show })}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                    >
                      {s.show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-muted py-1">
                  No API key required. Ollama runs locally.
                </div>
              )}

              {/* Error message */}
              {s.status === 'error' && s.error && (
                <p className="text-[10px] text-red">{s.error}</p>
              )}

              {/* Test button */}
              <Button
                size="sm"
                variant="outline"
                className="w-full h-7 text-xs"
                onClick={() => testProvider(provider)}
                disabled={s.testing}
              >
                {s.testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                {s.testing ? 'Testing…' : 'Test Connection'}
              </Button>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

// ─── Cost Panel ───────────────────────────────────────────────────────────────

function CostPanel({ configs }: { configs: FunctionModelConfig[] }) {
  const rows = configs.map((c) => {
    const dailyTokens = DAILY_TOKENS[c.function_name] ?? 50_000
    const rate = COST_PER_MILLION[c.config.model_id] ?? 3
    const dailyCost = (dailyTokens / 1_000_000) * rate
    const monthlyCost = dailyCost * 30
    return { fn: c.function_name, displayName: c.display_name, model: c.config.model_id, dailyTokens, monthlyCost, rate }
  })

  const totalMonthly = rows.reduce((sum, r) => sum + r.monthlyCost, 0)

  return (
    <Card className="h-fit">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <DollarSign className="h-4 w-4 text-muted" />
          Cost Estimation
        </CardTitle>
        <p className="text-[11px] text-muted">Based on estimated daily usage at current model rates.</p>
      </CardHeader>
      <CardContent className="space-y-2">
        {rows.map((r) => (
          <div key={r.fn} className="flex items-center justify-between py-1 border-b border-border last:border-0">
            <div className="min-w-0">
              <div className="text-xs text-text font-medium">{r.displayName}</div>
              <div className="text-[10px] text-muted font-mono truncate">{r.model}</div>
            </div>
            <div className="text-right shrink-0 pl-2">
              <div className="text-xs font-mono text-text">${r.monthlyCost.toFixed(2)}/mo</div>
              <div className="text-[10px] text-muted">{(r.dailyTokens / 1000).toFixed(0)}k tok/day</div>
            </div>
          </div>
        ))}

        {/* Total */}
        <div className="pt-2 flex items-center justify-between">
          <span className="text-xs font-semibold text-text">Estimated Total</span>
          <span className="text-sm font-bold text-primary font-mono">
            ${totalMonthly.toFixed(2)}/mo
          </span>
        </div>

        <p className="text-[10px] text-muted pt-1">
          Rates: GPT-4o $5, Claude Sonnet $3, Gemini Flash $0.075 per 1M tokens. Estimates only.
        </p>
      </CardContent>
    </Card>
  )
}

// ─── Function Row ─────────────────────────────────────────────────────────────

interface DraftRow {
  provider: LLMProvider
  model_id: string
  temperature: number
  max_tokens: number
  is_active: boolean
  dirty: boolean
}

function FunctionRow({
  item,
  draft,
  onChange,
  onSave,
  onTest,
  saving,
  testing,
}: {
  item: FunctionModelConfig
  draft: DraftRow
  onChange: (patch: Partial<DraftRow>) => void
  onSave: () => void
  onTest: () => void
  saving: boolean
  testing: boolean
}) {
  return (
    <div
      className={cn(
        'rounded-xl border bg-card p-4 space-y-4 transition-colors',
        draft.dirty ? 'border-primary/40' : 'border-border'
      )}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold text-primary">{item.function_name}</span>
            {draft.dirty && (
              <span className="text-[10px] rounded-full px-1.5 py-0.5 bg-primary/20 text-primary border border-primary/30">
                unsaved
              </span>
            )}
          </div>
          <p className="text-[11px] text-muted mt-0.5">{item.description}</p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <StatusIcon status={item.config.status} testing={testing} />
          {/* Active toggle */}
          <button
            role="switch"
            aria-checked={draft.is_active}
            onClick={() => onChange({ is_active: !draft.is_active, dirty: true })}
            title={draft.is_active ? 'Active' : 'Inactive'}
            className={cn(
              'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none',
              draft.is_active ? 'bg-primary' : 'bg-border'
            )}
          >
            <span
              className={cn(
                'inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform',
                draft.is_active ? 'translate-x-5' : 'translate-x-0.5'
              )}
            />
          </button>
        </div>
      </div>

      {/* Controls grid */}
      <div className="grid grid-cols-[1fr_1fr_140px_100px] gap-3 items-end">
        {/* Provider */}
        <div className="space-y-1">
          <label className="text-[10px] text-muted uppercase tracking-wider">Provider</label>
          <select
            value={draft.provider}
            onChange={(e) => {
              const p = e.target.value as LLMProvider
              const models = PROVIDER_MODELS[p]
              onChange({ provider: p, model_id: models[0] ?? '', dirty: true })
            }}
            className="h-8 w-full rounded-lg border border-border bg-bg px-2.5 text-xs text-text focus:outline-none focus:ring-2 focus:ring-primary"
          >
            {(Object.keys(PROVIDER_LABELS) as LLMProvider[]).map((p) => (
              <option key={p} value={p}>{PROVIDER_LABELS[p]}</option>
            ))}
          </select>
        </div>

        {/* Model */}
        <div className="space-y-1">
          <label className="text-[10px] text-muted uppercase tracking-wider">Model</label>
          <select
            value={draft.model_id}
            onChange={(e) => onChange({ model_id: e.target.value, dirty: true })}
            className="h-8 w-full rounded-lg border border-border bg-bg px-2.5 text-xs text-text focus:outline-none focus:ring-2 focus:ring-primary"
          >
            {PROVIDER_MODELS[draft.provider].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>

        {/* Temperature */}
        <div className="space-y-1 pb-0.5">
          <TemperatureSlider value={draft.temperature} onChange={(v) => onChange({ temperature: v, dirty: true })} />
        </div>

        {/* Max tokens */}
        <div className="space-y-1">
          <label className="text-[10px] text-muted uppercase tracking-wider">Max Tokens</label>
          <Input
            type="number"
            min={128}
            max={200000}
            value={draft.max_tokens}
            onChange={(e) => onChange({ max_tokens: parseInt(e.target.value, 10) || 1, dirty: true })}
            className="h-8 text-xs"
          />
        </div>
      </div>

      {/* Error */}
      {item.config.status === 'error' && item.config.error_message && (
        <div className="rounded-lg border border-red/40 bg-red/5 px-3 py-2 text-[11px] text-red">
          {item.config.error_message}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          className="h-7 text-xs"
          onClick={onTest}
          disabled={testing || saving}
        >
          {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
          {testing ? 'Testing…' : 'Test'}
        </Button>
        {draft.dirty && (
          <Button
            size="sm"
            className="h-7 text-xs"
            onClick={onSave}
            disabled={saving}
          >
            {saving ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
            {saving ? 'Saving…' : 'Save'}
          </Button>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ModelConfigPage() {
  const [configs, setConfigs] = useState<FunctionModelConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [drafts, setDrafts] = useState<Record<string, DraftRow>>({})

  const [testingFn, setTestingFn] = useState<FunctionName | null>(null)
  const [savingFn, setSavingFn] = useState<FunctionName | null>(null)
  const [testingAll, setTestingAll] = useState(false)
  const [savingAll, setSavingAll] = useState(false)
  const [resetting, setResetting] = useState(false)

  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  function showToast(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }

  function seedDrafts(cfgs: FunctionModelConfig[]) {
    const d: Record<string, DraftRow> = {}
    for (const c of cfgs) {
      d[c.function_name] = {
        provider: c.config.provider,
        model_id: c.config.model_id,
        temperature: c.config.temperature,
        max_tokens: c.config.max_tokens,
        is_active: c.config.is_active,
        dirty: false,
      }
    }
    setDrafts(d)
  }

  const loadConfigs = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getModelConfigs()
      const normalized = Array.isArray(data) ? data : (data as { configs?: FunctionModelConfig[] }).configs ?? []
      setConfigs(normalized)
      seedDrafts(normalized)
    } catch {
      setConfigs(SEED_CONFIGS)
      seedDrafts(SEED_CONFIGS)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadConfigs()
  }, [loadConfigs])

  function patchDraft(fn: FunctionName, patch: Partial<DraftRow>) {
    setDrafts((d) => ({ ...d, [fn]: { ...d[fn], ...patch } }))
  }

  async function handleSave(fn: FunctionName) {
    const draft = drafts[fn]
    if (!draft) return
    setSavingFn(fn)
    try {
      const config: ModelConfig = {
        provider: draft.provider,
        model_id: draft.model_id,
        temperature: draft.temperature,
        max_tokens: draft.max_tokens,
        is_active: draft.is_active,
        status: 'untested',
      }
      const updated = await updateModelConfig(fn, config)
      setConfigs((prev) => prev.map((c) => (c.function_name === fn ? updated : c)))
      patchDraft(fn, { dirty: false })
      showToast('success', `${fn} saved.`)
    } catch {
      // Optimistic local update
      setConfigs((prev) =>
        prev.map((c) =>
          c.function_name === fn
            ? { ...c, config: { ...c.config, ...draft, status: 'untested' }, updated_at: new Date().toISOString() }
            : c
        )
      )
      patchDraft(fn, { dirty: false })
      showToast('error', 'Save failed — applied locally only. Check API.')
    } finally {
      setSavingFn(null)
    }
  }

  async function handleTest(fn: FunctionName) {
    setTestingFn(fn)
    try {
      const result: TestResult = await testModelConfig(fn)
      setConfigs((prev) =>
        prev.map((c) =>
          c.function_name === fn
            ? { ...c, config: { ...c.config, status: result.ok ? 'ok' : 'error', error_message: result.error } }
            : c
        )
      )
      showToast(
        result.ok ? 'success' : 'error',
        result.ok ? `${fn}: OK (${result.latency_ms}ms)` : `${fn}: ${result.error ?? 'failed'}`
      )
    } catch (err) {
      setConfigs((prev) =>
        prev.map((c) =>
          c.function_name === fn
            ? { ...c, config: { ...c.config, status: 'error', error_message: err instanceof Error ? err.message : 'Test failed' } }
            : c
        )
      )
      showToast('error', err instanceof Error ? err.message : 'Test failed.')
    } finally {
      setTestingFn(null)
    }
  }

  async function handleTestAll() {
    setTestingAll(true)
    try {
      const results = await testAllModelConfigs()
      setConfigs((prev) =>
        prev.map((c) => {
          const r = results[c.function_name]
          if (!r) return c
          return { ...c, config: { ...c.config, status: r.ok ? 'ok' : 'error' } }
        })
      )
      const passed = Object.values(results).filter((r) => r.ok).length
      showToast('success', `Test All: ${passed}/${Object.keys(results).length} passed.`)
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Test All failed.')
    } finally {
      setTestingAll(false)
    }
  }

  async function handleSaveAll() {
    const dirtyFns = Object.entries(drafts)
      .filter(([, d]) => d.dirty)
      .map(([fn]) => fn as FunctionName)
    if (dirtyFns.length === 0) {
      showToast('success', 'No unsaved changes.')
      return
    }
    setSavingAll(true)
    let saved = 0
    for (const fn of dirtyFns) {
      try {
        await handleSave(fn)
        saved++
      } catch {
        // individual errors already handled
      }
    }
    showToast('success', `Saved ${saved}/${dirtyFns.length} configs.`)
    setSavingAll(false)
  }

  async function handleReset() {
    if (!window.confirm('Reset all model configs to defaults? This cannot be undone.')) return
    setResetting(true)
    try {
      await resetToDefaults()
      await loadConfigs()
      showToast('success', 'All configs reset to defaults.')
    } catch {
      setConfigs(SEED_CONFIGS)
      seedDrafts(SEED_CONFIGS)
      showToast('error', 'Reset failed — reverted to seed data.')
    } finally {
      setResetting(false)
    }
  }

  const dirtyCount = Object.values(drafts).filter((d) => d.dirty).length
  const statusSummary = {
    ok: configs.filter((c) => c.config.status === 'ok').length,
    error: configs.filter((c) => c.config.status === 'error').length,
    untested: configs.filter((c) => !c.config.status || c.config.status === 'untested').length,
  }

  return (
    <>
      {toast && <Toast {...toast} />}

      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-text">Model Routing</h1>
            <p className="text-sm text-muted mt-1">
              Configure AI providers and per-function model assignments.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={handleReset} disabled={resetting || loading}>
              {resetting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
              Reset Defaults
            </Button>
            <Button variant="outline" size="sm" onClick={handleTestAll} disabled={testingAll || loading}>
              {testingAll ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
              {testingAll ? 'Testing All…' : 'Test All'}
            </Button>
            {dirtyCount > 0 && (
              <Button size="sm" onClick={handleSaveAll} disabled={savingAll}>
                {savingAll ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                Save All ({dirtyCount})
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={loadConfigs} disabled={loading}>
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </Button>
          </div>
        </div>

        {/* Status summary */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Healthy', count: statusSummary.ok, color: 'text-green', dot: 'bg-green' },
            { label: 'Errors', count: statusSummary.error, color: 'text-red', dot: 'bg-red' },
            { label: 'Untested', count: statusSummary.untested, color: 'text-muted', dot: 'bg-muted' },
          ].map(({ label, count, color, dot }) => (
            <div key={label} className="flex items-center gap-3 rounded-xl border border-border bg-card p-4">
              <span className={cn('h-2.5 w-2.5 rounded-full shrink-0', dot)} />
              <div>
                <div className={cn('text-xl font-bold tabular-nums', color)}>{count}</div>
                <div className="text-xs text-muted">{label}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Provider API key cards */}
        <div>
          <h2 className="text-sm font-semibold text-text mb-3">Provider Configuration</h2>
          <ProviderCards />
        </div>

        {/* Function routing + cost panel */}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_280px] gap-6 items-start">
          {/* Function rows */}
          <div>
            <h2 className="text-sm font-semibold text-text mb-3">Function Routing</h2>
            {loading ? (
              <div className="space-y-3">
                {[...Array(7)].map((_, i) => <Skeleton key={i} className="h-44" />)}
              </div>
            ) : (
              <div className="space-y-3">
                {configs.map((item) => {
                  const draft = drafts[item.function_name]
                  if (!draft) return null
                  return (
                    <FunctionRow
                      key={item.function_name}
                      item={item}
                      draft={draft}
                      onChange={(patch) => patchDraft(item.function_name, patch)}
                      onSave={() => handleSave(item.function_name)}
                      onTest={() => handleTest(item.function_name)}
                      saving={savingFn === item.function_name}
                      testing={testingFn === item.function_name}
                    />
                  )
                })}
              </div>
            )}
          </div>

          {/* Cost estimation sidebar */}
          <div className="xl:sticky xl:top-6">
            {loading ? (
              <Skeleton className="h-96" />
            ) : (
              <CostPanel configs={configs} />
            )}
          </div>
        </div>

        <p className="text-[11px] text-muted">
          Provider API keys entered here are stored only for this session. Set permanent keys via environment variables.
          Use &ldquo;Test All&rdquo; to verify all connections before running simulations.
        </p>
      </div>
    </>
  )
}
