'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle2,
  XCircle,
  Minus,
  RefreshCw,
  Zap,
  ChevronRight,
  Loader2,
  RotateCcw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Drawer } from '@/components/ui/Drawer'
import { ModelBadge } from '@/components/ModelBadge'
import { cn } from '@/lib/utils'
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

// ─── Default config used when seeding local state ────────────────────────────
const DEFAULT_CONFIG: ModelConfig = {
  provider: 'anthropic',
  model_id: 'claude-sonnet-4-6',
  temperature: 0.7,
  max_tokens: 4096,
  is_active: true,
  status: 'untested',
}

const SEED_CONFIGS: FunctionModelConfig[] = [
  {
    function_name: 'AGENT_CHAT',
    display_name: 'Agent Chat',
    description: FUNCTION_DESCRIPTIONS['AGENT_CHAT'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-sonnet-4-6' },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'LOG_GENERATION',
    display_name: 'Log Generation',
    description: FUNCTION_DESCRIPTIONS['LOG_GENERATION'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-haiku-4-5-20251001', temperature: 0.9 },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'THREAT_INTEL',
    display_name: 'Threat Intel',
    description: FUNCTION_DESCRIPTIONS['THREAT_INTEL'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-sonnet-4-6' },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'RULE_ANALYSIS',
    display_name: 'Rule Analysis',
    description: FUNCTION_DESCRIPTIONS['RULE_ANALYSIS'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-opus-4-6', temperature: 0.3 },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'EMBEDDING',
    display_name: 'Embedding',
    description: FUNCTION_DESCRIPTIONS['EMBEDDING'],
    config: {
      ...DEFAULT_CONFIG,
      provider: 'openai',
      model_id: 'gpt-4o-mini',
      temperature: 0,
      max_tokens: 512,
    },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'SCORING_ASSIST',
    display_name: 'Scoring Assist',
    description: FUNCTION_DESCRIPTIONS['SCORING_ASSIST'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-haiku-4-5-20251001', temperature: 0.4 },
    updated_at: new Date().toISOString(),
  },
  {
    function_name: 'ATTACK_CHAIN_PLAN',
    display_name: 'Attack Chain Plan',
    description: FUNCTION_DESCRIPTIONS['ATTACK_CHAIN_PLAN'],
    config: { ...DEFAULT_CONFIG, model_id: 'claude-opus-4-6', temperature: 0.8 },
    updated_at: new Date().toISOString(),
  },
]

// ─── Status icon ──────────────────────────────────────────────────────────────
function StatusIcon({
  status,
  testing,
}: {
  status?: 'ok' | 'error' | 'untested'
  testing?: boolean
}) {
  if (testing) {
    return <Loader2 className="h-4 w-4 animate-spin text-primary" />
  }
  if (status === 'ok')
    return <CheckCircle2 className="h-4 w-4 text-green" />
  if (status === 'error')
    return <XCircle className="h-4 w-4 text-red" />
  return <Minus className="h-4 w-4 text-muted" />
}

// ─── Temperature slider ───────────────────────────────────────────────────────
function TemperatureSlider({
  value,
  onChange,
}: {
  value: number
  onChange: (v: number) => void
}) {
  const pct = (value / 2) * 100
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <label className="text-xs text-muted">Temperature</label>
        <span className="text-xs font-mono text-text">{value.toFixed(2)}</span>
      </div>
      <div className="relative h-5 flex items-center">
        <div className="absolute inset-x-0 h-1.5 rounded-full bg-border" />
        <div
          className="absolute left-0 h-1.5 rounded-full bg-primary"
          style={{ width: `${pct}%` }}
        />
        <input
          type="range"
          min={0}
          max={2}
          step={0.05}
          value={value}
          onChange={(e) => onChange(parseFloat(e.target.value))}
          className="absolute inset-x-0 h-1.5 appearance-none bg-transparent cursor-pointer
            [&::-webkit-slider-thumb]:appearance-none
            [&::-webkit-slider-thumb]:h-4
            [&::-webkit-slider-thumb]:w-4
            [&::-webkit-slider-thumb]:rounded-full
            [&::-webkit-slider-thumb]:bg-primary
            [&::-webkit-slider-thumb]:border-2
            [&::-webkit-slider-thumb]:border-bg
            [&::-webkit-slider-thumb]:shadow-md
            [&::-webkit-slider-thumb]:transition-transform
            [&::-webkit-slider-thumb]:hover:scale-110"
        />
      </div>
      <div className="flex justify-between text-[10px] text-muted">
        <span>Precise</span>
        <span>Balanced</span>
        <span>Creative</span>
      </div>
    </div>
  )
}

// ─── Config modal/drawer content ─────────────────────────────────────────────
interface ConfigDrawerProps {
  item: FunctionModelConfig
  onSave: (fn: FunctionName, config: ModelConfig) => Promise<void>
  onTest: (fn: FunctionName) => Promise<void>
  testing: boolean
  saving: boolean
}

function ConfigDrawerContent({
  item,
  onSave,
  onTest,
  testing,
  saving,
}: ConfigDrawerProps) {
  const [draft, setDraft] = useState<ModelConfig>({ ...item.config })
  const [apiKey, setApiKey] = useState('')

  // Reset draft when item changes
  useEffect(() => {
    setDraft({ ...item.config })
    setApiKey('')
  }, [item])

  function setProvider(provider: LLMProvider) {
    const models = PROVIDER_MODELS[provider]
    setDraft((d) => ({
      ...d,
      provider,
      model_id: models[0] ?? '',
      base_url: provider === 'ollama' ? 'http://localhost:11434' : undefined,
    }))
  }

  function setField<K extends keyof ModelConfig>(key: K, value: ModelConfig[K]) {
    setDraft((d) => ({ ...d, [key]: value }))
  }

  const apiKeyPlaceholder: Record<LLMProvider, string> = {
    anthropic: 'Uses ANTHROPIC_API_KEY env var',
    openai: 'Uses OPENAI_API_KEY env var',
    google: 'Uses GOOGLE_API_KEY env var',
    ollama: 'No API key required',
  }

  const showBaseUrl = draft.provider === 'ollama'

  return (
    <div className="p-5 space-y-6">
      {/* Function info */}
      <div className="rounded-lg bg-bg border border-border p-4">
        <div className="text-xs font-mono text-primary mb-1">
          {item.function_name}
        </div>
        <div className="text-sm text-text font-medium">{item.display_name}</div>
        <div className="text-xs text-muted mt-1">{item.description}</div>
      </div>

      {/* Provider selector */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-muted uppercase tracking-wider">
          Provider
        </label>
        <div className="grid grid-cols-2 gap-2">
          {(Object.keys(PROVIDER_LABELS) as LLMProvider[]).map((p) => (
            <button
              key={p}
              onClick={() => setProvider(p)}
              className={cn(
                'flex items-center gap-2 rounded-lg border px-3 py-2.5 text-sm transition-colors text-left',
                draft.provider === p
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border bg-bg text-muted hover:border-border hover:text-text'
              )}
            >
              <ProviderDot provider={p} />
              {PROVIDER_LABELS[p]}
            </button>
          ))}
        </div>
      </div>

      {/* Model selector */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted uppercase tracking-wider">
          Model
        </label>
        <select
          value={draft.model_id}
          onChange={(e) => setField('model_id', e.target.value)}
          className="h-9 w-full rounded-lg border border-border bg-bg px-3 text-sm text-text focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary"
        >
          {PROVIDER_MODELS[draft.provider].map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </div>

      {/* API Key */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted uppercase tracking-wider">
          API Key Override
        </label>
        <Input
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={apiKeyPlaceholder[draft.provider]}
          disabled={draft.provider === 'ollama'}
        />
        <p className="text-[10px] text-muted">
          Leave blank to use the environment variable default.
        </p>
      </div>

      {/* Base URL (Ollama only) */}
      {showBaseUrl && (
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted uppercase tracking-wider">
            Base URL
          </label>
          <Input
            value={draft.base_url ?? 'http://localhost:11434'}
            onChange={(e) => setField('base_url', e.target.value)}
            placeholder="http://localhost:11434"
          />
        </div>
      )}

      {/* Temperature */}
      <TemperatureSlider
        value={draft.temperature}
        onChange={(v) => setField('temperature', v)}
      />

      {/* Max Tokens */}
      <div className="space-y-1.5">
        <label className="text-xs font-medium text-muted uppercase tracking-wider">
          Max Tokens
        </label>
        <Input
          type="number"
          min={1}
          max={200000}
          value={draft.max_tokens}
          onChange={(e) =>
            setField('max_tokens', parseInt(e.target.value, 10) || 1)
          }
        />
      </div>

      {/* Active toggle */}
      <div className="flex items-center justify-between rounded-lg border border-border bg-bg p-3">
        <div>
          <div className="text-sm text-text font-medium">Active</div>
          <div className="text-xs text-muted">Use this model for the function</div>
        </div>
        <button
          role="switch"
          aria-checked={draft.is_active}
          onClick={() => setField('is_active', !draft.is_active)}
          className={cn(
            'relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary',
            draft.is_active ? 'bg-primary' : 'bg-border'
          )}
        >
          <span
            className={cn(
              'inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform',
              draft.is_active ? 'translate-x-6' : 'translate-x-1'
            )}
          />
        </button>
      </div>

      {/* Test result display */}
      {item.config.status === 'error' && item.config.error_message && (
        <div className="rounded-lg border border-red/40 bg-red/10 p-3 text-xs text-red">
          <span className="font-medium">Error:</span> {item.config.error_message}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-2 pt-1">
        <Button
          variant="outline"
          className="flex-1"
          onClick={() => onTest(item.function_name)}
          disabled={testing || saving}
        >
          {testing ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Zap className="h-3.5 w-3.5" />
          )}
          {testing ? 'Testing…' : 'Test'}
        </Button>
        <Button
          className="flex-1"
          onClick={() => onSave(item.function_name, draft)}
          disabled={saving || testing}
        >
          {saving ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : null}
          {saving ? 'Saving…' : 'Save Config'}
        </Button>
      </div>
    </div>
  )
}

function ProviderDot({ provider }: { provider: LLMProvider }) {
  const colors: Record<LLMProvider, string> = {
    anthropic: 'bg-amber-400',
    openai: 'bg-green',
    google: 'bg-blue',
    ollama: 'bg-purple-400',
  }
  return (
    <span className={cn('h-2 w-2 rounded-full shrink-0', colors[provider])} />
  )
}

// ─── Relative date formatter ──────────────────────────────────────────────────
function relativeDate(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function ModelConfigPage() {
  const [configs, setConfigs] = useState<FunctionModelConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [selectedFn, setSelectedFn] = useState<FunctionName | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const [testingFn, setTestingFn] = useState<FunctionName | null>(null)
  const [savingFn, setSavingFn] = useState<FunctionName | null>(null)
  const [testingAll, setTestingAll] = useState(false)
  const [resetting, setResetting] = useState(false)

  const [toast, setToast] = useState<{
    type: 'success' | 'error'
    message: string
  } | null>(null)

  function showToast(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }

  const loadConfigs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await getModelConfigs()
      setConfigs(data)
    } catch {
      // API not available — use seed data for local development
      setConfigs(SEED_CONFIGS)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadConfigs()
  }, [loadConfigs])

  function openDrawer(fn: FunctionName) {
    setSelectedFn(fn)
    setDrawerOpen(true)
  }

  function closeDrawer() {
    setDrawerOpen(false)
    // Keep selectedFn so drawer animates out with content
  }

  async function handleSave(fn: FunctionName, config: ModelConfig) {
    setSavingFn(fn)
    try {
      const updated = await updateModelConfig(fn, config)
      setConfigs((prev) =>
        prev.map((c) => (c.function_name === fn ? updated : c))
      )
      showToast('success', `${fn} config saved.`)
      closeDrawer()
    } catch (err) {
      // Optimistic update for dev without backend
      setConfigs((prev) =>
        prev.map((c) =>
          c.function_name === fn
            ? {
                ...c,
                config: { ...config, status: 'untested' },
                updated_at: new Date().toISOString(),
              }
            : c
        )
      )
      showToast(
        'error',
        err instanceof Error ? err.message : 'Failed to save. Check API.'
      )
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
            ? {
                ...c,
                config: {
                  ...c.config,
                  status: result.ok ? 'ok' : 'error',
                  error_message: result.error,
                },
              }
            : c
        )
      )
      showToast(
        result.ok ? 'success' : 'error',
        result.ok
          ? `${fn}: OK (${result.latency_ms}ms)`
          : `${fn}: ${result.error ?? 'failed'}`
      )
    } catch (err) {
      setConfigs((prev) =>
        prev.map((c) =>
          c.function_name === fn
            ? {
                ...c,
                config: {
                  ...c.config,
                  status: 'error',
                  error_message:
                    err instanceof Error ? err.message : 'Test failed',
                },
              }
            : c
        )
      )
      showToast(
        'error',
        err instanceof Error ? err.message : 'Test failed. Check API.'
      )
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
          return {
            ...c,
            config: {
              ...c.config,
              status: r.ok ? 'ok' : 'error',
            },
          }
        })
      )
      const passed = Object.values(results).filter((r) => r.ok).length
      showToast(
        'success',
        `Test All: ${passed}/${Object.keys(results).length} passed.`
      )
    } catch (err) {
      showToast(
        'error',
        err instanceof Error ? err.message : 'Test All failed.'
      )
    } finally {
      setTestingAll(false)
    }
  }

  async function handleReset() {
    if (
      !window.confirm(
        'Reset all model configs to defaults? This cannot be undone.'
      )
    )
      return
    setResetting(true)
    try {
      await resetToDefaults()
      await loadConfigs()
      showToast('success', 'All configs reset to defaults.')
    } catch {
      setConfigs(SEED_CONFIGS)
      showToast('error', 'Reset failed — reverted to seed data.')
    } finally {
      setResetting(false)
    }
  }

  const selectedItem = configs.find((c) => c.function_name === selectedFn)

  const statusSummary = {
    ok: configs.filter((c) => c.config.status === 'ok').length,
    error: configs.filter((c) => c.config.status === 'error').length,
    untested: configs.filter(
      (c) => !c.config.status || c.config.status === 'untested'
    ).length,
  }

  return (
    <>
      {/* Toast */}
      {toast && (
        <div
          className={cn(
            'fixed bottom-5 right-5 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-xl transition-all duration-300',
            toast.type === 'success'
              ? 'border-green/40 bg-green/10 text-green'
              : 'border-red/40 bg-red/10 text-red'
          )}
        >
          {toast.type === 'success' ? (
            <CheckCircle2 className="h-4 w-4 shrink-0" />
          ) : (
            <XCircle className="h-4 w-4 shrink-0" />
          )}
          {toast.message}
        </div>
      )}

      <div className="space-y-5">
        {/* Page header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-bold text-text">Model Routing</h1>
            <p className="text-sm text-muted mt-1">
              Configure which AI model handles each platform function.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleReset}
              disabled={resetting || loading}
            >
              {resetting ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RotateCcw className="h-3.5 w-3.5" />
              )}
              Reset Defaults
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleTestAll}
              disabled={testingAll || loading}
            >
              {testingAll ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5" />
              )}
              {testingAll ? 'Testing All…' : 'Test All'}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={loadConfigs}
              disabled={loading}
            >
              <RefreshCw
                className={cn('h-3.5 w-3.5', loading && 'animate-spin')}
              />
            </Button>
          </div>
        </div>

        {/* Status summary */}
        <div className="grid grid-cols-3 gap-3">
          <StatusCard
            label="Healthy"
            count={statusSummary.ok}
            color="text-green"
            dot="bg-green"
          />
          <StatusCard
            label="Errors"
            count={statusSummary.error}
            color="text-red"
            dot="bg-red"
          />
          <StatusCard
            label="Untested"
            count={statusSummary.untested}
            color="text-muted"
            dot="bg-muted"
          />
        </div>

        {/* Error state */}
        {error && (
          <div className="rounded-lg border border-red/40 bg-red/10 p-4 text-sm text-red">
            {error}
          </div>
        )}

        {/* Table */}
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[2fr_3fr_2fr_1fr_80px] gap-4 border-b border-border px-5 py-3 text-xs font-medium uppercase tracking-wider text-muted">
            <span>Function</span>
            <span>Current Model</span>
            <span>Description</span>
            <span>Updated</span>
            <span className="text-center">Status</span>
          </div>

          {/* Rows */}
          {loading ? (
            <div className="flex items-center justify-center py-16 gap-2 text-sm text-muted">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading configs…
            </div>
          ) : (
            <div className="divide-y divide-border">
              {configs.map((item) => {
                const isTestingRow = testingFn === item.function_name
                return (
                  <button
                    key={item.function_name}
                    onClick={() => openDrawer(item.function_name)}
                    className={cn(
                      'grid w-full grid-cols-[2fr_3fr_2fr_1fr_80px] gap-4 px-5 py-4 text-left',
                      'hover:bg-bg transition-colors group',
                      selectedFn === item.function_name &&
                        drawerOpen &&
                        'bg-primary/5 border-l-2 border-l-primary'
                    )}
                  >
                    {/* Function name */}
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-xs font-mono font-medium text-text truncate">
                        {item.function_name}
                      </span>
                      <ChevronRight className="h-3 w-3 text-muted opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                    </div>

                    {/* Model badge */}
                    <div className="flex items-center min-w-0">
                      <ModelBadge
                        provider={item.config.provider}
                        model={item.config.model_id}
                        size="sm"
                      />
                    </div>

                    {/* Description */}
                    <div className="flex items-center min-w-0">
                      <span className="text-xs text-muted truncate">
                        {item.description}
                      </span>
                    </div>

                    {/* Updated */}
                    <div className="flex items-center">
                      <span className="text-xs text-muted">
                        {relativeDate(item.updated_at)}
                      </span>
                    </div>

                    {/* Status */}
                    <div className="flex items-center justify-center">
                      <StatusIcon
                        status={item.config.status}
                        testing={isTestingRow}
                      />
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>

        <p className="text-[11px] text-muted">
          Click any row to configure. Changes apply immediately after saving.
          Use &ldquo;Test All&rdquo; to verify all connections before running simulations.
        </p>
      </div>

      {/* Config drawer */}
      <Drawer
        open={drawerOpen}
        onClose={closeDrawer}
        title={
          selectedItem
            ? `Configure — ${selectedItem.display_name}`
            : 'Configure Model'
        }
      >
        {selectedItem && (
          <ConfigDrawerContent
            item={selectedItem}
            onSave={handleSave}
            onTest={handleTest}
            testing={testingFn === selectedItem.function_name}
            saving={savingFn === selectedItem.function_name}
          />
        )}
      </Drawer>
    </>
  )
}

// ─── Status summary card ──────────────────────────────────────────────────────
function StatusCard({
  label,
  count,
  color,
  dot,
}: {
  label: string
  count: number
  color: string
  dot: string
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-border bg-card p-4">
      <span className={cn('h-2.5 w-2.5 rounded-full shrink-0', dot)} />
      <div>
        <div className={cn('text-xl font-bold tabular-nums', color)}>{count}</div>
        <div className="text-xs text-muted">{label}</div>
      </div>
    </div>
  )
}
