'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  CheckCircle2, XCircle, Loader2, Eye, EyeOff, Save, Zap, RefreshCw,
  RotateCcw, Download, Trash2, Server, Key, Cpu, Settings2, ExternalLink,
  AlertTriangle, HardDrive, Search,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { authFetch } from '@/lib/auth'
import {
  getModelConfigs, updateModelConfig, testModelConfig, testAllModelConfigs,
  resetToDefaults, getOllamaModels, pullOllamaModel, saveApiKey, deleteApiKey,
  getApiKeyStatus, searchModels,
  type OllamaModel, type ProviderInfo, type ModelSearchResult,
} from '@/lib/api/model-config'
import type {
  FunctionModelConfig, FunctionName, LLMProvider, ModelConfig, TestResult,
} from './types'
import {
  PROVIDER_MODELS, PROVIDER_LABELS, PROVIDER_COLORS,
  FUNCTION_DESCRIPTIONS, COST_PER_MILLION,
} from './types'

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ type, message }: { type: 'success' | 'error'; message: string }) {
  return (
    <div className={cn(
      'fixed bottom-5 right-5 z-[100] flex items-center gap-2 rounded-lg border px-4 py-3 text-sm shadow-xl',
      type === 'success' ? 'border-green/40 bg-green/10 text-green' : 'border-red/40 bg-red/10 text-red'
    )}>
      {type === 'success' ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
      {message}
    </div>
  )
}

function useToast() {
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const show = (type: 'success' | 'error', message: string) => {
    setToast({ type, message })
    setTimeout(() => setToast(null), 3500)
  }
  return { toast, show }
}

// ─── Provider API Keys Tab ────────────────────────────────────────────────────

function ProvidersTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const providers: LLMProvider[] = ['anthropic', 'openai', 'google', 'ollama', 'azure_openai']

  const [keys, setKeys] = useState<Record<string, string>>({})
  const [showKey, setShowKey] = useState<Record<string, boolean>>({})
  const [status, setStatus] = useState<Record<string, { configured: boolean; source: string }>>({})
  const [saving, setSaving] = useState<string | null>(null)
  const [testing, setTesting] = useState<string | null>(null)

  useEffect(() => {
    getApiKeyStatus().then(setStatus).catch(() => {})
  }, [])

  async function handleSaveKey(provider: string) {
    const key = keys[provider]
    if (!key || key.length < 5) {
      showToast('error', 'API key is too short')
      return
    }
    setSaving(provider)
    try {
      await saveApiKey(provider, key)
      setStatus(s => ({ ...s, [provider]: { configured: true, source: 'database' } }))
      setKeys(k => ({ ...k, [provider]: '' }))
      showToast('success', `${PROVIDER_LABELS[provider as LLMProvider]} API key saved`)
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to save key')
    } finally {
      setSaving(null)
    }
  }

  async function handleDeleteKey(provider: string) {
    setSaving(provider)
    try {
      await deleteApiKey(provider)
      setStatus(s => ({ ...s, [provider]: { configured: false, source: '' } }))
      showToast('success', `${PROVIDER_LABELS[provider as LLMProvider]} API key removed`)
    } catch {
      showToast('error', 'Failed to remove key')
    } finally {
      setSaving(null)
    }
  }

  async function handleTestProvider(provider: string) {
    setTesting(provider)
    try {
      const res = await testAllModelConfigs()
      const anyOk = Object.values(res).some(r => r.ok)
      showToast(anyOk ? 'success' : 'error', anyOk ? `${PROVIDER_LABELS[provider as LLMProvider]} connection OK` : 'Connection test failed')
    } catch {
      showToast('error', 'Connection test failed')
    } finally {
      setTesting(null)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Configure API keys for cloud LLM providers. Keys are stored encrypted in the database.
        You can also set them via environment variables.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {providers.map(provider => {
          const colors = PROVIDER_COLORS[provider]
          const s = status[provider]
          const isOllama = provider === 'ollama'
          const configured = s?.configured ?? false

          return (
            <Card key={provider} className={cn(
              'transition-all',
              configured && 'border-green/20'
            )}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className={cn('h-3 w-3 rounded-full', colors.dot)} />
                    <CardTitle className="text-sm">{PROVIDER_LABELS[provider]}</CardTitle>
                  </div>
                  <span className={cn(
                    'text-[10px] font-medium rounded-full px-2 py-0.5 border',
                    configured
                      ? 'border-green/30 bg-green/10 text-green'
                      : 'border-border bg-bg text-muted'
                  )}>
                    {configured ? (s?.source === 'env' ? 'env var' : s?.source === 'database' ? 'saved' : 'ready') : 'not configured'}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {isOllama ? (
                  <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3">
                    <div className="flex items-center gap-2 text-purple-400 text-xs font-medium mb-1">
                      <Server className="h-3.5 w-3.5" />
                      Local Inference
                    </div>
                    <p className="text-[11px] text-muted">
                      No API key needed. Configure Ollama models in the Local Models tab.
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="space-y-1.5">
                      <label className="text-[10px] text-muted uppercase tracking-wider">
                        API Key {s?.source === 'env' && <span className="text-green">(set via env)</span>}
                      </label>
                      <div className="relative">
                        <Input
                          type={showKey[provider] ? 'text' : 'password'}
                          value={keys[provider] ?? ''}
                          onChange={e => setKeys(k => ({ ...k, [provider]: e.target.value }))}
                          placeholder={configured ? '••••••••••••••••' : 'Enter API key...'}
                          className="pr-8 text-xs h-8"
                        />
                        <button
                          onClick={() => setShowKey(s => ({ ...s, [provider]: !s[provider] }))}
                          className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-text"
                        >
                          {showKey[provider] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        size="sm" className="h-7 text-xs flex-1"
                        onClick={() => handleSaveKey(provider)}
                        disabled={saving === provider || !keys[provider]}
                      >
                        {saving === provider ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
                        Save Key
                      </Button>
                      <Button
                        size="sm" variant="ghost" className="h-7 text-xs"
                        onClick={() => handleTestProvider(provider)}
                        disabled={testing === provider || !configured}
                      >
                        {testing === provider ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
                        Test
                      </Button>
                      {configured && s?.source === 'database' && (
                        <Button
                          size="sm" variant="ghost" className="h-7 text-xs text-red hover:text-red"
                          onClick={() => handleDeleteKey(provider)}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}

// ─── Function Routing Tab ─────────────────────────────────────────────────────

interface DraftRow {
  provider: LLMProvider
  model_id: string
  temperature: number
  max_tokens: number
  is_active: boolean
  dirty: boolean
}

function FunctionRoutingTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [configs, setConfigs] = useState<FunctionModelConfig[]>([])
  const [loading, setLoading] = useState(true)
  const [drafts, setDrafts] = useState<Record<string, DraftRow>>({})
  const [testingFn, setTestingFn] = useState<string | null>(null)
  const [savingFn, setSavingFn] = useState<string | null>(null)
  const [testingAll, setTestingAll] = useState(false)
  const [ollamaModels, setOllamaModels] = useState<string[]>([])

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

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getModelConfigs()
      const normalized = Array.isArray(data) ? data : (data as { configs?: FunctionModelConfig[] }).configs ?? []
      setConfigs(normalized)
      seedDrafts(normalized)
    } catch {
      setConfigs([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  // Load Ollama models for the dropdown
  useEffect(() => {
    getOllamaModels().then(res => {
      if (res.available) {
        setOllamaModels(res.models.map(m => m.model_id))
      }
    }).catch(() => {})
  }, [])

  function getModelsForProvider(provider: LLMProvider): string[] {
    if (provider === 'ollama' && ollamaModels.length > 0) return ollamaModels
    return PROVIDER_MODELS[provider] ?? []
  }

  function patchDraft(fn: string, patch: Partial<DraftRow>) {
    setDrafts(d => ({ ...d, [fn]: { ...d[fn], ...patch } }))
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
      await updateModelConfig(fn, config)
      patchDraft(fn, { dirty: false })
      showToast('success', `${fn} configuration saved`)
    } catch {
      showToast('error', `Failed to save ${fn}`)
    } finally {
      setSavingFn(null)
    }
  }

  async function handleTest(fn: FunctionName) {
    setTestingFn(fn)
    try {
      const result: TestResult = await testModelConfig(fn)
      setConfigs(prev => prev.map(c =>
        c.function_name === fn
          ? { ...c, config: { ...c.config, status: result.ok ? 'ok' : 'error', error_message: result.error } }
          : c
      ))
      showToast(result.ok ? 'success' : 'error',
        result.ok ? `${fn}: OK (${result.latency_ms}ms)` : `${fn}: ${result.error ?? 'failed'}`)
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Test failed')
    } finally {
      setTestingFn(null)
    }
  }

  async function handleTestAll() {
    setTestingAll(true)
    try {
      const results = await testAllModelConfigs()
      setConfigs(prev => prev.map(c => {
        const r = results[c.function_name]
        if (!r) return c
        return { ...c, config: { ...c.config, status: r.ok ? 'ok' : 'error' } }
      }))
      const passed = Object.values(results).filter(r => r.ok).length
      showToast('success', `Test All: ${passed}/${Object.keys(results).length} passed`)
    } catch {
      showToast('error', 'Test All failed')
    } finally {
      setTestingAll(false)
    }
  }

  const dirtyCount = Object.values(drafts).filter(d => d.dirty).length

  if (loading) {
    return <div className="space-y-3">{[...Array(5)].map((_, i) => (
      <div key={i} className="animate-pulse rounded-xl bg-border/40 h-24" />
    ))}</div>
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted">
          Assign a provider and model to each platform capability. Changes take effect immediately.
        </p>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={handleTestAll} disabled={testingAll}>
            {testingAll ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            Test All
          </Button>
          {dirtyCount > 0 && (
            <Button size="sm" onClick={async () => {
              for (const [fn, d] of Object.entries(drafts)) {
                if (d.dirty) await handleSave(fn as FunctionName)
              }
            }}>
              <Save className="h-3.5 w-3.5" /> Save All ({dirtyCount})
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Compact table layout */}
      <div className="rounded-xl border border-border overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-card/50">
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-4 py-2.5 w-[180px]">Function</th>
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[140px]">Provider</th>
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[180px]">Model</th>
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[80px]">Temp</th>
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[90px]">Max Tokens</th>
              <th className="text-left text-[10px] text-muted uppercase tracking-wider px-3 py-2.5 w-[60px]">Status</th>
              <th className="text-right text-[10px] text-muted uppercase tracking-wider px-4 py-2.5 w-[120px]">Actions</th>
            </tr>
          </thead>
          <tbody>
            {configs.map(item => {
              const draft = drafts[item.function_name]
              if (!draft) return null
              const colors = PROVIDER_COLORS[draft.provider] ?? PROVIDER_COLORS.anthropic

              return (
                <tr key={item.function_name} className={cn(
                  'border-b border-border last:border-0 transition-colors',
                  draft.dirty && 'bg-primary/5'
                )}>
                  <td className="px-4 py-3">
                    <div className="text-xs font-medium text-text">{item.display_name}</div>
                    <div className="text-[10px] text-muted mt-0.5 line-clamp-1">{item.description}</div>
                  </td>
                  <td className="px-3 py-3">
                    <select
                      value={draft.provider}
                      onChange={e => {
                        const p = e.target.value as LLMProvider
                        const models = getModelsForProvider(p)
                        patchDraft(item.function_name, { provider: p, model_id: models[0] ?? '', dirty: true })
                      }}
                      className="h-7 w-full rounded-md border border-border bg-bg px-2 text-xs text-text focus:ring-1 focus:ring-primary"
                    >
                      {(Object.keys(PROVIDER_LABELS) as LLMProvider[]).map(p => (
                        <option key={p} value={p}>{PROVIDER_LABELS[p]}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-3 py-3">
                    <select
                      value={draft.model_id}
                      onChange={e => patchDraft(item.function_name, { model_id: e.target.value, dirty: true })}
                      className="h-7 w-full rounded-md border border-border bg-bg px-2 text-xs text-text focus:ring-1 focus:ring-primary"
                    >
                      {getModelsForProvider(draft.provider).map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-3 py-3">
                    <Input
                      type="number" min={0} max={2} step={0.1}
                      value={draft.temperature}
                      onChange={e => patchDraft(item.function_name, { temperature: parseFloat(e.target.value) || 0, dirty: true })}
                      className="h-7 text-xs w-16"
                    />
                  </td>
                  <td className="px-3 py-3">
                    <Input
                      type="number" min={128} max={200000}
                      value={draft.max_tokens}
                      onChange={e => patchDraft(item.function_name, { max_tokens: parseInt(e.target.value, 10) || 4096, dirty: true })}
                      className="h-7 text-xs w-20"
                    />
                  </td>
                  <td className="px-3 py-3">
                    {testingFn === item.function_name
                      ? <Loader2 className="h-4 w-4 animate-spin text-primary" />
                      : item.config.status === 'ok'
                        ? <CheckCircle2 className="h-4 w-4 text-green" />
                        : item.config.status === 'error'
                          ? <XCircle className="h-4 w-4 text-red" />
                          : <span className="h-2 w-2 rounded-full bg-muted inline-block" />
                    }
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0"
                        onClick={() => handleTest(item.function_name as FunctionName)}
                        disabled={testingFn === item.function_name}
                        title="Test"
                      >
                        <Zap className="h-3 w-3" />
                      </Button>
                      {draft.dirty && (
                        <Button size="sm" className="h-6 px-2 text-[10px]"
                          onClick={() => handleSave(item.function_name as FunctionName)}
                          disabled={savingFn === item.function_name}
                        >
                          {savingFn === item.function_name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
                          Save
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Model Search Component ───────────────────────────────────────────────────

function ModelSearch({ onPull, pulling }: { onPull: (model: string) => void; pulling: string | null }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<ModelSearchResult[]>([])
  const [searching, setSearching] = useState(false)
  const [searched, setSearched] = useState(false)

  async function handleSearch() {
    if (query.length < 2) return
    setSearching(true)
    setSearched(true)
    try {
      const data = await searchModels(query)
      setResults(data.results)
    } catch {
      setResults([])
    }
    setSearching(false)
  }

  const sourceColors: Record<string, { border: string; bg: string; text: string; label: string }> = {
    recommended: { border: 'border-green/30', bg: 'bg-green/10', text: 'text-green', label: 'Recommended' },
    security_specialized: { border: 'border-purple-500/30', bg: 'bg-purple-500/10', text: 'text-purple-400', label: 'Security' },
    ollama_library: { border: 'border-blue/30', bg: 'bg-blue/10', text: 'text-blue', label: 'Ollama Library' },
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Search className="h-4 w-4 text-muted" />
          Search Models
        </CardTitle>
        <p className="text-[11px] text-muted">
          Search by keyword — find models for security, malware, phishing, log analysis, embeddings, and more.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2">
          <Input value={query} onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Search by keyword (e.g. malware, phishing, log, embedding, sigma...)"
            className="h-8 text-xs flex-1" />
          <Button size="sm" className="h-8 text-xs" onClick={handleSearch} disabled={searching || query.length < 2}>
            {searching ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
            Search
          </Button>
        </div>

        {/* Quick search tags */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {['security', 'malware', 'phishing', 'log analysis', 'embedding', 'code', 'reasoning', 'sigma', 'NER', 'vulnerability'].map(tag => (
            <button key={tag} onClick={() => { setQuery(tag); setTimeout(handleSearch, 0) }}
              className="text-[9px] rounded-full px-2 py-0.5 border border-border text-muted hover:text-text hover:border-primary/40 transition-colors cursor-pointer">
              {tag}
            </button>
          ))}
        </div>

        {/* Results */}
        {searched && (
          results.length === 0 ? (
            <p className="text-xs text-muted text-center py-4">No models found for &ldquo;{query}&rdquo;</p>
          ) : (
            <div className="space-y-1.5 max-h-[400px] overflow-y-auto">
              {results.map((r, i) => {
                const sc = sourceColors[r.source] ?? sourceColors.ollama_library
                return (
                  <div key={`${r.model}-${i}`} className="flex items-start justify-between rounded-lg border border-border px-3 py-2.5 hover:bg-card/50">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-xs font-medium text-text">{r.name || r.model}</span>
                        {r.size && <span className="text-[9px] text-muted">{r.size}</span>}
                        <span className={cn('text-[9px] rounded-full px-1.5 py-0.5 border', sc.border, sc.bg, sc.text)}>
                          {sc.label}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted line-clamp-2">{r.description || r.use_case || ''}</p>
                      {r.use_cases && (
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {r.use_cases.slice(0, 4).map(uc => (
                            <span key={uc} className="text-[8px] rounded-full px-1.5 py-0.5 bg-border text-muted">{uc}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    {(r.type === 'ollama' || r.source === 'recommended' || r.source === 'ollama_library') && (
                      <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] shrink-0 ml-2"
                        onClick={() => onPull(r.model)} disabled={pulling !== null}>
                        {pulling === r.model ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                        Pull
                      </Button>
                    )}
                  </div>
                )
              })}
            </div>
          )
        )}
      </CardContent>
    </Card>
  )
}

// ─── Local Models Tab ─────────────────────────────────────────────────────────

function LocalModelsTab({ showToast }: { showToast: (t: 'success' | 'error', m: string) => void }) {
  const [ollamaStatus, setOllamaStatus] = useState<{ available: boolean; base_url: string; models: OllamaModel[]; error?: string } | null>(null)
  const [loading, setLoading] = useState(true)
  const [pulling, setPulling] = useState<string | null>(null)
  const [pullInput, setPullInput] = useState('')
  const [recommended, setRecommended] = useState<any>(null)

  const loadModels = useCallback(async () => {
    setLoading(true)
    try {
      const data = await getOllamaModels()
      setOllamaStatus(data)
    } catch {
      setOllamaStatus({ available: false, base_url: '', models: [], error: 'Failed to connect' })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void loadModels() }, [loadModels])

  useEffect(() => {
    authFetch('/api/v2/model-config/ollama/recommended')
      .then(r => r.json())
      .then(setRecommended)
      .catch(() => {})
  }, [])

  async function handlePull(model: string) {
    setPulling(model)
    showToast('success', `Pulling ${model}... this may take a few minutes`)
    try {
      const res = await pullOllamaModel(model)
      if (res.ok) {
        showToast('success', res.message)
        await loadModels()
      } else {
        showToast('error', res.message)
      }
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Pull failed')
    } finally {
      setPulling(null)
    }
  }

  return (
    <div className="space-y-6">
      {/* Ollama Status */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Server className="h-4 w-4 text-purple-400" />
              <CardTitle className="text-sm">Ollama</CardTitle>
              {ollamaStatus && (
                <span className={cn(
                  'text-[10px] font-medium rounded-full px-2 py-0.5 border',
                  ollamaStatus.available
                    ? 'border-green/30 bg-green/10 text-green'
                    : 'border-red/30 bg-red/10 text-red'
                )}>
                  {ollamaStatus.available ? 'running' : 'offline'}
                </span>
              )}
            </div>
            <Button size="sm" variant="ghost" onClick={loadModels} disabled={loading}>
              <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
            </Button>
          </div>
          {ollamaStatus?.base_url && (
            <p className="text-[11px] text-muted font-mono">{ollamaStatus.base_url}</p>
          )}
        </CardHeader>
        <CardContent>
          {!ollamaStatus?.available ? (
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
              <div className="flex items-center gap-2 text-amber-400 text-xs font-medium mb-2">
                <AlertTriangle className="h-3.5 w-3.5" />
                Ollama not detected
              </div>
              <p className="text-[11px] text-muted">
                Install Ollama from <span className="text-text">ollama.ai</span> and run <code className="text-xs bg-border/50 px-1 rounded">ollama serve</code>.
                {ollamaStatus?.error && <span className="block mt-1 text-red">{ollamaStatus.error}</span>}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {/* Installed models */}
              <div className="text-xs font-medium text-text mb-2">
                Installed Models ({ollamaStatus.models.length})
              </div>
              {ollamaStatus.models.length === 0 ? (
                <p className="text-xs text-muted">No models installed. Pull one from the recommended list below.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                  {ollamaStatus.models.map(m => (
                    <div key={m.model_id} className="flex items-center justify-between rounded-lg border border-border bg-card/50 px-3 py-2.5">
                      <div className="min-w-0">
                        <div className="text-xs font-medium text-text truncate">{m.model_id}</div>
                        <div className="text-[10px] text-muted">
                          {m.size_gb > 0 ? `${m.size_gb} GB` : 'unknown size'}
                          {m.parameter_size && ` · ${m.parameter_size}`}
                          {m.quantization && ` · ${m.quantization}`}
                        </div>
                      </div>
                      <HardDrive className="h-3.5 w-3.5 text-green shrink-0" />
                    </div>
                  ))}
                </div>
              )}

              {/* Pull custom model */}
              <div className="flex items-center gap-2 pt-2">
                <Input
                  value={pullInput}
                  onChange={e => setPullInput(e.target.value)}
                  placeholder="Pull a model (e.g. llama3, mistral, phi4)..."
                  className="h-8 text-xs flex-1"
                />
                <Button size="sm" className="h-8 text-xs"
                  onClick={() => { if (pullInput.trim()) handlePull(pullInput.trim()) }}
                  disabled={!pullInput.trim() || pulling !== null}
                >
                  {pulling ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                  Pull
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recommended Models */}
      {recommended && (
        <>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Cpu className="h-4 w-4 text-muted" />
                Recommended Ollama Models
              </CardTitle>
              <p className="text-[11px] text-muted">One-click install for security-optimized local models.</p>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
                {(recommended.recommended ?? []).map((m: any) => {
                  const installed = ollamaStatus?.models.some(om => om.model_id.startsWith(m.model))
                  return (
                    <div key={m.model} className={cn(
                      'rounded-lg border px-3 py-2.5 transition-colors',
                      installed ? 'border-green/20 bg-green/5' : 'border-border'
                    )}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-medium text-text">{m.model}</span>
                        <span className="text-[10px] text-muted">{m.size}</span>
                      </div>
                      <p className="text-[10px] text-muted mb-2">{m.use_case}</p>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-muted">{m.vram_gb} GB VRAM</span>
                        {installed ? (
                          <span className="text-[10px] text-green flex items-center gap-1">
                            <CheckCircle2 className="h-3 w-3" /> Installed
                          </span>
                        ) : (
                          <Button size="sm" variant="ghost" className="h-5 px-2 text-[10px]"
                            onClick={() => handlePull(m.model)}
                            disabled={pulling !== null}
                          >
                            {pulling === m.model ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                            Pull
                          </Button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>

          {/* Security-Specialized Models */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Settings2 className="h-4 w-4 text-muted" />
                Security-Specialized Models
              </CardTitle>
              <p className="text-[11px] text-muted">
                Domain-specific models for cybersecurity NLP tasks. Available via HuggingFace and Ollama.
              </p>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {(recommended.security_specialized ?? []).map((m: any) => (
                  <div key={m.model} className="rounded-lg border border-border px-4 py-3">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-text">{m.name}</span>
                        {m.size && <span className="text-[9px] text-muted">{m.size}</span>}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {m.domain && (
                          <span className="text-[9px] rounded-full px-2 py-0.5 border border-purple-500/30 bg-purple-500/10 text-purple-400">
                            {m.domain}
                          </span>
                        )}
                        <span className={cn('text-[10px] rounded-full px-2 py-0.5 border',
                          m.type === 'ollama' ? 'border-green/30 bg-green/10 text-green' : 'border-blue/30 bg-blue/10 text-blue'
                        )}>
                          {m.type === 'ollama' ? 'Ollama' : 'HuggingFace'}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-muted mb-2">{m.description}</p>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {(m.use_cases ?? []).map((uc: string) => (
                          <span key={uc} className="text-[9px] rounded-full px-2 py-0.5 bg-border text-muted">{uc}</span>
                        ))}
                      </div>
                      {m.type === 'ollama' && (
                        <Button size="sm" variant="ghost" className="h-5 px-2 text-[10px]"
                          onClick={() => handlePull(m.model)} disabled={pulling !== null}>
                          {pulling === m.model ? <Loader2 className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
                          Pull
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Model Search */}
          <ModelSearch onPull={handlePull} pulling={pulling} />
        </>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ModelConfigPage() {
  const { toast, show: showToast } = useToast()

  return (
    <>
      {toast && <Toast {...toast} />}
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-text">AI Models</h1>
          <p className="text-sm text-muted mt-1">
            Manage providers, API keys, model assignments, and local models.
          </p>
        </div>

        <Tabs defaultValue="providers">
          <TabsList>
            <TabsTrigger value="providers">
              <Key className="h-3.5 w-3.5 mr-1.5" />
              Providers
            </TabsTrigger>
            <TabsTrigger value="routing">
              <Settings2 className="h-3.5 w-3.5 mr-1.5" />
              Function Routing
            </TabsTrigger>
            <TabsTrigger value="local">
              <Server className="h-3.5 w-3.5 mr-1.5" />
              Local Models
            </TabsTrigger>
          </TabsList>

          <TabsContent value="providers" className="mt-4">
            <ProvidersTab showToast={showToast} />
          </TabsContent>

          <TabsContent value="routing" className="mt-4">
            <FunctionRoutingTab showToast={showToast} />
          </TabsContent>

          <TabsContent value="local" className="mt-4">
            <LocalModelsTab showToast={showToast} />
          </TabsContent>
        </Tabs>
      </div>
    </>
  )
}
