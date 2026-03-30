import { cn } from '@/lib/utils'
import type { LLMProvider } from '@/app/settings/models/types'
import { PROVIDER_LABELS } from '@/app/settings/models/types'

interface ModelBadgeProps {
  provider: LLMProvider
  model: string
  size?: 'sm' | 'md'
}

const PROVIDER_STYLES: Record<LLMProvider, string> = {
  anthropic: 'bg-amber-500/15 text-amber-400 border border-amber-500/30',
  openai: 'bg-green/15 text-green border border-green/30',
  google: 'bg-blue/15 text-blue border border-blue/30',
  ollama: 'bg-purple-500/15 text-purple-400 border border-purple-500/30',
  azure_openai: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30',
}

const PROVIDER_DOT: Record<LLMProvider, string> = {
  anthropic: 'bg-amber-400',
  openai: 'bg-green',
  google: 'bg-blue',
  ollama: 'bg-purple-400',
  azure_openai: 'bg-cyan-400',
}

export function ModelBadge({ provider, model, size = 'md' }: ModelBadgeProps) {
  const isSm = size === 'sm'

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md font-mono font-medium',
        PROVIDER_STYLES[provider],
        isSm ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs'
      )}
    >
      <span
        className={cn(
          'rounded-full shrink-0',
          PROVIDER_DOT[provider],
          isSm ? 'h-1.5 w-1.5' : 'h-2 w-2'
        )}
      />
      <span className="text-current opacity-70">
        {PROVIDER_LABELS[provider]}
      </span>
      <span className="text-current">/</span>
      <span>{model}</span>
      {provider === 'ollama' && (
        <span
          className={cn(
            'ml-0.5 rounded bg-purple-500/20 px-1 font-sans font-medium uppercase tracking-wide',
            isSm ? 'text-[8px]' : 'text-[9px]'
          )}
        >
          local
        </span>
      )}
    </span>
  )
}
