'use client'

/**
 * AskAboutThis — a small button that deep-links to the AI chat with pre-filled
 * context (environment, session, score page, use-case, etc.) and an optional
 * bootstrap message.
 *
 * Usage:
 *   <AskAboutThis
 *     goal="coverage"
 *     envId={env.id}
 *     envName={env.name}
 *     message="Analyse my coverage gaps and suggest which rules to build next"
 *   />
 */

import { useRouter } from 'next/navigation'
import { MessageSquare } from 'lucide-react'

interface AskAboutThisProps {
  /** Goal preset for the chat: red_team | detection_validation | tabletop | coverage | free */
  goal?: string
  /** Environment UUID to pass as context */
  envId?: string
  /** Environment display name */
  envName?: string
  /** Simulation session UUID */
  sessionId?: string
  /** The bootstrap message sent automatically on arrival */
  message?: string
  /** Button label (defaults to "Ask AI") */
  label?: string
  /** Extra className for the button */
  className?: string
  /** Button size: sm | md */
  size?: 'sm' | 'md'
}

export function AskAboutThis({
  goal,
  envId,
  envName,
  sessionId,
  message,
  label = 'Ask AI',
  className = '',
  size = 'sm',
}: AskAboutThisProps) {
  const router = useRouter()

  function handleClick() {
    const params = new URLSearchParams()
    if (goal) params.set('goal', goal)
    if (envId) params.set('env_id', envId)
    if (envName) params.set('env_name', envName)
    if (sessionId) params.set('session_id', sessionId)
    if (message) params.set('message', message)
    router.push(`/chat?${params.toString()}`)
  }

  const baseStyles =
    size === 'sm'
      ? 'flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-medium text-cyan-400 hover:bg-cyan-500/20 hover:border-cyan-500/70 transition-colors cursor-pointer'
      : 'flex items-center gap-2 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3.5 py-1.5 text-xs font-medium text-cyan-400 hover:bg-cyan-500/20 hover:border-cyan-500/70 transition-colors cursor-pointer'

  return (
    <button onClick={handleClick} className={`${baseStyles} ${className}`} type="button">
      <MessageSquare className={size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5'} />
      {label}
    </button>
  )
}
