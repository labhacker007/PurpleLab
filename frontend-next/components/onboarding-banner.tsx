'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { X, ArrowRight, Sparkles } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const STORAGE_KEY = 'pl_onboarding'
const DISMISS_KEY = 'pl_onboarding_banner_dismissed'

interface OnboardingState {
  completed: boolean
  step: number
}

export function OnboardingBanner() {
  const router = useRouter()
  const [visible, setVisible] = useState(false)
  const [currentStep, setCurrentStep] = useState(1)

  useEffect(() => {
    try {
      const dismissed = localStorage.getItem(DISMISS_KEY)
      if (dismissed) return

      const raw = localStorage.getItem(STORAGE_KEY)
      if (!raw) {
        // Brand-new user — show banner
        setVisible(true)
        return
      }

      const state = JSON.parse(raw) as OnboardingState
      if (!state.completed) {
        setCurrentStep(state.step ?? 1)
        setVisible(true)
      }
    } catch {
      // ignore
    }
  }, [])

  function dismiss() {
    localStorage.setItem(DISMISS_KEY, '1')
    setVisible(false)
  }

  function continueSetup() {
    router.push('/onboarding')
  }

  if (!visible) return null

  const stepLabel =
    currentStep > 1 ? `Continue from step ${currentStep}` : 'Complete your platform setup'

  return (
    <div
      className={cn(
        'flex items-center gap-3 rounded-xl border border-violet-500/40 bg-violet-500/10 px-4 py-3',
        'animate-in slide-in-from-top-2 duration-300'
      )}
    >
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-500/20">
        <Sparkles className="h-4 w-4 text-violet-400" />
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white">{stepLabel} — takes 5 minutes</p>
        <p className="text-xs text-slate-400 truncate">
          Connect your SIEM, import rules, and run your first detection validation.
        </p>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <Button
          size="sm"
          className="bg-violet-600 hover:bg-violet-500 text-white"
          onClick={continueSetup}
        >
          {currentStep > 1 ? 'Continue Setup' : 'Get Started'}
          <ArrowRight className="h-3.5 w-3.5" />
        </Button>
        <button
          onClick={dismiss}
          className="flex h-7 w-7 items-center justify-center rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
          aria-label="Dismiss"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  )
}
