'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function ITDRRedirect() {
  const router = useRouter()
  useEffect(() => {
    router.replace('/use-cases?identity=1')
  }, [router])
  return null
}
