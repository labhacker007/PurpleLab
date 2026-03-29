import type { ReactNode } from 'react'

// The visual auth layout (centered card + brand) is handled by ConditionalLayout
// in the root layout based on the pathname. This layout is just a passthrough.
export default function AuthGroupLayout({ children }: { children: ReactNode }) {
  return <>{children}</>
}
