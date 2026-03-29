import type { ReactNode } from 'react'

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-bg text-text antialiased">
        <div className="min-h-screen flex items-center justify-center p-4">
          <div className="w-full max-w-md">
            {/* Brand mark */}
            <div className="flex flex-col items-center mb-8">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-white font-bold text-xl mb-3">
                PL
              </div>
              <span className="text-lg font-bold text-text">PurpleLab</span>
              <span className="text-xs text-muted">Security Simulation Platform</span>
            </div>
            {children}
          </div>
        </div>
      </body>
    </html>
  )
}
