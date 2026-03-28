import type { Metadata } from "next"
import "./globals.css"
import { Sidebar } from "@/components/sidebar"

export const metadata: Metadata = {
  title: "PurpleLab",
  description: "Universal Security Product Simulator",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-bg text-text antialiased">
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 flex flex-col overflow-hidden">
            <Header />
            <div className="flex-1 overflow-auto p-6">{children}</div>
          </main>
        </div>
      </body>
    </html>
  )
}

function Header() {
  return (
    <header className="h-14 shrink-0 border-b border-border bg-card flex items-center px-6">
      <h1 className="text-sm font-semibold text-text">PurpleLab</h1>
      <span className="ml-2 text-xs text-muted">v2.0</span>
      <div className="flex-1" />
      <div className="flex items-center gap-3">
        <span className="text-xs text-muted">Security Product Simulator</span>
      </div>
    </header>
  )
}
