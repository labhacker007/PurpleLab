import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // Required for Docker multi-stage build (copies only the minimal standalone output)
  output: 'standalone',

  // Proxy API calls to FastAPI backend.
  // In Docker Compose the NEXT_PUBLIC_API_URL build arg is set to http://backend:8000,
  // but rewrites run server-side so they can resolve the internal service name.
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
    ]
  },
}

export default nextConfig
