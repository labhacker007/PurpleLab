import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  // Required for Docker multi-stage build (copies only the minimal standalone output)
  output: 'standalone',

  // Proxy /api/* to the FastAPI backend. Uses INTERNAL_API_URL (runtime env,
  // never baked into the client bundle) so Docker rewrites always resolve the
  // internal service name "backend:8000" regardless of how the image was built.
  async rewrites() {
    // INTERNAL_API_URL is evaluated at build time in standalone mode.
    // Use container name (purplelab-backend) not service name (backend) to avoid
    // Docker DNS round-robining to the Joti backend (also named 'backend' on shared network).
    const apiBase = process.env.INTERNAL_API_URL ?? 'http://purplelab-backend:8000'
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
    ]
  },
}

export default nextConfig
