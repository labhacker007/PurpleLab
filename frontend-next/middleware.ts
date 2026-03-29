import { NextRequest, NextResponse } from 'next/server'

const AUTH_PAGES = ['/login', '/register']
const PUBLIC_PREFIXES = ['/api/', '/_next/', '/favicon']

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow Next.js internals and API routes through
  if (PUBLIC_PREFIXES.some((p) => pathname.startsWith(p))) {
    return NextResponse.next()
  }

  const token = request.cookies.get('pl_access')?.value
  const isAuthPage = AUTH_PAGES.some((p) => pathname === p || pathname.startsWith(p + '/'))

  // Auth pages: if already logged in, redirect to dashboard
  if (isAuthPage) {
    if (token) {
      return NextResponse.redirect(new URL('/dashboard', request.url))
    }
    return NextResponse.next()
  }

  // Protected routes: redirect to login if no token
  if (!token) {
    const loginUrl = new URL('/login', request.url)
    loginUrl.searchParams.set('from', pathname)
    return NextResponse.redirect(loginUrl)
  }

  return NextResponse.next()
}

export const config = {
  matcher: [
    /*
     * Match all request paths except static files
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
