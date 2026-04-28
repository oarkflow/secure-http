import type { SecureFetchRuntimeScope } from './types'

export const DEFAULT_READY_TIMEOUT_MS = 4000
export const DEFAULT_SESSION_STORAGE_KEY = 'secure_http_session'
export const DEFAULT_CSRF_COOKIE_NAME = 'securehttp_csrf'
export const DEFAULT_CSRF_HEADER_NAME = 'X-CSRF-Token'

const TRUSTED_LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])

export function resolveWindowRef(windowRef?: SecureFetchRuntimeScope): SecureFetchRuntimeScope {
	return (windowRef || globalThis) as SecureFetchRuntimeScope
}

export function resolveFetch(
	fetchImpl: typeof fetch | undefined,
	windowRef: SecureFetchRuntimeScope,
): typeof fetch {
	if (typeof fetchImpl === 'function') {
		return fetchImpl
	}
	if (typeof windowRef.fetch === 'function') {
		return windowRef.fetch.bind(windowRef)
	}
	if (typeof globalThis.fetch === 'function') {
		return globalThis.fetch.bind(globalThis)
	}
	throw new Error('Fetch API not available.')
}

export function readCookieValue(name: string, source?: string): string {
	const cookieSource = typeof source === 'string' ? source : ''
	const prefix = `${name}=`
	const entries = cookieSource ? cookieSource.split('; ') : []
	for (const entry of entries) {
		if (entry.startsWith(prefix)) {
			return decodeURIComponent(entry.slice(prefix.length))
		}
	}
	return ''
}

export function isPotentiallyTrustedOrigin(rawUrl: string): boolean {
	try {
		const fallbackBase = globalThis.location?.href || 'http://localhost'
		const url = new URL(rawUrl, fallbackBase)
		if (url.protocol === 'https:') {
			return true
		}
		return url.protocol === 'http:' && TRUSTED_LOCAL_HOSTS.has(url.hostname)
	} catch {
		return false
	}
}
