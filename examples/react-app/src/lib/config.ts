function normalizeBaseUrl(value: string | undefined, fallback: string) {
	const trimmed = value?.trim()
	return (trimmed && trimmed.replace(/\/+$/, '')) || fallback
}

function resolveBrowserFallback() {
	if (typeof window === 'undefined' || !window.location) {
		return 'http://localhost:8443'
	}

	const { hostname, origin, port, protocol } = window.location

	// Vite dev/preview serve the frontend on their own port, while the demo
	// backend still listens on 8443 unless explicitly overridden.
	if (port === '5173' || port === '4173') {
		return `${protocol}//${hostname}:8443`
	}

	return origin
}

export const secureHttpBackendUrl = normalizeBaseUrl(
	import.meta.env.VITE_SECURE_HTTP_BACKEND_URL,
	resolveBrowserFallback(),
)

export const secureHttpAuthUrls = {
	login: `${secureHttpBackendUrl}/auth/login`,
	logout: `${secureHttpBackendUrl}/auth/logout`,
}
