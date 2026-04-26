function normalizeBaseUrl(value: string | undefined, fallback: string) {
  const trimmed = value?.trim()
  return (trimmed && trimmed.replace(/\/+$/, '')) || fallback
}

const browserFallback =
  typeof window !== 'undefined' && window.location?.origin
    ? window.location.origin
    : 'http://localhost:9443'

export const secureHttpBackendUrl = normalizeBaseUrl(
  import.meta.env.VITE_SECURE_HTTP_BACKEND_URL,
  browserFallback,
)

export const secureHttpAuthUrls = {
  login: `${secureHttpBackendUrl}/auth/login`,
  logout: `${secureHttpBackendUrl}/auth/logout`,
}
