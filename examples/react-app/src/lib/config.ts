function normalizeBaseUrl(value: string | undefined, fallback: string) {
  const trimmed = value?.trim()
  return (trimmed && trimmed.replace(/\/+$/, '')) || fallback
}

export const secureHttpBackendUrl = normalizeBaseUrl(
  import.meta.env.VITE_SECURE_HTTP_BACKEND_URL,
  'http://localhost:9443',
)

export const secureHttpAuthUrls = {
  login: `${secureHttpBackendUrl}/auth/login`,
  logout: `${secureHttpBackendUrl}/auth/logout`,
}
