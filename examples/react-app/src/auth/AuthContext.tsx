import {
	createContext,
	useContext,
	useEffect,
	useRef,
	useState,
	type PropsWithChildren,
} from 'react'
import {
	useSecureSession,
	createSessionStore,
	isSessionAuthError,
	readCookieValue,
} from '../lib/secure-fetch'

import type { LoginCredentials, LoginResponse } from '../types'
import { secureHttpAuthUrls, secureHttpBackendUrl } from '../lib/config'
import { client } from '../lib/secure-fetch'

const sessionStore = createSessionStore({
	storageKey: 'secure_http_react_session',
})

type AuthContextValue = {
	bootstrapError: string
	identity: string
	initializing: boolean
	isAuthenticated: boolean
	login: (credentials: LoginCredentials) => Promise<void>
	logout: () => Promise<void>
	refreshSession: () => Promise<void>
	status: string
}

const AuthContext = createContext<AuthContextValue | null>(null)

function useAuthSession() {
	return useSecureSession({
		client: client,
		loginUrl: secureHttpAuthUrls.login,
		logoutUrl: secureHttpAuthUrls.logout,
		restoreOnMount: false,
		sessionStore,
		baseURL: secureHttpBackendUrl,
		requestCredentials: 'include',
		resolveIdentity(payload: LoginResponse, credentials?: Record<string, unknown>) {
			return (
				payload.userID ??
				payload.user_id ??
				payload.username ??
				String(credentials?.username ?? '')
			)
		},
		createSession({ identity, config }) {
			return {
				identity,
				timestamp: Date.now(),
				config: {
					baseURL: config.baseURL,
					bootstrapPath: config.bootstrapPath,
					handshakePath: config.handshakePath,
					csrfCookieName: config.csrfCookieName,
					csrfHeaderName: config.csrfHeaderName,
					autoHandshake: true,
				},
			}
		},
		async parseResponse(response: Response) {
			return (await response.json()) as LoginResponse
		},
	})
}

export function AuthProvider({ children }: PropsWithChildren) {
	const auth = useAuthSession()
	const [initializing, setInitializing] = useState(true)
	const [bootstrapError, setBootstrapError] = useState('')
	const ranRef = useRef(false)

	async function refreshSession() {
		setBootstrapError('')
		setInitializing(true)
		await auth.restore()
		setInitializing(false)
	}

	async function login(credentials: LoginCredentials) {
		setBootstrapError('')
		await auth.login({ ...credentials })
	}

	async function logout() {
		setBootstrapError('')
		await auth.logout()
	}

	useEffect(() => {
		if (ranRef.current) {
			return
		}
		ranRef.current = true
		void refreshSession()
	}, [])

	useEffect(() => {
		if (auth.error && !isSessionAuthError(auth.error)) {
			setBootstrapError(auth.error.message)
		}
	}, [auth.error])

	const value: AuthContextValue = {
		bootstrapError,
		identity: auth.identity,
		initializing,
		isAuthenticated: auth.isAuthenticated,
		login,
		logout,
		refreshSession,
		status: auth.status,
	}

	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
	const context = useContext(AuthContext)
	if (!context) {
		throw new Error('useAuth must be used inside AuthProvider')
	}
	return context
}

export function readCsrfToken(cookieName = 'securehttp_csrf') {
	return readCookieValue(cookieName, document.cookie)
}
