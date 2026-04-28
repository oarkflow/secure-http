import type { SecureHttpClient } from './client'
import type {
	LabConfig,
	SecureFetchRuntimeScope,
	SecureSession,
	SessionStore,
} from './types'
import {
	DEFAULT_CSRF_COOKIE_NAME,
	DEFAULT_CSRF_HEADER_NAME,
	DEFAULT_SESSION_STORAGE_KEY,
	readCookieValue,
	resolveFetch,
	resolveWindowRef,
} from './utils'

type SessionResolverContext<TPayload = any> = {
	identity: string
	payload: TPayload
	config: LabConfig
}

export type SessionPayloadResult<TPayload = any> = {
	identity: string
	payload: TPayload
	config: LabConfig
	session: SecureSession
}

export interface ResolveSessionPayloadOptions<TPayload = any> {
	windowRef?: SecureFetchRuntimeScope
	cookieSource?: string
	baseURL?: string
	handshakePath?: string
	bootstrapPath?: string
	csrfCookieName?: string
	csrfHeaderName?: string
	autoHandshake?: boolean
	credentials?: Record<string, unknown>
	resolveIdentity?: (payload: TPayload, credentials?: Record<string, unknown>) => string
	createSession?: (context: SessionResolverContext<TPayload>) => SecureSession
}

export interface LoginWithCredentialsOptions<TPayload = any> extends ResolveSessionPayloadOptions<TPayload> {
	client?: SecureHttpClient
	fetchImpl?: typeof fetch
	credentials?: Record<string, unknown>
	loginUrl?: string
	requestCredentials?: RequestCredentials
	buildLoginRequest?: (credentials: Record<string, unknown>) => RequestInit
	parseResponse?: (response: Response) => Promise<TPayload>
	getErrorMessage?: (payload: TPayload, response: Response) => string
	sessionStore?: SessionStore
}

export interface RestoreSessionOptions {
	client: SecureHttpClient
	windowRef?: SecureFetchRuntimeScope
	sessionStore?: SessionStore
	cookieSource?: string
	baseURL?: string
}

export interface LogoutSessionOptions {
	client?: SecureHttpClient
	windowRef?: SecureFetchRuntimeScope
	fetchImpl?: typeof fetch
	sessionStore?: SessionStore
	cookieSource?: string
	logoutUrl?: string
	requestCredentials?: RequestCredentials
	csrfCookieName?: string
	csrfHeaderName?: string
	performLogout?: (context: {
		client?: SecureHttpClient
		cookieSource: string
		fetch: typeof fetch | null
		sessionStore?: SessionStore
		windowRef?: SecureFetchRuntimeScope
	}) => Promise<void>
}

function defaultParseResponse<TPayload>(response: Response): Promise<TPayload> {
	return response.json() as Promise<TPayload>
}

function defaultLoginRequest(credentials: Record<string, unknown>): RequestInit {
	return {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(credentials),
	}
}

function asRecord(value: any): Record<string, any> {
	if (value && typeof value === 'object') {
		return value
	}
	return {}
}

function defaultResolveIdentity(payload: any, credentials?: Record<string, unknown>): string {
	const source = asRecord(payload)
	if (source.userID) {
		return String(source.userID)
	}
	if (source.user_id) {
		return String(source.user_id)
	}
	if (source.username) {
		return String(source.username)
	}
	return String(credentials?.username || '')
}

export function createSessionStore(options: {
	storage?: Storage
	storageKey?: string
} = {}): SessionStore {
	const storageKey = options.storageKey || DEFAULT_SESSION_STORAGE_KEY
	return {
		load() {
			try {
				const storage = options.storage || globalThis.sessionStorage
				const raw = storage?.getItem?.(storageKey)
				return raw ? (JSON.parse(raw) as SecureSession) : null
			} catch {
				return null
			}
		},
		save(session) {
			try {
				const storage = options.storage || globalThis.sessionStorage
				storage?.setItem?.(storageKey, JSON.stringify(session))
				return true
			} catch {
				return false
			}
		},
		clear() {
			try {
				const storage = options.storage || globalThis.sessionStorage
				storage?.removeItem?.(storageKey)
			} catch {}
		},
		storageKey,
	}
}

export function isSessionAuthError(error: unknown): boolean {
	const message = String((error as Error | undefined)?.message || error || '').toLowerCase()
	return (
		message.includes('bootstrap failed with status 401') ||
		message.includes('bootstrap failed with status 403') ||
		message.includes('bootstrap failed with status 404') ||
		message.includes('auth claims missing') ||
		message.includes('missing authorization token') ||
		message.includes('invalid token') ||
		message.includes('request failed with status 401') ||
		message.includes('request failed with status 403')
	)
}

export function resolveSessionPayload<TPayload = any>(
	payload: TPayload,
	options: ResolveSessionPayloadOptions<TPayload> = {},
): SessionPayloadResult<TPayload> {
	const windowRef = resolveWindowRef(options.windowRef)
	const payloadRecord = asRecord(payload)
	const cookieSource =
		options.cookieSource !== undefined ? options.cookieSource : windowRef.document?.cookie || ''
	const csrfCookieName =
		options.csrfCookieName || String(payloadRecord.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME)
	const identity = options.resolveIdentity
		? options.resolveIdentity(payload, options.credentials)
		: defaultResolveIdentity(payload, options.credentials)
	const config: LabConfig = {
		baseURL: options.baseURL || String(payloadRecord.baseURL || windowRef.location?.origin || ''),
		handshakePath: String(payloadRecord.handshakePath || options.handshakePath || '/handshake'),
		bootstrapPath: String(payloadRecord.bootstrapPath || options.bootstrapPath || '/auth/bootstrap'),
		csrfCookieName,
		csrfHeaderName: String(payloadRecord.csrfHeaderName || options.csrfHeaderName || DEFAULT_CSRF_HEADER_NAME),
		csrfToken: readCookieValue(csrfCookieName, cookieSource),
		autoHandshake: options.autoHandshake !== false,
	}
	return {
		identity,
		payload,
		config,
		session: options.createSession
			? options.createSession({ identity, payload, config })
			: {
					identity,
					timestamp: Date.now(),
					config: {
						baseURL: config.baseURL,
						handshakePath: config.handshakePath,
						bootstrapPath: config.bootstrapPath,
						csrfCookieName: config.csrfCookieName,
						csrfHeaderName: config.csrfHeaderName,
						autoHandshake: config.autoHandshake,
					},
				},
	}
}

export async function loginWithCredentials<TPayload = any>(
	options: LoginWithCredentialsOptions<TPayload> = {},
): Promise<SessionPayloadResult<TPayload>> {
	const windowRef = resolveWindowRef(options.windowRef)
	const fetcher = resolveFetch(options.fetchImpl, windowRef)
	const credentials = options.credentials || {}
	const requestInit = options.buildLoginRequest
		? options.buildLoginRequest(credentials)
		: defaultLoginRequest(credentials)
	const response = await fetcher(options.loginUrl || '/auth/login', {
		credentials: options.requestCredentials || 'same-origin',
		...requestInit,
	})
	const payload = options.parseResponse
		? await options.parseResponse(response)
		: await defaultParseResponse<TPayload>(response)
	if (!response.ok) {
		const message = options.getErrorMessage
			? options.getErrorMessage(payload, response)
			: asRecord(payload).error || 'login failed'
		throw new Error(String(message))
	}
	const resolved = resolveSessionPayload(payload, {
		...options,
		credentials,
		windowRef,
	})
	if (options.client) {
		await options.client.init(resolved.config)
	}
	options.sessionStore?.save?.(resolved.session)
	return resolved
}

export async function restoreSession(
	options: RestoreSessionOptions,
): Promise<{
	identity: string
	session: SecureSession
	config: LabConfig
} | null> {
	const windowRef = resolveWindowRef(options.windowRef)
	const saved = options.sessionStore?.load?.()
	if (!saved?.config) {
		return null
	}
	const csrfCookieName = saved.config.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME
	const cookieSource =
		options.cookieSource !== undefined ? options.cookieSource : windowRef.document?.cookie || ''
	const csrfToken = readCookieValue(csrfCookieName, cookieSource)
	if (!csrfToken) {
		options.sessionStore?.clear?.()
		return null
	}

	const config: LabConfig = {
		...saved.config,
		...(options.baseURL ? { baseURL: options.baseURL } : {}),
		csrfToken,
		autoHandshake: saved.config.autoHandshake !== false,
	} as LabConfig
	await options.client.init(config)
	return {
		identity: saved.identity || '',
		session: saved,
		config,
	}
}

export async function logoutSession(options: LogoutSessionOptions = {}): Promise<void> {
	const windowRef = resolveWindowRef(options.windowRef)
	const client = options.client
	const fetcher = options.performLogout || options.logoutUrl ? resolveFetch(options.fetchImpl, windowRef) : null
	try {
		if (options.performLogout) {
			await options.performLogout({
				client,
				cookieSource:
					options.cookieSource !== undefined ? options.cookieSource : windowRef.document?.cookie || '',
				fetch: fetcher,
				sessionStore: options.sessionStore,
				windowRef,
			})
		} else if (client?.isReady && fetcher && options.logoutUrl) {
			const csrfCookieName = options.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME
			const cookieSource =
				options.cookieSource !== undefined ? options.cookieSource : windowRef.document?.cookie || ''
			await fetcher(options.logoutUrl, {
				method: 'POST',
				credentials: options.requestCredentials || 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					[options.csrfHeaderName || DEFAULT_CSRF_HEADER_NAME]: readCookieValue(csrfCookieName, cookieSource),
				},
				body: '{}',
			})
		}
	} finally {
		await client?.reset?.()
		options.sessionStore?.clear?.()
	}
}

export {
	DEFAULT_CSRF_COOKIE_NAME,
	DEFAULT_CSRF_HEADER_NAME,
	DEFAULT_SESSION_STORAGE_KEY,
	readCookieValue,
}
