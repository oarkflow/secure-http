import './wasm_exec'

import type {
	FetchRequest,
	GateSecret,
	LabConfig,
	ResponseType,
	SecureClientConfig,
	SecureFetchPayload,
	SecureHttpClientShape,
	SecureFetchRuntimeScope,
} from './types'
import {
	DEFAULT_CSRF_COOKIE_NAME,
	DEFAULT_READY_TIMEOUT_MS,
	isPotentiallyTrustedOrigin,
	readCookieValue,
} from './utils'

function isBrowserLikeObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object'
}

function normalizeResponseType(responseType?: ResponseType): ResponseType {
	return responseType || 'json'
}

function normalizeMethod(method?: string, fallback = 'POST'): string {
	return String(method || fallback).toUpperCase()
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms))
}

function normalizeGateSecrets(gateSecrets?: GateSecret[]): GateSecret[] {
	if (!Array.isArray(gateSecrets)) {
		return []
	}
	const now = Date.now()
	return gateSecrets
		.filter((entry) => isBrowserLikeObject(entry) && entry.id && entry.secret)
		.map((entry) => {
			const notBefore = entry.notBefore || entry.not_before || ''
			const expiresAt = entry.expiresAt || entry.expires_at || ''
			return {
				...entry,
				id: String(entry.id).trim(),
				notBefore,
				expiresAt,
				_notBeforeMs: notBefore ? Date.parse(notBefore) : Number.NEGATIVE_INFINITY,
				_expiresAtMs: expiresAt ? Date.parse(expiresAt) : Number.POSITIVE_INFINITY,
			}
		})
		.filter((entry) => entry.id && !Number.isNaN(entry._notBeforeMs) && !Number.isNaN(entry._expiresAtMs))
		.filter((entry) => entry._notBeforeMs <= now && now <= entry._expiresAtMs)
		.sort((a, b) => b._notBeforeMs - a._notBeforeMs)
		.map(({ _notBeforeMs, _expiresAtMs, ...entry }) => entry)
}

function normalizeLabConfig(labConfig?: LabConfig | null): LabConfig | null {
	if (!labConfig) {
		return null
	}
	const normalized: LabConfig = {
		...labConfig,
		baseURL: String(labConfig.baseURL || '').trim(),
		deviceID: String(labConfig.deviceID || '').trim(),
		capabilityToken: String(labConfig.capabilityToken || '').trim(),
		handshakePath: String(labConfig.handshakePath || '/handshake').trim(),
		bootstrapPath: String(labConfig.bootstrapPath || '/bootstrap').trim(),
		csrfHeaderName: String(labConfig.csrfHeaderName || 'X-CSRF-Token').trim(),
		csrfCookieName: String(labConfig.csrfCookieName || 'securehttp_csrf').trim(),
		csrfToken: String(labConfig.csrfToken || '').trim(),
		autoHandshake: labConfig.autoHandshake !== false,
		gateSecrets: normalizeGateSecrets(labConfig.gateSecrets),
		accessToken: String(labConfig.accessToken || '').trim(),
	}
	if (!normalized.baseURL) {
		throw new Error('labConfig.baseURL is required')
	}
	if (!isPotentiallyTrustedOrigin(normalized.baseURL)) {
		throw new Error('labConfig.baseURL must use HTTPS outside trusted local development hosts')
	}
	const hasDirectSecrets = Boolean(
		normalized.deviceID &&
		normalized.deviceSecret &&
		normalized.capabilityToken &&
		normalized.gateSecrets &&
		normalized.gateSecrets.length > 0,
	)
	const hasBootstrapFlow = Boolean(normalized.bootstrapPath)
	if (!hasDirectSecrets && !hasBootstrapFlow) {
		throw new Error('labConfig requires direct secrets or bootstrapPath')
	}
	return normalized
}

async function toUint8Array(fileLike: File | Blob | Uint8Array): Promise<{
	data: Uint8Array
	filename: string
	contentType: string
}> {
	if (typeof File !== 'undefined' && fileLike instanceof File) {
		return {
			data: new Uint8Array(await fileLike.arrayBuffer()),
			filename: fileLike.name,
			contentType: fileLike.type || 'application/octet-stream',
		}
	}
	if (typeof Blob !== 'undefined' && fileLike instanceof Blob) {
		return {
			data: new Uint8Array(await fileLike.arrayBuffer()),
			filename: 'blob',
			contentType: fileLike.type || 'application/octet-stream',
		}
	}
	if (fileLike instanceof Uint8Array) {
		return {
			data: fileLike,
			filename: 'file',
			contentType: 'application/octet-stream',
		}
	}
	throw new Error('File must be File, Blob, or Uint8Array')
}

async function sha256Base64(bytes: ArrayBuffer, cryptoRef?: Crypto): Promise<string> {
	if (!cryptoRef?.subtle) {
		throw new Error('SubtleCrypto is unavailable for integrity verification')
	}
	const digest = await cryptoRef.subtle.digest('SHA-256', bytes)
	const view = new Uint8Array(digest)
	let output = ''
	for (const value of view) {
		output += String.fromCharCode(value)
	}
	return btoa(output)
}

export class SecureHttpClient implements SecureHttpClientShape {
	readonly config: SecureClientConfig
	wasmUrl: string
	windowRef: SecureFetchRuntimeScope
	fetchImpl?: typeof fetch
	WebAssemblyRef?: typeof WebAssembly
	cryptoRef?: Crypto
	GoClass?: SecureClientConfig['GoClass']
	readyTimeoutMs: number
	initPromise: Promise<void> | null
	state: string
	labConfig: LabConfig | null
	appliedConfigKey: string | null

	constructor(config: SecureClientConfig) {
		this.config = { ...config }
		this.wasmUrl = this.config.wasmUrl
		this.windowRef = this.config.windowRef || (globalThis as SecureFetchRuntimeScope)
		this.fetchImpl = this.config.fetchImpl || this.windowRef.fetch?.bind(this.windowRef) || globalThis.fetch?.bind(globalThis)
		this.WebAssemblyRef = this.config.WebAssemblyRef || globalThis.WebAssembly
		this.cryptoRef = this.config.cryptoRef || globalThis.crypto
		this.GoClass =
			this.config.GoClass || this.windowRef.Go || (globalThis as SecureFetchRuntimeScope).Go
		this.readyTimeoutMs = this.config.readyTimeoutMs || DEFAULT_READY_TIMEOUT_MS
		this.initPromise = null
		this.state = 'idle'
		this.labConfig = normalizeLabConfig(this.config.labConfig)
		this.appliedConfigKey = null
	}

	get isReady(): boolean {
		return this.state === 'ready'
	}

	set isReady(value: boolean) {
		this.state = value ? 'ready' : 'idle'
	}

	async init(nextConfig?: LabConfig): Promise<void> {
		if (nextConfig) {
			this.configure(nextConfig)
		}
		if (this.initPromise) {
			await this.initPromise
			if (this.labConfig) {
				await this.applyLabConfig()
			}
			return
		}
		this.state = 'initializing'
		this.initPromise = this.bootstrap()
		try {
			await this.initPromise
		} catch (error) {
			this.state = 'error'
			this.initPromise = null
			throw error
		}
	}

	configure(labConfig: LabConfig): LabConfig {
		const normalized = normalizeLabConfig(labConfig)
		if (!normalized) {
			throw new Error('labConfig is required')
		}
		this.labConfig = normalized
		return normalized
	}

	private configKey(): string | null {
		if (!this.labConfig) {
			return null
		}
		return JSON.stringify(this.labConfig)
	}

	private refreshCSRFToken(): void {
		if (!this.labConfig) {
			return
		}
		const cookieName = this.labConfig.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME
		const nextToken = readCookieValue(cookieName, this.windowRef.document?.cookie || '')
		if (nextToken) {
			this.labConfig = {
				...this.labConfig,
				csrfToken: nextToken,
			}
		}
	}

	private async applyLabConfig(): Promise<void> {
		if (!this.labConfig) {
			return
		}
		if (!this.hasBridge()) {
			throw new Error('secureFetch bridge is not ready')
		}
		const nextKey = this.configKey()
		if (nextKey === this.appliedConfigKey) {
			return
		}
		await this.windowRef.secureFetchInit?.(this.labConfig)
		this.appliedConfigKey = nextKey
		this.state = 'ready'
	}

	private async bootstrap(): Promise<void> {
		if (!this.wasmUrl) {
			throw new Error('wasmUrl is required')
		}
		if (!isPotentiallyTrustedOrigin(this.wasmUrl)) {
			throw new Error('wasmUrl must use HTTPS outside trusted local development hosts')
		}
		if (typeof this.GoClass !== 'function') {
			throw new Error('Go WASM loader not found. Ensure wasm_exec.js is loaded.')
		}
		if (typeof this.fetchImpl !== 'function') {
			throw new Error('Fetch API not available.')
		}
		if (!this.WebAssemblyRef) {
			throw new Error('WebAssembly is unavailable.')
		}

		const go = new this.GoClass()
		const response = await this.fetchImpl(this.wasmUrl, { integrity: this.config.wasmIntegrity })
		if (!response?.ok) {
			throw new Error(`Failed to fetch WASM from ${this.wasmUrl}: ${response?.status ?? 'unknown'}`)
		}

		const bytes = await response.arrayBuffer()
		if (this.config.expectedWasmSha256) {
			const digest = await sha256Base64(bytes, this.cryptoRef)
			if (digest !== this.config.expectedWasmSha256) {
				throw new Error('WASM integrity check failed')
			}
		}

		const instanceResult = await this.WebAssemblyRef.instantiate(bytes, go.importObject)
		Promise.resolve(go.run(instanceResult.instance)).catch(() => { })
		await this.waitForBridge()
		await this.applyLabConfig()
		this.state = 'ready'
	}

	private async waitForBridge(): Promise<void> {
		const start = Date.now()
		while (Date.now() - start < this.readyTimeoutMs) {
			if (this.hasBridge()) {
				return
			}
			await sleep(25)
		}
		throw new Error('Timeout waiting for secureFetch bridge')
	}

	private hasBridge(): boolean {
		return (
			typeof this.windowRef.secureFetchInit === 'function' &&
			typeof this.windowRef.secureFetch === 'function' &&
			typeof this.windowRef.secureFetchHandshake === 'function' &&
			typeof this.windowRef.secureFetchReset === 'function'
		)
	}

	private async ensureConfigured(): Promise<void> {
		await this.init()
		if (!this.labConfig) {
			throw new Error('SecureHttp client is not configured')
		}
	}

	async handshake(force = false): Promise<void> {
		await this.ensureConfigured()
		await this.windowRef.secureFetchHandshake?.(Boolean(force))
		this.state = 'ready'
	}

	private isRecoverableSessionError(error: unknown): boolean {
		const message = String((error as Error | undefined)?.message || error || '').toLowerCase()
		return (
			message.includes('session expired or missing') ||
			message.includes('request failed with status 404') ||
			message.includes('request failed with status 401') ||
			message.includes('request failed with status 403') ||
			message.includes('missing authorization token') ||
			message.includes('invalid token') ||
			message.includes('session not found') ||
			message.includes('fingerprint mismatch') ||
			message.includes('missing session')
		)
	}

	private async recoverSession(): Promise<void> {
		if (!this.labConfig) {
			throw new Error('SecureHttp client is not configured')
		}
		this.refreshCSRFToken()
		this.windowRef.secureFetchReset?.()
		this.appliedConfigKey = null
		this.state = 'recovering'
		await this.applyLabConfig()
		this.state = 'ready'
	}

	private async performRequest(payload: SecureFetchPayload): Promise<any> {
		const secureFetch = this.windowRef.secureFetch
		if (typeof secureFetch !== 'function') {
			throw new Error('secureFetch bridge is not ready')
		}
		try {
			return await secureFetch(payload)
		} catch (error) {
			if (!this.isRecoverableSessionError(error)) {
				throw error
			}
			await this.recoverSession()
			return secureFetch({
				...payload,
				forceHandshake: true,
			})
		}
	}

	async request(request: FetchRequest): Promise<any> {
		await this.ensureConfigured()
		const payload: SecureFetchPayload = {
			endpoint: request.endpoint,
			body: request.body ?? null,
			responseType: normalizeResponseType(request.responseType),
			method: normalizeMethod(request.method),
			forceHandshake: Boolean(request.forceHandshake),
		}
		return this.performRequest(payload)
	}

	async fetch(endpoint: string, body?: unknown, responseType: ResponseType = 'json', method = 'POST'): Promise<any> {
		return this.request({ endpoint, body, responseType, method })
	}

	async get(endpoint: string, responseType: ResponseType = 'json'): Promise<any> {
		return this.request({ endpoint, responseType, method: 'GET' })
	}

	async post(endpoint: string, body?: unknown, responseType: ResponseType = 'json'): Promise<any> {
		return this.request({ endpoint, body, responseType, method: 'POST' })
	}

	async put(endpoint: string, body?: unknown, responseType: ResponseType = 'json'): Promise<any> {
		return this.request({ endpoint, body, responseType, method: 'PUT' })
	}

	async delete(endpoint: string, responseType: ResponseType = 'json'): Promise<any> {
		return this.request({ endpoint, responseType, method: 'DELETE' })
	}

	async patch(endpoint: string, body?: unknown, responseType: ResponseType = 'json'): Promise<any> {
		return this.request({ endpoint, body, responseType, method: 'PATCH' })
	}

	async uploadFile(
		endpoint: string,
		file: File | Blob | Uint8Array,
		filename?: string,
		fieldName = 'file',
		formData: Record<string, unknown> = {},
		responseType: ResponseType = 'json',
	): Promise<any> {
		await this.ensureConfigured()
		const normalized = await toUint8Array(file)
		return this.performRequest({
			endpoint,
			file: normalized.data,
			filename: filename || normalized.filename,
			fieldName,
			formData: {
				...formData,
				__file_content_type__: normalized.contentType,
			},
			responseType: normalizeResponseType(responseType),
			method: 'POST',
		})
	}

	async reset(): Promise<void> {
		this.windowRef.secureFetchReset?.()
		this.appliedConfigKey = null
		this.state = 'idle'
		this.initPromise = null
	}
}

export class SecureClient extends SecureHttpClient { }

export function createSecureHttpClient(config: SecureClientConfig): SecureHttpClient {
	return new SecureHttpClient(config)
}
