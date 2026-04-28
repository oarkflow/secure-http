export type ResponseType = 'json' | 'text' | 'bytes' | 'arraybuffer'

export interface GateSecret {
	id: string
	secret: Uint8Array | string
	notBefore?: string
	not_before?: string
	expiresAt?: string
	expires_at?: string
}

export interface LabConfig {
	baseURL: string
	deviceID?: string
	deviceSecret?: Uint8Array | string
	userToken?: string
	handshakePath?: string
	bootstrapPath?: string
	accessToken?: string
	csrfToken?: string
	csrfHeaderName?: string
	csrfCookieName?: string
	capabilityToken?: string
	gateSecrets?: GateSecret[]
	autoHandshake?: boolean
	timeoutMs?: number
	gateNonceSize?: number
}

export interface FetchRequest {
	endpoint: string
	body?: unknown
	method?: string
	responseType?: ResponseType
	forceHandshake?: boolean
}

export interface SecureFetchPayload extends FetchRequest {
	file?: Uint8Array
	filename?: string
	fieldName?: string
	formData?: Record<string, unknown>
}

export interface GoInstance {
	importObject: WebAssembly.Imports
	run(instance: WebAssembly.Instance): Promise<void> | void
}

export type GoConstructor = new () => GoInstance

export type SecureFetchRuntimeScope = typeof globalThis & {
	Go?: GoConstructor
	secureFetchInit?: (config: LabConfig) => Promise<void> | void
	secureFetch?: (payload: SecureFetchPayload) => Promise<any>
	secureFetchHandshake?: (force?: boolean) => Promise<void> | void
	secureFetchReset?: () => void
}

export interface SecureClientConfig {
	wasmUrl: string
	labConfig?: LabConfig
	expectedWasmSha256?: string
	wasmIntegrity?: string
	windowRef?: SecureFetchRuntimeScope
	fetchImpl?: typeof fetch
	WebAssemblyRef?: typeof WebAssembly
	cryptoRef?: Crypto
	GoClass?: GoConstructor
	readyTimeoutMs?: number
}

export interface SecureHttpClientShape {
	readonly isReady: boolean
	init(labConfig?: LabConfig): Promise<void>
	configure(labConfig: LabConfig): LabConfig
	request(request: FetchRequest): Promise<any>
	fetch(endpoint: string, body?: unknown, responseType?: ResponseType, method?: string): Promise<any>
	get(endpoint: string, responseType?: ResponseType): Promise<any>
	post(endpoint: string, body?: unknown, responseType?: ResponseType): Promise<any>
	put(endpoint: string, body?: unknown, responseType?: ResponseType): Promise<any>
	patch(endpoint: string, body?: unknown, responseType?: ResponseType): Promise<any>
	delete(endpoint: string, responseType?: ResponseType): Promise<any>
	handshake(force?: boolean): Promise<void>
	reset(): Promise<void>
}

export interface SecureSession {
	identity: string
	timestamp: number
	config: Partial<LabConfig> & {
		baseURL: string
	}
}

export interface SessionStore {
	storageKey: string
	load(): SecureSession | null
	save(session: SecureSession): boolean
	clear(): void
}
