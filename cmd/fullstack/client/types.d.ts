
export interface SecureClientConfig {
    /** URL to the securefetch.wasm file */
    wasmUrl: string;
    /** Configuration for the secureFetch initialization */
    labConfig?: LabConfig;
    /** Optional base64 SHA-256 of the wasm module */
    expectedWasmSha256?: string;
}

export interface LabConfig {
    baseURL: string;
    deviceID: string;
    deviceSecret: Uint8Array | string;
    userToken?: string;
    handshakePath?: string;
    capabilityToken: string;
    gateSecrets: GateSecret[];
    autoHandshake?: boolean;
    timeoutMs?: number;
    gateNonceSize?: number;
}

export interface GateSecret {
    id: string;
    secret: Uint8Array | string;
    notBefore?: string;
    expiresAt?: string;
}

export interface FetchRequest {
    endpoint: string;
    body?: any;
    method?: string;
    responseType?: "json" | "text" | "bytes" | "arraybuffer";
    forceHandshake?: boolean;
}

export class SecureHttpClient {
    constructor(config: SecureClientConfig);

    /**
     * Initializes the WASM module and the secure client.
     */
    init(labConfig?: LabConfig): Promise<void>;

    /**
     * Reconfigures the secure transport bootstrap.
     */
    configure(labConfig: LabConfig): LabConfig;

    /**
     * Performs a secure fetch request.
     */
    fetch(endpoint: string, body?: any, responseType?: string): Promise<any>;

    /**
     * Performs a secure request using an explicit request envelope.
     */
    request(request: FetchRequest): Promise<any>;

    /**
     * Forces a handshake with the server.
     */
    handshake(force?: boolean): Promise<void>;

    /**
     * Resets the client session and clears local storage.
     */
    reset(): Promise<void>;
}

export class SecureClient extends SecureHttpClient {}

export function createSecureHttpClient(config: SecureClientConfig): SecureHttpClient;
