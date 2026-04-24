
export interface SecureClientConfig {
    /** URL to the securefetch.wasm file */
    wasmUrl: string;
    /** Configuration for the secureFetch initialization */
    labConfig?: LabConfig;
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
}

export interface FetchRequest {
    endpoint: string;
    body?: any;
    responseType?: "json" | "text" | "bytes" | "arraybuffer";
    forceHandshake?: boolean;
}

export class SecureClient {
    constructor(config: SecureClientConfig);

    /**
     * Initializes the WASM module and the secure client.
     */
    init(): Promise<void>;

    /**
     * Performs a secure fetch request.
     */
    fetch(endpoint: string, body?: any, responseType?: string): Promise<any>;

    /**
     * Forces a handshake with the server.
     */
    handshake(force?: boolean): Promise<void>;

    /**
     * Resets the client session and clears local storage.
     */
    reset(): Promise<void>;
}
