import type { LabConfig, SecureHttpClient } from "./types";

export interface SecureSession {
    identity: string;
    timestamp: number;
    config: Partial<LabConfig> & {
        baseURL: string;
    };
}

export interface SessionStore {
    storageKey: string;
    load(): SecureSession | null;
    save(session: SecureSession): boolean;
    clear(): void;
}

export function readCookieValue(name: string, source?: string): string;
export function createSessionStore(options?: {
    storage?: Storage;
    storageKey?: string;
}): SessionStore;
export function isSessionAuthError(error: unknown): boolean;
export function resolveSessionPayload(payload: any, options?: {
    windowRef?: Window;
    cookieSource?: string;
    baseURL?: string;
    handshakePath?: string;
    bootstrapPath?: string;
    csrfCookieName?: string;
    csrfHeaderName?: string;
    autoHandshake?: boolean;
    credentials?: Record<string, unknown>;
    resolveIdentity?: (payload: any, credentials?: Record<string, unknown>) => string;
    createSession?: (context: {
        identity: string;
        payload: any;
        config: LabConfig;
    }) => SecureSession;
}): {
    identity: string;
    payload: any;
    config: LabConfig;
    session: SecureSession;
};
export function loginWithCredentials(options?: {
    client?: SecureHttpClient;
    windowRef?: Window;
    fetchImpl?: typeof fetch;
    credentials?: Record<string, unknown>;
    loginUrl?: string;
    requestCredentials?: RequestCredentials;
    buildLoginRequest?: (credentials: Record<string, unknown>) => RequestInit;
    parseResponse?: (response: Response) => Promise<any>;
    getErrorMessage?: (payload: any, response: Response) => string;
    sessionStore?: SessionStore;
    baseURL?: string;
    handshakePath?: string;
    bootstrapPath?: string;
    csrfCookieName?: string;
    csrfHeaderName?: string;
    autoHandshake?: boolean;
    cookieSource?: string;
    resolveIdentity?: (payload: any, credentials?: Record<string, unknown>) => string;
    createSession?: (context: {
        identity: string;
        payload: any;
        config: LabConfig;
    }) => SecureSession;
}): Promise<{
    identity: string;
    payload: any;
    config: LabConfig;
    session: SecureSession;
}>;
export function restoreSession(options?: {
    client: SecureHttpClient;
    windowRef?: Window;
    sessionStore?: SessionStore;
    cookieSource?: string;
}): Promise<{
    identity: string;
    session: SecureSession;
    config: LabConfig;
} | null>;
export function logoutSession(options?: {
    client?: SecureHttpClient;
    windowRef?: Window;
    fetchImpl?: typeof fetch;
    sessionStore?: SessionStore;
    cookieSource?: string;
    logoutUrl?: string;
    requestCredentials?: RequestCredentials;
    csrfCookieName?: string;
    csrfHeaderName?: string;
    performLogout?: (context: {
        client?: SecureHttpClient;
        cookieSource: string;
        fetch: typeof fetch | null;
        sessionStore?: SessionStore;
        windowRef?: Window;
    }) => Promise<void>;
}): Promise<void>;
export const DEFAULT_SESSION_STORAGE_KEY: string;
export const DEFAULT_CSRF_COOKIE_NAME: string;
export const DEFAULT_CSRF_HEADER_NAME: string;
