import type * as React from "react";
import type { SecureHttpClient, SecureClientConfig, FetchRequest, LabConfig } from "./types";
import type { SecureSession, SessionStore } from "./session";

export function SecureHttpProvider(props: {
    children?: React.ReactNode;
    client?: SecureHttpClient;
    wasmUrl?: string;
    clientConfig?: SecureClientConfig;
}): React.ReactElement;

export function useSecureHttpClient(options?: {
    client?: SecureHttpClient;
    wasmUrl?: string;
    clientConfig?: SecureClientConfig;
}): {
    client: SecureHttpClient;
    error: Error | null;
    initialize(labConfig?: LabConfig): Promise<void>;
    isReady: boolean;
    reset(): Promise<void>;
    status: string;
};

export function useSecureSession(options?: {
    client?: SecureHttpClient;
    wasmUrl?: string;
    clientConfig?: SecureClientConfig;
    sessionStore?: SessionStore;
    sessionOptions?: { storage?: Storage; storageKey?: string };
    restoreOnMount?: boolean;
    windowRef?: Window;
    fetchImpl?: typeof fetch;
    requestCredentials?: RequestCredentials;
    loginUrl?: string;
    logoutUrl?: string;
    cookieSource?: string;
    csrfCookieName?: string;
    csrfHeaderName?: string;
    baseURL?: string;
    handshakePath?: string;
    bootstrapPath?: string;
    autoHandshake?: boolean;
    buildLoginRequest?: (credentials: Record<string, unknown>) => RequestInit;
    parseResponse?: (response: Response) => Promise<any>;
    getErrorMessage?: (payload: any, response: Response) => string;
    resolveIdentity?: (payload: any, credentials?: Record<string, unknown>) => string;
    createSession?: (context: {
        identity: string;
        payload: any;
        config: LabConfig;
    }) => SecureSession;
    performLogout?: (context: {
        client?: SecureHttpClient;
        cookieSource: string;
        fetch: typeof fetch | null;
        sessionStore?: SessionStore;
        windowRef?: Window;
    }) => Promise<void>;
}): {
    client: SecureHttpClient;
    error: Error | null;
    identity: string;
    isAuthenticated: boolean;
    login(credentials: Record<string, unknown>): Promise<{
        identity: string;
        payload: any;
        config: LabConfig;
        session: SecureSession;
    }>;
    logout(): Promise<void>;
    restore(): Promise<{
        identity: string;
        session: SecureSession;
        config: LabConfig;
    } | null>;
    session: SecureSession | null;
    sessionStore: SessionStore;
    status: string;
    transportStatus: string;
};

export function useSecureRequest(options?: {
    client?: SecureHttpClient;
    wasmUrl?: string;
    clientConfig?: SecureClientConfig;
    enabled?: boolean;
    immediate?: boolean;
    initialData?: any;
    request?: FetchRequest | ((client: SecureHttpClient) => Promise<any>);
}): {
    client: SecureHttpClient;
    data: any;
    error: Error | null;
    execute(request?: FetchRequest | ((client: SecureHttpClient) => Promise<any>)): Promise<any>;
    isReady: boolean;
    loading: boolean;
    reset(): void;
    status: string;
};

export function useSecureMutation(options?: {
    client?: SecureHttpClient;
    wasmUrl?: string;
    clientConfig?: SecureClientConfig;
    request?: FetchRequest | ((client: SecureHttpClient) => Promise<any>);
}): {
    client: SecureHttpClient;
    data: any;
    error: Error | null;
    execute(request?: FetchRequest | ((client: SecureHttpClient) => Promise<any>)): Promise<any>;
    isReady: boolean;
    loading: boolean;
    reset(): void;
    status: string;
};
