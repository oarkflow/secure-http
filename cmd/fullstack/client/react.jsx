import React, {
    createContext,
    useContext,
    useEffect,
    useRef,
    useState,
} from "react";

import { createSecureHttpClient } from "./secure_http.js";
import {
    createSessionStore,
    isSessionAuthError,
    loginWithCredentials,
    logoutSession,
    restoreSession,
} from "./session.js";

const SecureHttpContext = createContext(null);

function createDefaultClient(options) {
    return createSecureHttpClient({
        wasmUrl: options.wasmUrl || "fetch.wasm",
        ...(options.clientConfig || {}),
    });
}

async function runRequest(client, request) {
    if (typeof request === "function") {
        return request(client);
    }
    return client.request(request);
}

export function SecureHttpProvider(props) {
    const { children, client, wasmUrl, clientConfig } = props;
    const clientRef = useRef(client || createDefaultClient({ wasmUrl, clientConfig }));
    if (client && clientRef.current !== client) {
        clientRef.current = client;
    }
    return (
        <SecureHttpContext.Provider value={clientRef.current}>
            {children}
        </SecureHttpContext.Provider>
    );
}

export function useSecureHttpClient(options = {}) {
    const contextClient = useContext(SecureHttpContext);
    const clientRef = useRef(options.client || contextClient || createDefaultClient(options));

    if (options.client && clientRef.current !== options.client) {
        clientRef.current = options.client;
    } else if (!options.client && contextClient && clientRef.current !== contextClient) {
        clientRef.current = contextClient;
    }

    const [status, setStatus] = useState(clientRef.current.isReady ? "ready" : "idle");
    const [error, setError] = useState(null);

    async function initialize(labConfig) {
        setStatus("initializing");
        setError(null);
        try {
            await clientRef.current.init(labConfig);
            setStatus("ready");
        } catch (nextError) {
            setError(nextError);
            setStatus("error");
            throw nextError;
        }
    }

    async function reset() {
        await clientRef.current.reset();
        setError(null);
        setStatus("idle");
    }

    return {
        client: clientRef.current,
        error,
        initialize,
        isReady: status === "ready",
        reset,
        status,
    };
}

export function useSecureSession(options = {}) {
    const clientState = useSecureHttpClient(options);
    const sessionStoreRef = useRef(options.sessionStore || createSessionStore(options.sessionOptions));
    const [identity, setIdentity] = useState("");
    const [session, setSession] = useState(null);
    const [status, setStatus] = useState("idle");
    const [error, setError] = useState(null);
    const restoreStartedRef = useRef(false);

    async function login(credentials) {
        setStatus("authenticating");
        setError(null);
        try {
            const result = await loginWithCredentials({
                ...options,
                client: clientState.client,
                credentials,
                sessionStore: sessionStoreRef.current,
            });
            setIdentity(result.identity);
            setSession(result.session);
            setStatus("authenticated");
            return result;
        } catch (nextError) {
            await clientState.reset();
            sessionStoreRef.current.clear();
            setIdentity("");
            setSession(null);
            setStatus("error");
            setError(nextError);
            throw nextError;
        }
    }

    async function restore() {
        setError(null);
        setStatus("restoring");
        try {
            const restored = await restoreSession({
                ...options,
                client: clientState.client,
                sessionStore: sessionStoreRef.current,
            });
            if (!restored) {
                setIdentity("");
                setSession(null);
                setStatus("idle");
                return null;
            }
            setIdentity(restored.identity);
            setSession(restored.session);
            setStatus("authenticated");
            return restored;
        } catch (nextError) {
            await clientState.reset();
            setIdentity("");
            setSession(null);
            if (isSessionAuthError(nextError)) {
                sessionStoreRef.current.clear();
                setStatus("idle");
            } else {
                setStatus("error");
            }
            setError(nextError);
            return null;
        }
    }

    async function logout() {
        await logoutSession({
            ...options,
            client: clientState.client,
            sessionStore: sessionStoreRef.current,
        });
        setIdentity("");
        setSession(null);
        setStatus("idle");
        setError(null);
    }

    useEffect(() => {
        if (options.restoreOnMount === false || restoreStartedRef.current) {
            return;
        }
        restoreStartedRef.current = true;
        void restore();
    }, [options.restoreOnMount]);

    return {
        client: clientState.client,
        error,
        identity,
        isAuthenticated: Boolean(identity && clientState.client.isReady),
        login,
        logout,
        restore,
        session,
        sessionStore: sessionStoreRef.current,
        status,
        transportStatus: clientState.client.isReady ? "ready" : clientState.status,
    };
}

export function useSecureRequest(options = {}) {
    const clientState = useSecureHttpClient(options);
    const [data, setData] = useState(options.initialData ?? null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    async function execute(overrideRequest) {
        const nextRequest = overrideRequest ?? options.request;
        if (!nextRequest) {
            throw new Error("request is required");
        }
        setLoading(true);
        setError(null);
        try {
            const result = await runRequest(clientState.client, nextRequest);
            setData(result);
            return result;
        } catch (nextError) {
            setError(nextError);
            throw nextError;
        } finally {
            setLoading(false);
        }
    }

    function reset() {
        setData(options.initialData ?? null);
        setError(null);
        setLoading(false);
    }

    useEffect(() => {
        if (options.enabled === false || !options.request || options.immediate === false) {
            return;
        }
        void execute();
    }, [options.enabled, options.immediate, options.request, clientState.client]);

    return {
        client: clientState.client,
        data,
        error,
        execute,
        isReady: clientState.isReady,
        loading,
        reset,
        status: clientState.status,
    };
}

export function useSecureMutation(options = {}) {
    const clientState = useSecureHttpClient(options);
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    async function execute(request) {
        const nextRequest = request ?? options.request;
        if (!nextRequest) {
            throw new Error("request is required");
        }
        setLoading(true);
        setError(null);
        try {
            const result = await runRequest(clientState.client, nextRequest);
            setData(result);
            return result;
        } catch (nextError) {
            setError(nextError);
            throw nextError;
        } finally {
            setLoading(false);
        }
    }

    function reset() {
        setData(null);
        setError(null);
        setLoading(false);
    }

    return {
        client: clientState.client,
        data,
        error,
        execute,
        isReady: clientState.isReady,
        loading,
        reset,
        status: clientState.status,
    };
}
