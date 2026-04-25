const DEFAULT_SESSION_STORAGE_KEY = "secure_http_session";
const DEFAULT_CSRF_COOKIE_NAME = "securehttp_csrf";
const DEFAULT_CSRF_HEADER_NAME = "X-CSRF-Token";

function resolveWindowRef(windowRef) {
    return windowRef || globalThis;
}

function resolveFetch(fetchImpl, windowRef) {
    if (typeof fetchImpl === "function") {
        return fetchImpl;
    }
    if (typeof windowRef?.fetch === "function") {
        return windowRef.fetch.bind(windowRef);
    }
    if (typeof globalThis.fetch === "function") {
        return globalThis.fetch.bind(globalThis);
    }
    throw new Error("Fetch API not available.");
}

function defaultParseResponse(response) {
    return response.json();
}

function defaultLoginRequest(credentials) {
    return {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(credentials),
    };
}

function defaultResolveIdentity(payload, credentials) {
    if (payload?.userID) {
        return payload.userID;
    }
    if (payload?.user_id) {
        return payload.user_id;
    }
    if (payload?.username) {
        return payload.username;
    }
    return credentials?.username || "";
}

export function readCookieValue(name, source) {
    const cookieSource = typeof source === "string" ? source : "";
    const prefix = `${name}=`;
    const entries = cookieSource ? cookieSource.split("; ") : [];
    for (const entry of entries) {
        if (entry.startsWith(prefix)) {
            return decodeURIComponent(entry.slice(prefix.length));
        }
    }
    return "";
}

export function createSessionStore(options = {}) {
    const storageKey = options.storageKey || DEFAULT_SESSION_STORAGE_KEY;
    return {
        load() {
            try {
                const storage = options.storage || globalThis.sessionStorage;
                const raw = storage?.getItem?.(storageKey);
                return raw ? JSON.parse(raw) : null;
            } catch (error) {
                return null;
            }
        },
        save(session) {
            try {
                const storage = options.storage || globalThis.sessionStorage;
                storage?.setItem?.(storageKey, JSON.stringify(session));
                return true;
            } catch (error) {
                return false;
            }
        },
        clear() {
            try {
                const storage = options.storage || globalThis.sessionStorage;
                storage?.removeItem?.(storageKey);
            } catch (error) {}
        },
        storageKey,
    };
}

export function isSessionAuthError(error) {
    const message = String(error?.message || error || "").toLowerCase();
    return message.includes("bootstrap failed with status 401") ||
        message.includes("bootstrap failed with status 403") ||
        message.includes("bootstrap failed with status 404") ||
        message.includes("auth claims missing") ||
        message.includes("missing authorization token") ||
        message.includes("invalid token") ||
        message.includes("request failed with status 401") ||
        message.includes("request failed with status 403");
}

export function resolveSessionPayload(payload, options = {}) {
    const windowRef = resolveWindowRef(options.windowRef);
    const cookieSource = options.cookieSource !== undefined
        ? options.cookieSource
        : windowRef?.document?.cookie || "";
    const csrfCookieName = options.csrfCookieName || payload?.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME;
    const identity = options.resolveIdentity
        ? options.resolveIdentity(payload, options.credentials)
        : defaultResolveIdentity(payload, options.credentials);
    const config = {
        baseURL: options.baseURL || payload?.baseURL || windowRef?.location?.origin || "",
        handshakePath: payload?.handshakePath || options.handshakePath || "/handshake",
        bootstrapPath: payload?.bootstrapPath || options.bootstrapPath || "/auth/bootstrap",
        csrfCookieName,
        csrfHeaderName: payload?.csrfHeaderName || options.csrfHeaderName || DEFAULT_CSRF_HEADER_NAME,
        csrfToken: readCookieValue(csrfCookieName, cookieSource),
        autoHandshake: options.autoHandshake !== false,
    };
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
    };
}

export async function loginWithCredentials(options = {}) {
    const windowRef = resolveWindowRef(options.windowRef);
    const fetcher = resolveFetch(options.fetchImpl, windowRef);
    const credentials = options.credentials || {};
    const requestInit = options.buildLoginRequest
        ? options.buildLoginRequest(credentials)
        : defaultLoginRequest(credentials);
    const response = await fetcher(options.loginUrl || "/auth/login", {
        credentials: options.requestCredentials || "same-origin",
        ...requestInit,
    });
    const payload = options.parseResponse
        ? await options.parseResponse(response)
        : await defaultParseResponse(response);
    if (!response.ok) {
        const message = options.getErrorMessage
            ? options.getErrorMessage(payload, response)
            : payload?.error || "login failed";
        throw new Error(message);
    }
    const resolved = resolveSessionPayload(payload, {
        ...options,
        credentials,
        windowRef,
    });
    if (options.client) {
        await options.client.init(resolved.config);
    }
    options.sessionStore?.save?.(resolved.session);
    return resolved;
}

export async function restoreSession(options = {}) {
    const windowRef = resolveWindowRef(options.windowRef);
    const saved = options.sessionStore?.load?.();
    if (!saved?.config) {
        return null;
    }
    const csrfCookieName = saved.config.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME;
    const cookieSource = options.cookieSource !== undefined
        ? options.cookieSource
        : windowRef?.document?.cookie || "";
    const csrfToken = readCookieValue(csrfCookieName, cookieSource);
    if (!csrfToken) {
        options.sessionStore?.clear?.();
        return null;
    }

    const config = {
        ...saved.config,
        ...(options.baseURL ? { baseURL: options.baseURL } : {}),
        csrfToken,
        autoHandshake: saved.config.autoHandshake !== false,
    };
    await options.client.init(config);
    return {
        identity: saved.identity || "",
        session: saved,
        config,
    };
}

export async function logoutSession(options = {}) {
    const windowRef = resolveWindowRef(options.windowRef);
    const client = options.client;
    const fetcher = options.performLogout || options.logoutUrl
        ? resolveFetch(options.fetchImpl, windowRef)
        : null;
    try {
        if (options.performLogout) {
            await options.performLogout({
                client,
                cookieSource: options.cookieSource !== undefined
                    ? options.cookieSource
                    : windowRef?.document?.cookie || "",
                fetch: fetcher,
                sessionStore: options.sessionStore,
                windowRef,
            });
        } else if (client?.isReady && fetcher && options.logoutUrl) {
            const csrfCookieName = options.csrfCookieName || DEFAULT_CSRF_COOKIE_NAME;
            const cookieSource = options.cookieSource !== undefined
                ? options.cookieSource
                : windowRef?.document?.cookie || "";
            await fetcher(options.logoutUrl, {
                method: "POST",
                credentials: options.requestCredentials || "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    [options.csrfHeaderName || DEFAULT_CSRF_HEADER_NAME]: readCookieValue(csrfCookieName, cookieSource),
                },
                body: "{}",
            });
        }
    } finally {
        await client?.reset?.();
        options.sessionStore?.clear?.();
    }
}

export { DEFAULT_SESSION_STORAGE_KEY, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_HEADER_NAME };
