import crypto from "node:crypto";

const DEFAULT_GATE_HEADERS = {
  secretID: "X-Gate-Key",
  timestamp: "X-Gate-Timestamp",
  nonce: "X-Gate-Nonce",
  signature: "X-Gate-Signature",
  capability: "X-Capability-Token",
};

const DEFAULT_TRANSPORT_HEADERS = {
  sessionID: "X-Session-ID",
  userToken: "X-User-Token",
};

const DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000;
const DEFAULT_MESSAGE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;

function decodeBase64(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} is required`);
  }
  return Buffer.from(value, "base64");
}

function encodeBase64(value) {
  return Buffer.from(value).toString("base64");
}

function parseJSONBuffer(rawBody) {
  const text = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody || "");
  return text ? JSON.parse(text) : {};
}

function cloneMap(input) {
  if (!input || typeof input !== "object") {
    return {};
  }
  return { ...input };
}

function toSet(values) {
  if (!Array.isArray(values)) {
    return new Set();
  }
  return new Set(values.map((value) => String(value || "").trim().toUpperCase()).filter(Boolean));
}

function uint64BE(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value), 0);
  return buffer;
}

function deriveKeys(sharedSecret) {
  const okm = Buffer.from(
    crypto.hkdfSync("sha512", sharedSecret, Buffer.alloc(0), Buffer.from("secure-communication-v1", "utf8"), 64),
  );
  return {
    encKey: okm.subarray(0, 32),
    macKey: okm.subarray(32, 64),
  };
}

function computeHMAC(key, payload) {
  return crypto.createHmac("sha256", key).update(payload).digest();
}

function gateCanonicalPayload(method, path, timestamp, nonce, capability) {
  return Buffer.from(
    [
      String(method || "").trim().toUpperCase(),
      normalizePath(path),
      String(timestamp),
      String(nonce),
      String(capability),
    ].join("\n"),
    "utf8",
  );
}

function normalizePath(rawPath) {
  const value = String(rawPath || "").trim();
  if (!value) {
    return "/";
  }
  try {
    const parsed = new URL(value, "http://localhost");
    return parsed.pathname || "/";
  } catch {
    if (value.startsWith("/")) {
      return value.split("?")[0] || "/";
    }
    return `/${value.split("?")[0]}`;
  }
}

function pathMatches(pattern, path) {
  if (!pattern) {
    return false;
  }
  if (pattern.endsWith("*")) {
    return path.startsWith(pattern.slice(0, -1));
  }
  return pattern === path;
}

function normalizeOrigin(origin) {
  const value = String(origin || "").trim().toLowerCase().replace(/\/+$/, "");
  if (!value) {
    return "";
  }
  try {
    return new URL(value).origin.toLowerCase();
  } catch {
    return value;
  }
}

function timingSafeEquals(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function fingerprintForRequest(req) {
  const ip = clientIP(req);
  const userAgent = String(req?.headers?.["user-agent"] || "");
  if (!ip && !userAgent.trim()) {
    return "";
  }
  return crypto.createHash("sha256").update(`${ip.trim()}|${userAgent.trim()}`).digest("hex");
}

function clientIP(req) {
  const forwarded = String(req?.headers?.["x-forwarded-for"] || "").trim();
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  return String(req?.socket?.remoteAddress || req?.connection?.remoteAddress || "").trim();
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function writeJSON(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(payload));
}

function writeNotFound(res) {
  res.statusCode = 404;
  res.end();
}

function ensureArray(value) {
  return Array.isArray(value) ? value : [];
}

function buildCapabilityMatcher(definition) {
  const methods = toSet(definition.methods);
  const paths = ensureArray(definition.paths).map((entry) => String(entry || "").trim()).filter(Boolean);
  const routes = ensureArray(definition.routes).map((route) => ({
    path: String(route?.path || "").trim(),
    methods: toSet(route?.methods),
  })).filter((route) => route.path);

  return {
    token: String(definition.token || "").trim(),
    metadata: cloneMap(definition.metadata),
    allows(method, path) {
      const normalizedMethod = String(method || "").trim().toUpperCase();
      const normalizedPath = normalizePath(path);
      if (routes.length > 0) {
        return routes.some((route) => pathMatches(route.path, normalizedPath) && (route.methods.size === 0 || route.methods.has(normalizedMethod)));
      }
      if (methods.size > 0 && !methods.has(normalizedMethod)) {
        return false;
      }
      if (paths.length === 0) {
        return true;
      }
      return paths.some((pattern) => pathMatches(pattern, normalizedPath));
    },
  };
}

function normalizeRouteKey(method, path) {
  return `${String(method || "").trim().toUpperCase()} ${normalizePath(path)}`;
}

class SecureSession {
  constructor({ sessionID, encKey, macKey, expiresAt, metadata }) {
    this.sessionID = sessionID;
    this.encKey = Buffer.from(encKey);
    this.macKey = Buffer.from(macKey);
    this.expiresAt = expiresAt;
    this.metadata = cloneMap(metadata);
  }

  encrypt(plaintext) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
    const timestamp = Math.floor(Date.now() / 1000);
    const macPayload = Buffer.concat([nonce, ciphertext, uint64BE(timestamp)]);
    return {
      nonce: encodeBase64(nonce),
      ciphertext: encodeBase64(ciphertext),
      hmac: encodeBase64(computeHMAC(this.macKey, macPayload)),
      timestamp,
    };
  }

  decrypt(message, messageTTLms) {
    const nonce = decodeBase64(message?.nonce, "nonce");
    const ciphertext = decodeBase64(message?.ciphertext, "ciphertext");
    const mac = decodeBase64(message?.hmac, "hmac");
    const timestamp = Number(message?.timestamp || 0);
    if (!Number.isFinite(timestamp) || timestamp <= 0) {
      throw new Error("invalid timestamp");
    }
    const now = Date.now();
    const drift = now - timestamp * 1000;
    if (drift > messageTTLms || drift < -messageTTLms) {
      throw new Error("message expired");
    }
    const expected = computeHMAC(this.macKey, Buffer.concat([nonce, ciphertext, uint64BE(timestamp)]));
    if (!timingSafeEquals(expected, mac)) {
      throw new Error("HMAC verification failed");
    }
    const authTag = ciphertext.subarray(ciphertext.length - 16);
    const body = ciphertext.subarray(0, ciphertext.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.encKey, nonce);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  }
}

export class SecureHttpServerSDK {
  constructor(config = {}) {
    this.config = config;
    this.handshakePath = normalizePath(config.handshakePath || "/handshake");
    this.transportHeaders = {
      ...DEFAULT_TRANSPORT_HEADERS,
      ...(config.transportHeaders || {}),
    };
    this.gateHeaders = {
      ...DEFAULT_GATE_HEADERS,
      ...(config.gateHeaders || {}),
    };
    this.requireDevice = config.requireDevice !== false;
    this.requireUser = Boolean(config.requireUser);
    this.sessionTTLms = Number(config.sessionTTLms || DEFAULT_SESSION_TTL_MS);
    this.messageTTLms = Number(config.messageTTLms || DEFAULT_MESSAGE_TTL_MS);
    this.maxClockSkewMs = Number(config.maxClockSkewMs || DEFAULT_CLOCK_SKEW_MS);
    this.strictOrigin = Boolean(config.strictOrigin);
    this.allowedOrigins = new Set(ensureArray(config.allowedOrigins).map(normalizeOrigin).filter(Boolean));
    this.deviceSecrets = new Map(Object.entries(config.deviceSecrets || {}).map(([key, value]) => [key, Buffer.from(value)]));
    this.capabilities = new Map(ensureArray(config.capabilities).map(buildCapabilityMatcher).filter((entry) => entry.token).map((entry) => [entry.token, entry]));
    this.gateSecrets = ensureArray(config.gateSecrets).map((secret) => ({
      id: String(secret?.id || "").trim(),
      secret: Buffer.from(secret?.secret || ""),
      notBefore: secret?.notBefore ? Date.parse(secret.notBefore) : Number.NEGATIVE_INFINITY,
      expiresAt: secret?.expiresAt ? Date.parse(secret.expiresAt) : Number.POSITIVE_INFINITY,
    })).filter((secret) => secret.id && secret.secret.length > 0);
    this.sessions = new Map();
    this.userAuthenticator = typeof config.userAuthenticator === "function" ? config.userAuthenticator : async () => null;
    this.ecdh = crypto.createECDH("prime256v1");
    this.ecdh.generateKeys();
  }

  serverPublicKey() {
    return this.ecdh.getPublicKey();
  }

  buildLoginResponse({
    userID,
    baseURL = "",
    bootstrapPath = "/auth/bootstrap",
    handshakePath = this.handshakePath,
    cookieAuth = true,
    csrfCookieName = "securehttp_csrf",
    csrfHeaderName = "X-CSRF-Token",
    accessToken = "",
    refreshToken = "",
    csrfToken = "",
  }) {
    const response = {
      status: 200,
      success: true,
      userID,
      user_id: userID,
      bootstrapPath: normalizePath(bootstrapPath),
      handshakePath: normalizePath(handshakePath),
      baseURL,
      cookieAuth: Boolean(cookieAuth),
      csrfCookieName,
      csrfHeaderName,
    };
    if (!cookieAuth) {
      response.accessToken = accessToken;
      response.refreshToken = refreshToken;
      response.csrfToken = csrfToken;
    }
    return response;
  }

  buildBootstrapConfig({ baseURL = "", deviceID, userToken = "", capabilityToken, handshakePath = this.handshakePath }) {
    const gateSecrets = this.gateSecrets.map((secret) => ({
      id: secret.id,
      secret: String(this.config.gateSecretStrings?.[secret.id] || ""),
    })).filter((entry) => entry.secret);
    const deviceSecret = this.config.deviceSecretStrings?.[deviceID];
    if (!deviceSecret) {
      throw new Error(`device secret not found for ${deviceID}`);
    }
    if (!capabilityToken) {
      throw new Error("capabilityToken is required");
    }
    if (gateSecrets.length === 0) {
      throw new Error("at least one gate secret must be exported");
    }
    return {
      baseURL,
      deviceID,
      deviceSecret,
      userToken,
      handshakePath: normalizePath(handshakePath),
      capabilityToken,
      gateSecrets,
    };
  }

  verifyGate(req) {
    const origin = normalizeOrigin(req.headers.origin || req.headers.referer || "");
    if ((this.allowedOrigins.size > 0 || this.strictOrigin) && (!origin || !this.allowedOrigins.has(origin))) {
      throw new Error("origin not allowed");
    }

    const secretID = String(req.headers[this.gateHeaders.secretID.toLowerCase()] || "").trim();
    const timestamp = String(req.headers[this.gateHeaders.timestamp.toLowerCase()] || "").trim();
    const nonce = String(req.headers[this.gateHeaders.nonce.toLowerCase()] || "").trim();
    const signature = String(req.headers[this.gateHeaders.signature.toLowerCase()] || "").trim();
    const capabilityToken = String(req.headers[this.gateHeaders.capability.toLowerCase()] || "").trim();
    if (!secretID || !timestamp || !nonce || !signature || !capabilityToken) {
      throw new Error("missing gate headers");
    }

    const ts = Number.parseInt(timestamp, 10);
    if (!Number.isFinite(ts)) {
      throw new Error("invalid timestamp");
    }
    const drift = Date.now() - ts * 1000;
    if (drift > this.maxClockSkewMs || drift < -this.maxClockSkewMs) {
      throw new Error("timestamp skew");
    }

    const capability = this.capabilities.get(capabilityToken);
    if (!capability || !capability.allows(req.method, req.url)) {
      throw new Error("capability denied");
    }

    const secret = this.gateSecrets.find((entry) => entry.id === secretID && Date.now() >= entry.notBefore && Date.now() <= entry.expiresAt);
    if (!secret) {
      throw new Error("unknown gate secret");
    }

    const expected = computeHMAC(secret.secret, gateCanonicalPayload(req.method, req.url, timestamp, nonce, capabilityToken));
    const provided = Buffer.from(signature, "base64");
    if (!timingSafeEquals(expected, provided)) {
      throw new Error("invalid gate signature");
    }

    return {
      token: capabilityToken,
      metadata: cloneMap(capability.metadata),
    };
  }

  async handleHandshake(req, res) {
    try {
      const body = parseJSONBuffer(await readRequestBody(req));
      const clientPublicKey = decodeBase64(body.client_public_key, "client_public_key");
      const deviceSignature = decodeBase64(body.device_signature, "device_signature");
      const deviceID = String(body.device_id || "").trim();
      const userToken = String(body.user_token || "").trim();
      const timestamp = Number(body.timestamp || 0);
      if (!Number.isFinite(timestamp) || timestamp <= 0) {
        throw new Error("invalid timestamp");
      }

      const drift = Date.now() - timestamp * 1000;
      if (drift > this.maxClockSkewMs || drift < -this.maxClockSkewMs) {
        throw new Error("timestamp skew");
      }

      if (this.requireDevice) {
        const deviceSecret = this.deviceSecrets.get(deviceID);
        if (!deviceSecret) {
          throw new Error("unknown device");
        }
        const payload = Buffer.concat([clientPublicKey, uint64BE(timestamp)]);
        const expected = computeHMAC(deviceSecret, payload);
        if (!timingSafeEquals(expected, deviceSignature)) {
          throw new Error("invalid device signature");
        }
      }

      let userContext = null;
      if (userToken) {
        userContext = await this.userAuthenticator(userToken);
        if (!userContext) {
          throw new Error("invalid user token");
        }
      } else if (this.requireUser) {
        throw new Error("missing user token");
      }

      const sharedSecret = this.ecdh.computeSecret(clientPublicKey);
      const { encKey, macKey } = deriveKeys(sharedSecret);
      const sessionID = crypto.randomBytes(32).toString("base64");
      const metadata = {};
      if (deviceID) {
        metadata.device_id = deviceID;
      }
      if (userContext?.id) {
        metadata.user_id = String(userContext.id);
      }
      if (Array.isArray(userContext?.roles) && userContext.roles.length > 0) {
        metadata.user_roles = userContext.roles.join(",");
      }
      if (userContext?.metadata && typeof userContext.metadata === "object") {
        for (const [key, value] of Object.entries(userContext.metadata)) {
          metadata[`user_meta_${key}`] = String(value);
        }
      }
      const fingerprint = fingerprintForRequest(req);
      if (fingerprint) {
        metadata.session_fp = fingerprint;
      }

      const expiresAt = Date.now() + this.sessionTTLms;
      this.sessions.set(sessionID, new SecureSession({
        sessionID,
        encKey,
        macKey,
        expiresAt,
        metadata,
      }));

      writeJSON(res, 200, {
        server_public_key: encodeBase64(this.serverPublicKey()),
        session_id: encodeBase64(Buffer.from(sessionID, "utf8")),
        device_id: deviceID,
        expires_at: Math.floor(expiresAt / 1000),
        timestamp: Math.floor(Date.now() / 1000),
      });
    } catch {
      writeNotFound(res);
    }
  }

  async executeSecure(req, res, handler) {
    let sessionID = "";
    try {
      sessionID = String(req.headers[this.transportHeaders.sessionID.toLowerCase()] || "").trim();
      if (!sessionID) {
        throw new Error("missing session");
      }
      const session = this.sessions.get(sessionID);
      if (!session || Date.now() > session.expiresAt) {
        this.sessions.delete(sessionID);
        throw new Error("invalid session");
      }
      const fingerprint = fingerprintForRequest(req);
      if (!session.metadata.session_fp || session.metadata.session_fp !== fingerprint) {
        this.sessions.delete(sessionID);
        throw new Error("fingerprint mismatch");
      }

      let userContext = null;
      const userToken = String(req.headers[this.transportHeaders.userToken.toLowerCase()] || "").trim();
      if (userToken) {
        userContext = await this.userAuthenticator(userToken);
        if (!userContext) {
          throw new Error("invalid user token");
        }
      } else if (this.requireUser && !session.metadata.user_id) {
        throw new Error("missing user token");
      } else if (session.metadata.user_id) {
        userContext = {
          id: session.metadata.user_id,
          roles: session.metadata.user_roles ? session.metadata.user_roles.split(",") : [],
          metadata: Object.fromEntries(
            Object.entries(session.metadata)
              .filter(([key]) => key.startsWith("user_meta_"))
              .map(([key, value]) => [key.slice("user_meta_".length), value]),
          ),
        };
      }

      const rawBody = await readRequestBody(req);
      let plaintext = Buffer.alloc(0);
      const method = String(req.method || "").toUpperCase();
      const allowsEmpty = method === "GET" || method === "HEAD" || method === "OPTIONS" || method === "DELETE";
      if (rawBody.length > 0) {
        plaintext = session.decrypt(parseJSONBuffer(rawBody), this.messageTTLms);
      } else if (!allowsEmpty) {
        throw new Error("empty body");
      }

      const result = await handler({
        req,
        res,
        plaintext,
        json() {
          return plaintext.length > 0 ? JSON.parse(plaintext.toString("utf8")) : null;
        },
        sessionID,
        deviceID: session.metadata.device_id || "",
        userContext,
        session,
      });

      if (res.writableEnded) {
        return;
      }

      const responseBody = result === undefined ? Buffer.alloc(0)
        : Buffer.isBuffer(result) ? result
          : typeof result === "string" ? Buffer.from(result, "utf8")
            : Buffer.from(JSON.stringify(result), "utf8");

      if (responseBody.length === 0) {
        res.statusCode = res.statusCode || 200;
        res.end();
        return;
      }

      const encrypted = session.encrypt(responseBody);
      writeJSON(res, res.statusCode || 200, encrypted);
    } catch {
      if (sessionID) {
        this.sessions.delete(sessionID);
      }
      if (!res.writableEnded) {
        writeNotFound(res);
      }
    }
  }

  createNodeHandlers() {
    return {
      handshake: this.handleHandshake.bind(this),
      secure: (handler) => this.executeSecure.bind(this, undefined, undefined, handler),
    };
  }

  createHTTPRequestHandler(routes = {}) {
    const secureRoutes = new Map(
      Object.entries(routes.secure || {}).map(([key, value]) => {
        const separator = key.indexOf(" ");
        if (separator <= 0) {
          return [normalizeRouteKey("GET", key), value];
        }
        return [normalizeRouteKey(key.slice(0, separator), key.slice(separator + 1)), value];
      }),
    );
    return async (req, res) => {
      try {
        this.verifyGate(req);
      } catch {
        writeNotFound(res);
        return;
      }
      const routeKey = normalizeRouteKey(req.method, req.url);
      if (routeKey === normalizeRouteKey("POST", this.handshakePath)) {
        await this.handleHandshake(req, res);
        return;
      }
      const handler = secureRoutes.get(routeKey);
      if (!handler) {
        writeNotFound(res);
        return;
      }
      await this.executeSecure(req, res, handler);
    };
  }
}

export function createExpressAdapter(sdk) {
  return {
    gate(req, res, next) {
      try {
        req.secureHttpCapability = sdk.verifyGate(req);
        next();
      } catch {
        res.status(404).end();
      }
    },
    async handshake(req, res) {
      await sdk.handleHandshake(req, res);
    },
    secure(handler) {
      return async (req, res) => {
        await sdk.executeSecure(req, res, handler);
      };
    },
  };
}
