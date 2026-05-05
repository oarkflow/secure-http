import crypto from "node:crypto";
import { URL } from "node:url";

const DEFAULT_HANDSHAKE_PATH = "/handshake";
const DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000;
const DEFAULT_MESSAGE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_CLOCK_SKEW_MS = 60 * 1000;

function uint64BE(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value));
  return buffer;
}

function hmac(key, payload) {
  return crypto.createHmac("sha256", key).update(payload).digest();
}

function timingSafeEqual(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function hkdf(sharedSecret) {
  const okm = Buffer.from(
    crypto.hkdfSync("sha512", sharedSecret, Buffer.alloc(0), Buffer.from("secure-communication-v1"), 64),
  );
  return {
    encKey: okm.subarray(0, 32),
    macKey: okm.subarray(32, 64),
  };
}

function decodeSecret(secret) {
  if (Buffer.isBuffer(secret)) return Buffer.from(secret);
  if (secret instanceof Uint8Array) return Buffer.from(secret);
  if (typeof secret !== "string") return Buffer.alloc(0);
  if (secret.startsWith("base64:")) return Buffer.from(secret.slice(7), "base64");
  if (secret.startsWith("hex:")) return Buffer.from(secret.slice(4), "hex");
  return Buffer.from(secret);
}

function normalizePath(url) {
  try {
    return new URL(url, "http://localhost").pathname || "/";
  } catch {
    return "/";
  }
}

function routeKey(method, path) {
  return `${String(method || "").toUpperCase()} ${path}`;
}

function pathMatches(pattern, path) {
  if (!pattern) return false;
  if (pattern.endsWith("*")) return path.startsWith(pattern.slice(0, -1));
  return pattern === path;
}

function capabilityAllows(capability, method, path) {
  if (!capability) return false;
  const upperMethod = String(method || "").toUpperCase();
  if (Array.isArray(capability.routes) && capability.routes.length > 0) {
    return capability.routes.some((route) => {
      if (!pathMatches(route.path, path)) return false;
      if (!Array.isArray(route.methods) || route.methods.length === 0) return true;
      return route.methods.map((item) => String(item).toUpperCase()).includes(upperMethod);
    });
  }
  if (Array.isArray(capability.methods) && capability.methods.length > 0) {
    if (!capability.methods.map((item) => String(item).toUpperCase()).includes(upperMethod)) return false;
  }
  if (Array.isArray(capability.paths) && capability.paths.length > 0) {
    return capability.paths.some((pattern) => pathMatches(pattern, path));
  }
  return true;
}

function gatePayload(method, path, timestamp, nonce, capability) {
  return Buffer.from([String(method).toUpperCase(), path, String(timestamp), nonce, capability].join("\n"));
}

function envelopeAuthData(nonce, ciphertext, timestamp) {
  return Buffer.concat([nonce, ciphertext, uint64BE(timestamp)]);
}

function encryptMessage(session, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", session.encKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    hmac: hmac(session.macKey, envelopeAuthData(nonce, ciphertext, timestamp)).toString("base64"),
    timestamp,
  };
}

function decryptMessage(session, message, ttlMs) {
  const nonce = Buffer.from(message?.nonce || "", "base64");
  const ciphertext = Buffer.from(message?.ciphertext || "", "base64");
  const mac = Buffer.from(message?.hmac || "", "base64");
  const timestamp = Number(message?.timestamp || 0);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!timestamp || Math.abs(nowSeconds - timestamp) * 1000 > ttlMs) {
    throw new Error("message expired");
  }
  const expected = hmac(session.macKey, envelopeAuthData(nonce, ciphertext, timestamp));
  if (!timingSafeEqual(expected, mac)) {
    throw new Error("HMAC verification failed");
  }
  const nonceKey = nonce.toString("base64");
  const cutoff = Date.now() - ttlMs;
  for (const [key, seenAt] of session.seenMessages) {
    if (seenAt < cutoff) session.seenMessages.delete(key);
  }
  if (session.seenMessages.has(nonceKey)) {
    throw new Error("message replay detected");
  }
  session.seenMessages.set(nonceKey, Date.now());
  const tag = ciphertext.subarray(ciphertext.length - 16);
  const body = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", session.encKey, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function sendJSON(res, statusCode, payload) {
  res.statusCode = statusCode;
  res.setHeader?.("content-type", "application/json");
  res.end(JSON.stringify(payload));
}

function reject(res) {
  sendJSON(res, 404, { error: "not_found" });
}

export class SecureHttpServerSDK {
  constructor(options = {}) {
    this.handshakePath = options.handshakePath || DEFAULT_HANDSHAKE_PATH;
    this.requireDevice = options.requireDevice !== false;
    this.requireUser = Boolean(options.requireUser);
    this.userAuthenticator = options.userAuthenticator || null;
    this.sessionTTLMS = options.sessionTTLMS || DEFAULT_SESSION_TTL_MS;
    this.messageTTLMS = options.messageTTLMS || DEFAULT_MESSAGE_TTL_MS;
    this.clockSkewMS = options.clockSkewMS || DEFAULT_CLOCK_SKEW_MS;
    this.gateSecrets = new Map();
    this.gateSecretStrings = { ...(options.gateSecretStrings || {}) };
    this.deviceSecrets = new Map();
    this.deviceSecretStrings = { ...(options.deviceSecretStrings || {}) };
    this.capabilities = new Map();
    this.sessions = new Map();
    this.gateNonces = new Map();
    this.ecdh = crypto.createECDH("prime256v1");
    this.ecdh.generateKeys();

    for (const entry of options.gateSecrets || []) {
      if (entry?.id && entry?.secret) this.gateSecrets.set(entry.id, decodeSecret(entry.secret));
    }
    for (const [id, secret] of Object.entries(options.deviceSecrets || {})) {
      this.deviceSecrets.set(id, decodeSecret(secret));
    }
    for (const capability of options.capabilities || []) {
      if (capability?.token) this.capabilities.set(capability.token, capability);
    }
  }

  createHTTPRequestHandler(routes = {}) {
    const secureRoutes = routes.secure || {};
    return async (req, res) => {
      try {
        const method = String(req.method || "GET").toUpperCase();
        const path = normalizePath(req.url || "/");
        if (!this.evaluateGate(req, method, path)) {
          reject(res);
          return;
        }
        if (method === "POST" && path === this.handshakePath) {
          await this.handleHandshake(req, res);
          return;
        }
        const handler = secureRoutes[routeKey(method, path)];
        if (!handler) {
          reject(res);
          return;
        }
        await this.handleSecureRoute(req, res, handler);
      } catch {
        reject(res);
      }
    };
  }

  buildBootstrapConfig(options = {}) {
    const deviceID = String(options.deviceID || "").trim();
    const capabilityToken = String(options.capabilityToken || "").trim();
    return {
      baseURL: String(options.baseURL || "").trim(),
      deviceID,
      deviceSecret: this.deviceSecretStrings[deviceID] || "",
      userToken: String(options.userToken || "").trim(),
      handshakePath: this.handshakePath,
      capabilityToken,
      gateSecrets: [...this.gateSecrets.keys()].map((id) => ({
        id,
        secret: this.gateSecretStrings[id] || this.gateSecrets.get(id)?.toString("base64") || "",
      })),
      autoHandshake: true,
    };
  }

  evaluateGate(req, method, path) {
    const headers = req.headers || {};
    const secretID = String(headers["x-gate-key"] || "").trim();
    const timestamp = String(headers["x-gate-timestamp"] || "").trim();
    const nonce = String(headers["x-gate-nonce"] || "").trim();
    const signature = String(headers["x-gate-signature"] || "").trim();
    const capabilityToken = String(headers["x-capability-token"] || "").trim();
    if (!secretID || !timestamp || !nonce || !signature || !capabilityToken) return false;
    const ts = Number(timestamp);
    if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) * 1000 > this.clockSkewMS) return false;
    const gateSecret = this.gateSecrets.get(secretID);
    if (!gateSecret) return false;
    const capability = this.capabilities.get(capabilityToken);
    if (!capabilityAllows(capability, method, path)) return false;
    const expected = hmac(gateSecret, gatePayload(method, path, timestamp, nonce, capabilityToken));
    const actual = Buffer.from(signature, "base64");
    if (!timingSafeEqual(expected, actual)) return false;
    return !this.gateNonceSeen(secretID, nonce);
  }

  gateNonceSeen(secretID, nonce) {
    const key = `${secretID}::${nonce}`;
    const cutoff = Date.now() - this.messageTTLMS;
    for (const [seenKey, seenAt] of this.gateNonces) {
      if (seenAt < cutoff) this.gateNonces.delete(seenKey);
    }
    if (this.gateNonces.has(key)) return true;
    this.gateNonces.set(key, Date.now());
    return false;
  }

  async handleHandshake(req, res) {
    const body = JSON.parse((await readRequestBody(req)).toString("utf8") || "{}");
    const clientPublicKey = Buffer.from(body.client_public_key || "", "base64");
    const timestamp = Number(body.timestamp || 0);
    if (!timestamp || Math.abs(Date.now() / 1000 - timestamp) * 1000 > this.clockSkewMS) {
      reject(res);
      return;
    }
    const deviceID = String(body.device_id || "").trim();
    if (this.requireDevice) {
      const deviceSecret = this.deviceSecrets.get(deviceID);
      const signature = Buffer.from(body.device_signature || "", "base64");
      const expected = hmac(deviceSecret || Buffer.alloc(0), Buffer.concat([clientPublicKey, uint64BE(timestamp)]));
      if (!deviceSecret || !timingSafeEqual(expected, signature)) {
        reject(res);
        return;
      }
    }
    const userContext = await this.resolveUser(body.user_token || "");
    if (this.requireUser && !userContext) {
      reject(res);
      return;
    }
    const sharedSecret = this.ecdh.computeSecret(clientPublicKey);
    const keys = hkdf(sharedSecret);
    const sessionID = crypto.randomBytes(32).toString("base64");
    this.sessions.set(sessionID, {
      ...keys,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      deviceID,
      userContext,
      seenMessages: new Map(),
    });
    sendJSON(res, 200, {
      server_public_key: this.ecdh.getPublicKey().toString("base64"),
      session_id: Buffer.from(sessionID).toString("base64"),
      device_id: deviceID,
      expires_at: Math.floor((Date.now() + this.sessionTTLMS) / 1000),
      timestamp: Math.floor(Date.now() / 1000),
    });
  }

  async handleSecureRoute(req, res, handler) {
    const sessionID = String(req.headers?.["x-session-id"] || "").trim();
    const session = this.sessions.get(sessionID);
    if (!session || Date.now() - session.lastUsed > this.sessionTTLMS) {
      reject(res);
      return;
    }
    const body = JSON.parse((await readRequestBody(req)).toString("utf8") || "{}");
    const plaintext = decryptMessage(session, body, this.messageTTLMS);
    session.lastUsed = Date.now();
    const userToken = String(req.headers?.["x-user-token"] || "").trim();
    const userContext = userToken ? await this.resolveUser(userToken) : session.userContext;
    if (this.requireUser && !userContext) {
      reject(res);
      return;
    }
    const result = await handler({
      body: plaintext,
      text: () => plaintext.toString("utf8"),
      json: () => JSON.parse(plaintext.toString("utf8") || "{}"),
      deviceID: session.deviceID,
      userContext,
      sessionID,
      request: req,
    });
    const encrypted = encryptMessage(session, Buffer.from(JSON.stringify(result ?? null)));
    res.statusCode = 200;
    res.setHeader?.("content-type", "application/octet-stream");
    res.end(JSON.stringify(encrypted));
  }

  async resolveUser(token) {
    if (!token) return null;
    if (!this.userAuthenticator) return null;
    const user = await this.userAuthenticator(token);
    return user || null;
  }
}
