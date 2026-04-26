import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Readable, Writable } from "node:stream";

import { SecureHttpServerSDK } from "../../sdks/server/node/index.js";

function uint64BE(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(value), 0);
  return buffer;
}

function computeHMAC(key, payload) {
  return crypto.createHmac("sha256", key).update(payload).digest();
}

function gatePayload(method, path, timestamp, nonce, capability) {
  return Buffer.from([method.toUpperCase(), path, String(timestamp), nonce, capability].join("\n"), "utf8");
}

function randomNonce() {
  return crypto.randomBytes(16).toString("base64url");
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

function encryptMessage(encKey, macKey, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()]);
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    hmac: computeHMAC(macKey, Buffer.concat([nonce, ciphertext, uint64BE(timestamp)])).toString("base64"),
    timestamp,
  };
}

function decryptMessage(encKey, macKey, message) {
  const nonce = Buffer.from(message.nonce, "base64");
  const ciphertext = Buffer.from(message.ciphertext, "base64");
  const hmac = Buffer.from(message.hmac, "base64");
  const timestamp = Number(message.timestamp);
  const expected = computeHMAC(macKey, Buffer.concat([nonce, ciphertext, uint64BE(timestamp)]));
  assert.equal(crypto.timingSafeEqual(expected, hmac), true);
  const authTag = ciphertext.subarray(ciphertext.length - 16);
  const body = ciphertext.subarray(0, ciphertext.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function gateHeaders({ method, path, capability, gateSecretID, gateSecret }) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomNonce();
  const signature = computeHMAC(gateSecret, gatePayload(method, path, timestamp, nonce, capability)).toString("base64");
  return {
    "X-Gate-Key": gateSecretID,
    "X-Gate-Timestamp": String(timestamp),
    "X-Gate-Nonce": nonce,
    "X-Gate-Signature": signature,
    "X-Capability-Token": capability,
  };
}

test("Node server SDK completes handshake and encrypted request flow", async () => {
  const gateSecret = Buffer.from("gate-secret-1");
  const deviceSecret = Buffer.from("device-secret-1");
  const sdk = new SecureHttpServerSDK({
    handshakePath: "/handshake",
    requireDevice: true,
    requireUser: true,
    gateSecrets: [{ id: "gate-1", secret: gateSecret }],
    gateSecretStrings: { "gate-1": "base64:Z2F0ZS1zZWNyZXQtMQ==" },
    deviceSecrets: { "device-1": deviceSecret },
    deviceSecretStrings: { "device-1": "base64:ZGV2aWNlLXNlY3JldC0x" },
    capabilities: [
      {
        token: "cap-root",
        routes: [
          { path: "/handshake", methods: ["POST"] },
          { path: "/api/echo", methods: ["POST"] },
        ],
      },
    ],
    async userAuthenticator(token) {
      return token === "user-token-1" ? { id: "user-1", roles: ["admin"] } : null;
    },
  });

  const handler = sdk.createHTTPRequestHandler({
    secure: {
      "POST /api/echo": async ({ json, deviceID, userContext }) => ({
        ok: true,
        deviceID,
        userID: userContext?.id,
        payload: json(),
      }),
    },
  });

  try {
    const clientECDH = crypto.createECDH("prime256v1");
    clientECDH.generateKeys();
    const timestamp = Math.floor(Date.now() / 1000);
    const handshakePayload = Buffer.concat([clientECDH.getPublicKey(), uint64BE(timestamp)]);
    const handshakeRequest = {
      client_public_key: clientECDH.getPublicKey().toString("base64"),
      device_id: "device-1",
      device_signature: computeHMAC(deviceSecret, handshakePayload).toString("base64"),
      user_token: "user-token-1",
      timestamp,
    };

    const handshakeResponse = await dispatch(handler, {
      method: "POST",
      path: "/handshake",
      headers: {
        "content-type": "application/json",
        ...lowercaseKeys(
          gateHeaders({
            method: "POST",
            path: "/handshake",
            capability: "cap-root",
            gateSecretID: "gate-1",
            gateSecret,
          }),
        ),
      },
      body: JSON.stringify(handshakeRequest),
    });
    assert.equal(handshakeResponse.statusCode, 200);
    const handshakeBody = JSON.parse(handshakeResponse.body.toString("utf8"));
    const serverPublicKey = Buffer.from(handshakeBody.server_public_key, "base64");
    const sessionID = Buffer.from(handshakeBody.session_id, "base64").toString("utf8");
    const sharedSecret = clientECDH.computeSecret(serverPublicKey);
    const { encKey, macKey } = deriveKeys(sharedSecret);

    const encryptedRequest = encryptMessage(encKey, macKey, Buffer.from(JSON.stringify({ hello: "world" }), "utf8"));
    const apiResponse = await dispatch(handler, {
      method: "POST",
      path: "/api/echo",
      headers: {
        "content-type": "application/octet-stream",
        "x-session-id": sessionID,
        "x-user-token": "user-token-1",
        ...lowercaseKeys(
          gateHeaders({
            method: "POST",
            path: "/api/echo",
            capability: "cap-root",
            gateSecretID: "gate-1",
            gateSecret,
          }),
        ),
      },
      body: JSON.stringify(encryptedRequest),
    });
    assert.equal(apiResponse.statusCode, 200);
    const encryptedResponse = JSON.parse(apiResponse.body.toString("utf8"));
    const plaintext = decryptMessage(encKey, macKey, encryptedResponse);
    const payload = JSON.parse(plaintext.toString("utf8"));

    assert.equal(payload.ok, true);
    assert.equal(payload.deviceID, "device-1");
    assert.equal(payload.userID, "user-1");
    assert.deepEqual(payload.payload, { hello: "world" });

    const bootstrap = sdk.buildBootstrapConfig({
      baseURL: "https://api.example.com",
      deviceID: "device-1",
      userToken: "user-token-1",
      capabilityToken: "cap-root",
    });
    assert.equal(bootstrap.deviceID, "device-1");
    assert.equal(bootstrap.capabilityToken, "cap-root");
  } finally {
    // no-op
  }
});

function lowercaseKeys(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}

class MockResponse extends Writable {
  constructor() {
    super();
    this.headers = {};
    this.statusCode = 200;
    this.body = Buffer.alloc(0);
  }

  _write(chunk, _encoding, callback) {
    this.body = Buffer.concat([this.body, Buffer.from(chunk)]);
    callback();
  }

  setHeader(name, value) {
    this.headers[String(name).toLowerCase()] = value;
  }

  getHeader(name) {
    return this.headers[String(name).toLowerCase()];
  }

  end(chunk) {
    if (chunk) {
      this.body = Buffer.concat([this.body, Buffer.from(chunk)]);
    }
    super.end();
  }
}

async function dispatch(handler, { method, path, headers, body }) {
  const request = Readable.from(body ? [Buffer.from(body)] : []);
  request.method = method;
  request.url = path;
  request.headers = headers || {};
  request.socket = { remoteAddress: "127.0.0.1" };
  const response = new MockResponse();
  await handler(request, response);
  return response;
}
