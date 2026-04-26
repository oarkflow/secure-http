import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DEFAULT_GATE_HEADERS = {
    "secretID": "X-Gate-Key",
    "timestamp": "X-Gate-Timestamp",
    "nonce": "X-Gate-Nonce",
    "signature": "X-Gate-Signature",
    "capability": "X-Capability-Token",
}

DEFAULT_TRANSPORT_HEADERS = {
    "sessionID": "X-Session-ID",
    "userToken": "X-User-Token",
}

DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
DEFAULT_MESSAGE_TTL_MS = 5 * 60 * 1000
DEFAULT_CLOCK_SKEW_MS = 60 * 1000
CURVE = ec.SECP256R1()


def _b64decode(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return base64.b64decode(value)


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _uint64_be(value: int) -> bytes:
    return int(value).to_bytes(8, "big", signed=False)


def _derive_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=None,
        info=b"secure-communication-v1",
    )
    okm = hkdf.derive(shared_secret)
    return okm[:32], okm[32:64]


def _compute_hmac(key: bytes, payload: bytes) -> bytes:
    return hmac.new(key, payload, hashlib.sha256).digest()


def _normalize_path(raw_path: str) -> str:
    value = str(raw_path or "").strip()
    if not value:
        return "/"
    parsed = urlparse(value)
    path = parsed.path or value.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path or "/"


def _path_matches(pattern: str, path: str) -> bool:
    if not pattern:
        return False
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return pattern == path


def _normalize_origin(origin: str) -> str:
    value = str(origin or "").strip().lower().rstrip("/")
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".lower()
    return value


def _canonical_gate_payload(method: str, path: str, timestamp: str, nonce: str, capability: str) -> bytes:
    payload = "\n".join(
        [
            str(method or "").strip().upper(),
            _normalize_path(path),
            str(timestamp),
            str(nonce),
            str(capability),
        ]
    )
    return payload.encode("utf-8")


def _fingerprint_for_request(headers: Dict[str, str], client_ip: str) -> str:
    user_agent = str(headers.get("user-agent", "")).strip()
    client_ip = str(client_ip or "").strip()
    if not client_ip and not user_agent:
        return ""
    payload = f"{client_ip}|{user_agent}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class SecureSession:
    session_id: str
    enc_key: bytes
    mac_key: bytes
    expires_at_ms: int
    metadata: Dict[str, str] = field(default_factory=dict)

    def encrypt(self, plaintext: bytes) -> Dict[str, Any]:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.enc_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        timestamp = int(time.time())
        mac = _compute_hmac(self.mac_key, nonce + ciphertext + _uint64_be(timestamp))
        return {
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
            "hmac": _b64encode(mac),
            "timestamp": timestamp,
        }

    def decrypt(self, message: Dict[str, Any], message_ttl_ms: int) -> bytes:
        nonce = _b64decode(message.get("nonce", ""), "nonce")
        ciphertext = _b64decode(message.get("ciphertext", ""), "ciphertext")
        provided_mac = _b64decode(message.get("hmac", ""), "hmac")
        timestamp = int(message.get("timestamp", 0))
        drift = int(time.time() * 1000) - timestamp * 1000
        if abs(drift) > message_ttl_ms:
            raise ValueError("message expired")
        expected_mac = _compute_hmac(self.mac_key, nonce + ciphertext + _uint64_be(timestamp))
        if not hmac.compare_digest(expected_mac, provided_mac):
            raise ValueError("HMAC verification failed")
        aesgcm = AESGCM(self.enc_key)
        return aesgcm.decrypt(nonce, ciphertext, None)


class CapabilityMatcher:
    def __init__(self, definition: Dict[str, Any]):
        self.token = str(definition.get("token", "")).strip()
        self.metadata = dict(definition.get("metadata") or {})
        self.methods = {
            str(method or "").strip().upper()
            for method in definition.get("methods", [])
            if str(method or "").strip()
        }
        self.paths = [
            str(path or "").strip()
            for path in definition.get("paths", [])
            if str(path or "").strip()
        ]
        self.routes = []
        for route in definition.get("routes", []):
            path = str((route or {}).get("path", "")).strip()
            if not path:
                continue
            methods = {
                str(method or "").strip().upper()
                for method in (route or {}).get("methods", [])
                if str(method or "").strip()
            }
            self.routes.append({"path": path, "methods": methods})

    def allows(self, method: str, path: str) -> bool:
        normalized_method = str(method or "").strip().upper()
        normalized_path = _normalize_path(path)
        if self.routes:
            return any(
                _path_matches(route["path"], normalized_path)
                and (not route["methods"] or normalized_method in route["methods"])
                for route in self.routes
            )
        if self.methods and normalized_method not in self.methods:
            return False
        if not self.paths:
            return True
        return any(_path_matches(pattern, normalized_path) for pattern in self.paths)


class SecureHttpServerSDK:
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        *,
        user_authenticator: Optional[Callable[[str], Any]] = None,
    ):
        config = config or {}
        self.config = config
        self.handshake_path = _normalize_path(config.get("handshakePath", "/handshake"))
        self.transport_headers = {**DEFAULT_TRANSPORT_HEADERS, **(config.get("transportHeaders") or {})}
        self.gate_headers = {**DEFAULT_GATE_HEADERS, **(config.get("gateHeaders") or {})}
        self.require_device = config.get("requireDevice", True) is not False
        self.require_user = bool(config.get("requireUser"))
        self.session_ttl_ms = int(config.get("sessionTTLms", DEFAULT_SESSION_TTL_MS))
        self.message_ttl_ms = int(config.get("messageTTLms", DEFAULT_MESSAGE_TTL_MS))
        self.max_clock_skew_ms = int(config.get("maxClockSkewMs", DEFAULT_CLOCK_SKEW_MS))
        self.strict_origin = bool(config.get("strictOrigin"))
        self.allowed_origins = {
            _normalize_origin(origin)
            for origin in config.get("allowedOrigins", [])
            if _normalize_origin(origin)
        }
        self.device_secrets = {
            str(key): bytes(value) if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
            for key, value in (config.get("deviceSecrets") or {}).items()
        }
        self.capabilities = {
            matcher.token: matcher
            for matcher in (CapabilityMatcher(item) for item in config.get("capabilities", []))
            if matcher.token
        }
        self.gate_secrets = []
        for secret in config.get("gateSecrets", []):
            secret_id = str((secret or {}).get("id", "")).strip()
            raw = (secret or {}).get("secret", b"")
            secret_bytes = bytes(raw) if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
            if secret_id and secret_bytes:
                self.gate_secrets.append(
                    {
                        "id": secret_id,
                        "secret": secret_bytes,
                        "notBefore": self._parse_epoch_ms((secret or {}).get("notBefore"), float("-inf")),
                        "expiresAt": self._parse_epoch_ms((secret or {}).get("expiresAt"), float("inf")),
                    }
                )
        self.sessions: Dict[str, SecureSession] = {}
        self.user_authenticator = user_authenticator or config.get("userAuthenticator") or (lambda token: None)
        self._server_private_key = ec.generate_private_key(CURVE)

    @classmethod
    def from_manifest(
        cls,
        manifest: Dict[str, Any],
        *,
        gate_secret_resolver: Callable[[str], bytes],
        device_secret_resolver: Callable[[str], bytes],
        user_authenticator: Optional[Callable[[str], Any]] = None,
    ) -> "SecureHttpServerSDK":
        gate_secrets = []
        for secret in manifest.get("gate", {}).get("secrets", []):
            secret_id = str((secret or {}).get("id", "")).strip()
            if not secret_id:
                continue
            gate_secrets.append(
                {
                    "id": secret_id,
                    "secret": gate_secret_resolver(secret_id),
                    "notBefore": (secret or {}).get("notBefore"),
                    "expiresAt": (secret or {}).get("expiresAt"),
                }
            )
        config = {
            "handshakePath": manifest.get("handshakePath", "/handshake"),
            "bootstrapPath": manifest.get("bootstrapPath", "/auth/bootstrap"),
            "requireDevice": manifest.get("auth", {}).get("requireDevice", True),
            "requireUser": manifest.get("auth", {}).get("requireUser", False),
            "transportHeaders": manifest.get("headers", {}),
            "gateHeaders": manifest.get("headers", {}).get("gate", {}),
            "allowedOrigins": manifest.get("gate", {}).get("allowedOrigins", []),
            "strictOrigin": manifest.get("gate", {}).get("strictOrigin", False),
            "capabilities": manifest.get("capabilities", []),
            "gateSecrets": gate_secrets,
            "deviceSecrets": ManifestDeviceSecrets(device_secret_resolver),
        }
        sdk = cls(config, user_authenticator=user_authenticator)
        sdk._manifest = manifest
        return sdk

    def verify_gate(self, method: str, path: str, headers: Dict[str, str]) -> Dict[str, Any]:
        headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
        origin = _normalize_origin(headers.get("origin") or headers.get("referer") or "")
        if (self.allowed_origins or self.strict_origin) and (not origin or origin not in self.allowed_origins):
            raise ValueError("origin not allowed")

        secret_id = headers.get(self.gate_headers["secretID"].lower(), "").strip()
        timestamp = headers.get(self.gate_headers["timestamp"].lower(), "").strip()
        nonce = headers.get(self.gate_headers["nonce"].lower(), "").strip()
        signature = headers.get(self.gate_headers["signature"].lower(), "").strip()
        capability_token = headers.get(self.gate_headers["capability"].lower(), "").strip()
        if not all([secret_id, timestamp, nonce, signature, capability_token]):
            raise ValueError("missing gate headers")

        ts = int(timestamp)
        drift = int(time.time() * 1000) - ts * 1000
        if abs(drift) > self.max_clock_skew_ms:
            raise ValueError("timestamp skew")

        capability = self.capabilities.get(capability_token)
        if not capability or not capability.allows(method, path):
            raise ValueError("capability denied")

        now_ms = int(time.time() * 1000)
        secret = next(
            (
                item
                for item in self.gate_secrets
                if item["id"] == secret_id and item["notBefore"] <= now_ms <= item["expiresAt"]
            ),
            None,
        )
        if not secret:
            raise ValueError("unknown gate secret")

        expected = _compute_hmac(
            secret["secret"],
            _canonical_gate_payload(method, path, timestamp, nonce, capability_token),
        )
        if not hmac.compare_digest(expected, base64.b64decode(signature)):
            raise ValueError("invalid gate signature")
        return {"token": capability_token, "metadata": dict(capability.metadata)}

    def handle_handshake(
        self,
        request: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
        client_ip: str = "",
    ) -> Dict[str, Any]:
        body = request or {}
        client_public_key = _b64decode(body.get("client_public_key", ""), "client_public_key")
        device_signature = _b64decode(body.get("device_signature", ""), "device_signature")
        device_id = str(body.get("device_id", "")).strip()
        user_token = str(body.get("user_token", "")).strip()
        timestamp = int(body.get("timestamp", 0))
        drift = int(time.time() * 1000) - timestamp * 1000
        if timestamp <= 0 or abs(drift) > self.max_clock_skew_ms:
            raise ValueError("timestamp skew")

        if self.require_device:
            device_secret = self.device_secrets.get(device_id)
            if not device_secret:
                raise ValueError("unknown device")
            payload = client_public_key + _uint64_be(timestamp)
            expected = _compute_hmac(device_secret, payload)
            if not hmac.compare_digest(expected, device_signature):
                raise ValueError("invalid device signature")

        user_context = None
        if user_token:
            user_context = self.user_authenticator(user_token)
            if not user_context:
                raise ValueError("invalid user token")
        elif self.require_user:
            raise ValueError("missing user token")

        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, client_public_key)
        shared_secret = self._server_private_key.exchange(ec.ECDH(), peer_public_key)
        enc_key, mac_key = _derive_keys(shared_secret)
        session_id = _b64encode(secrets.token_bytes(24))
        metadata: Dict[str, str] = {}
        if device_id:
            metadata["device_id"] = device_id
        if user_context and getattr(user_context, "get", None):
            user_id = user_context.get("id")
            if user_id:
                metadata["user_id"] = str(user_id)
            roles = user_context.get("roles")
            if isinstance(roles, Iterable) and not isinstance(roles, (str, bytes)):
                joined = ",".join(str(role) for role in roles if str(role))
                if joined:
                    metadata["user_roles"] = joined
            user_metadata = user_context.get("metadata")
            if isinstance(user_metadata, dict):
                for key, value in user_metadata.items():
                    metadata[f"user_meta_{key}"] = str(value)
        fingerprint = _fingerprint_for_request(headers or {}, client_ip)
        if fingerprint:
            metadata["session_fp"] = fingerprint

        expires_at_ms = int(time.time() * 1000) + self.session_ttl_ms
        self.sessions[session_id] = SecureSession(
            session_id=session_id,
            enc_key=enc_key,
            mac_key=mac_key,
            expires_at_ms=expires_at_ms,
            metadata=metadata,
        )
        server_public_key = self._server_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return {
            "server_public_key": _b64encode(server_public_key),
            "session_id": _b64encode(session_id.encode("utf-8")),
            "device_id": device_id,
            "expires_at": expires_at_ms // 1000,
            "timestamp": int(time.time()),
        }

    def decrypt_request(
        self,
        message: Dict[str, Any],
        *,
        headers: Dict[str, str],
        client_ip: str = "",
    ) -> Dict[str, Any]:
        session, user_context = self._resolve_session(headers, client_ip)
        plaintext = session.decrypt(message, self.message_ttl_ms)
        payload = json.loads(plaintext.decode("utf-8")) if plaintext else None
        return {
            "session": session,
            "sessionID": session.session_id,
            "deviceID": session.metadata.get("device_id", ""),
            "userContext": user_context,
            "plaintext": plaintext,
            "json": payload,
        }

    def encrypt_response(self, session_id: str, payload: Any) -> Optional[Dict[str, Any]]:
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError("invalid session")
        if payload is None:
            return None
        if isinstance(payload, bytes):
            plaintext = payload
        elif isinstance(payload, str):
            plaintext = payload.encode("utf-8")
        else:
            plaintext = json.dumps(payload).encode("utf-8")
        if not plaintext:
            return None
        return session.encrypt(plaintext)

    def build_login_response(
        self,
        *,
        user_id: str,
        base_url: str = "",
        bootstrap_path: str = "/auth/bootstrap",
        handshake_path: Optional[str] = None,
        cookie_auth: bool = True,
        csrf_cookie_name: str = "securehttp_csrf",
        csrf_header_name: str = "X-CSRF-Token",
        access_token: str = "",
        refresh_token: str = "",
        csrf_token: str = "",
    ) -> Dict[str, Any]:
        response = {
            "status": 200,
            "success": True,
            "userID": user_id,
            "user_id": user_id,
            "bootstrapPath": _normalize_path(bootstrap_path),
            "handshakePath": _normalize_path(handshake_path or self.handshake_path),
            "baseURL": base_url,
            "cookieAuth": bool(cookie_auth),
            "csrfCookieName": csrf_cookie_name,
            "csrfHeaderName": csrf_header_name,
        }
        if not cookie_auth:
            response["accessToken"] = access_token
            response["refreshToken"] = refresh_token
            response["csrfToken"] = csrf_token
        return response

    def build_bootstrap_config(
        self,
        *,
        base_url: str = "",
        device_id: str,
        capability_token: str,
        user_token: str = "",
        handshake_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        gate_secrets = []
        gate_strings = self.config.get("gateSecretStrings") or {}
        for secret in self.gate_secrets:
            exported = str(gate_strings.get(secret["id"], "")).strip()
            if exported:
                gate_secrets.append({"id": secret["id"], "secret": exported})
        device_secret = str((self.config.get("deviceSecretStrings") or {}).get(device_id, "")).strip()
        if not device_secret:
            raise ValueError(f"device secret not found for {device_id}")
        if not capability_token:
            raise ValueError("capabilityToken is required")
        if not gate_secrets:
            raise ValueError("at least one gate secret must be exported")
        return {
            "baseURL": base_url,
            "deviceID": device_id,
            "deviceSecret": device_secret,
            "userToken": user_token,
            "handshakePath": _normalize_path(handshake_path or self.handshake_path),
            "capabilityToken": capability_token,
            "gateSecrets": gate_secrets,
        }

    def _resolve_session(self, headers: Dict[str, str], client_ip: str) -> tuple[SecureSession, Optional[Dict[str, Any]]]:
        normalized_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
        session_id = normalized_headers.get(self.transport_headers["sessionID"].lower(), "").strip()
        if not session_id:
            raise ValueError("missing session")
        session = self.sessions.get(session_id)
        if not session or int(time.time() * 1000) > session.expires_at_ms:
            self.sessions.pop(session_id, None)
            raise ValueError("invalid session")
        fingerprint = _fingerprint_for_request(normalized_headers, client_ip)
        if session.metadata.get("session_fp") and session.metadata.get("session_fp") != fingerprint:
            self.sessions.pop(session_id, None)
            raise ValueError("fingerprint mismatch")

        user_context = None
        user_token = normalized_headers.get(self.transport_headers["userToken"].lower(), "").strip()
        if user_token:
            user_context = self.user_authenticator(user_token)
            if not user_context:
                raise ValueError("invalid user token")
        elif self.require_user and not session.metadata.get("user_id"):
            raise ValueError("missing user token")
        elif session.metadata.get("user_id"):
            user_context = {
                "id": session.metadata.get("user_id", ""),
                "roles": session.metadata.get("user_roles", "").split(",") if session.metadata.get("user_roles") else [],
                "metadata": {
                    key[len("user_meta_") :]: value
                    for key, value in session.metadata.items()
                    if key.startswith("user_meta_")
                },
            }
        return session, user_context

    @staticmethod
    def _parse_epoch_ms(value: Any, default: float) -> float:
        if not value:
            return default
        if isinstance(value, (int, float)):
            return float(value)
        try:
            if str(value).isdigit():
                return float(value)
            return time.mktime(time.strptime(str(value), "%Y-%m-%dT%H:%M:%S%z")) * 1000
        except ValueError:
            try:
                return time.mktime(time.strptime(str(value), "%Y-%m-%dT%H:%M:%S")) * 1000
            except ValueError:
                return default


class ManifestDeviceSecrets(dict):
    def __init__(self, resolver: Callable[[str], bytes]):
        super().__init__()
        self._resolver = resolver

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self._resolver(key)
        except Exception:
            return default
