package dev.oarkflow.securehttp.server;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SecureHttpServerSDK {
    private static final Map<String, String> DEFAULT_GATE_HEADERS = Map.of(
        "secretID", "X-Gate-Key",
        "timestamp", "X-Gate-Timestamp",
        "nonce", "X-Gate-Nonce",
        "signature", "X-Gate-Signature",
        "capability", "X-Capability-Token"
    );

    private static final Map<String, String> DEFAULT_TRANSPORT_HEADERS = Map.of(
        "sessionID", "X-Session-ID",
        "userToken", "X-User-Token"
    );

    private static final long DEFAULT_SESSION_TTL_MS = 30L * 60L * 1000L;
    private static final long DEFAULT_MESSAGE_TTL_MS = 5L * 60L * 1000L;
    private static final long DEFAULT_CLOCK_SKEW_MS = 60L * 1000L;
    private static final String HKDF_INFO = "secure-communication-v1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, Object> config;
    private final String handshakePath;
    private final Map<String, String> transportHeaders;
    private final Map<String, String> gateHeaders;
    private final boolean requireDevice;
    private final boolean requireUser;
    private final long sessionTTLms;
    private final long messageTTLms;
    private final long maxClockSkewMs;
    private final boolean strictOrigin;
    private final Set<String> allowedOrigins;
    private final Function<String, byte[]> deviceSecretResolver;
    private final Map<String, CapabilityMatcher> capabilities;
    private final List<GateSecret> gateSecrets;
    private final Map<String, SecureSession> sessions = new ConcurrentHashMap<>();
    private final Function<String, Map<String, Object>> userAuthenticator;
    private final KeyPair serverKeyPair;

    public SecureHttpServerSDK(Map<String, Object> config) {
        this(config, null, null);
    }

    public SecureHttpServerSDK(
        Map<String, Object> config,
        Function<String, Map<String, Object>> userAuthenticator,
        Function<String, byte[]> deviceSecretResolver
    ) {
        this.config = config == null ? Map.of() : new LinkedHashMap<>(config);
        this.handshakePath = normalizePath(asString(this.config.get("handshakePath"), "/handshake"));
        this.transportHeaders = mergeHeaders(DEFAULT_TRANSPORT_HEADERS, asMap(this.config.get("transportHeaders")));
        this.gateHeaders = mergeHeaders(DEFAULT_GATE_HEADERS, asMap(this.config.get("gateHeaders")));
        this.requireDevice = !Boolean.FALSE.equals(this.config.get("requireDevice"));
        this.requireUser = Boolean.TRUE.equals(this.config.get("requireUser"));
        this.sessionTTLms = asLong(this.config.get("sessionTTLms"), DEFAULT_SESSION_TTL_MS);
        this.messageTTLms = asLong(this.config.get("messageTTLms"), DEFAULT_MESSAGE_TTL_MS);
        this.maxClockSkewMs = asLong(this.config.get("maxClockSkewMs"), DEFAULT_CLOCK_SKEW_MS);
        this.strictOrigin = Boolean.TRUE.equals(this.config.get("strictOrigin"));
        this.allowedOrigins = ConcurrentHashMap.newKeySet();
        for (Object item : asList(this.config.get("allowedOrigins"))) {
            String origin = normalizeOrigin(Objects.toString(item, ""));
            if (!origin.isBlank()) {
                this.allowedOrigins.add(origin);
            }
        }
        this.deviceSecretResolver = deviceSecretResolver != null ? deviceSecretResolver : buildDeviceResolver(this.config.get("deviceSecrets"));
        this.capabilities = new LinkedHashMap<>();
        for (Object item : asList(this.config.get("capabilities"))) {
            CapabilityMatcher matcher = new CapabilityMatcher(asMap(item));
            if (!matcher.token.isBlank()) {
                this.capabilities.put(matcher.token, matcher);
            }
        }
        this.gateSecrets = new ArrayList<>();
        for (Object item : asList(this.config.get("gateSecrets"))) {
            Map<String, Object> secret = asMap(item);
            String id = asString(secret.get("id"), "").trim();
            byte[] material = bytesValue(secret.get("secret"));
            if (!id.isBlank() && material.length > 0) {
                this.gateSecrets.add(new GateSecret(
                    id,
                    material,
                    parseEpochMs(secret.get("notBefore"), Long.MIN_VALUE),
                    parseEpochMs(secret.get("expiresAt"), Long.MAX_VALUE)
                ));
            }
        }
        this.userAuthenticator = userAuthenticator != null ? userAuthenticator : token -> null;
        this.serverKeyPair = generateServerKeyPair();
    }

    public static SecureHttpServerSDK fromManifest(
        Map<String, Object> manifest,
        Function<String, byte[]> gateSecretResolver,
        Function<String, byte[]> deviceSecretResolver,
        Function<String, Map<String, Object>> userAuthenticator
    ) {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("handshakePath", asString(manifest.get("handshakePath"), "/handshake"));
        config.put("requireDevice", asMap(manifest.get("auth")).getOrDefault("requireDevice", Boolean.TRUE));
        config.put("requireUser", asMap(manifest.get("auth")).getOrDefault("requireUser", Boolean.FALSE));
        config.put("transportHeaders", asMap(manifest.get("headers")));
        config.put("gateHeaders", asMap(asMap(manifest.get("headers")).get("gate")));
        config.put("allowedOrigins", asList(asMap(manifest.get("gate")).get("allowedOrigins")));
        config.put("strictOrigin", asMap(manifest.get("gate")).getOrDefault("strictOrigin", Boolean.FALSE));
        config.put("capabilities", asList(manifest.get("capabilities")));

        List<Map<String, Object>> gateSecrets = new ArrayList<>();
        for (Object item : asList(asMap(manifest.get("gate")).get("secrets"))) {
            Map<String, Object> secret = asMap(item);
            String id = asString(secret.get("id"), "");
            if (!id.isBlank()) {
                Map<String, Object> exported = new LinkedHashMap<>();
                exported.put("id", id);
                exported.put("secret", gateSecretResolver.apply(id));
                exported.put("notBefore", secret.get("notBefore"));
                exported.put("expiresAt", secret.get("expiresAt"));
                gateSecrets.add(exported);
            }
        }
        config.put("gateSecrets", gateSecrets);
        return new SecureHttpServerSDK(config, userAuthenticator, deviceSecretResolver);
    }

    public Map<String, Object> verifyGate(String method, String path, Map<String, String> headers) {
        Map<String, String> normalizedHeaders = lowercase(headers);
        String origin = normalizeOrigin(normalizedHeaders.getOrDefault("origin", normalizedHeaders.getOrDefault("referer", "")));
        if ((!allowedOrigins.isEmpty() || strictOrigin) && (origin.isBlank() || !allowedOrigins.contains(origin))) {
            throw new IllegalArgumentException("origin not allowed");
        }

        String secretID = normalizedHeaders.getOrDefault(gateHeaders.get("secretID").toLowerCase(Locale.ROOT), "").trim();
        String timestamp = normalizedHeaders.getOrDefault(gateHeaders.get("timestamp").toLowerCase(Locale.ROOT), "").trim();
        String nonce = normalizedHeaders.getOrDefault(gateHeaders.get("nonce").toLowerCase(Locale.ROOT), "").trim();
        String signature = normalizedHeaders.getOrDefault(gateHeaders.get("signature").toLowerCase(Locale.ROOT), "").trim();
        String capabilityToken = normalizedHeaders.getOrDefault(gateHeaders.get("capability").toLowerCase(Locale.ROOT), "").trim();
        if (secretID.isBlank() || timestamp.isBlank() || nonce.isBlank() || signature.isBlank() || capabilityToken.isBlank()) {
            throw new IllegalArgumentException("missing gate headers");
        }

        long ts = Long.parseLong(timestamp);
        long drift = System.currentTimeMillis() - ts * 1000L;
        if (Math.abs(drift) > maxClockSkewMs) {
            throw new IllegalArgumentException("timestamp skew");
        }

        CapabilityMatcher capability = capabilities.get(capabilityToken);
        if (capability == null || !capability.allows(method, path)) {
            throw new IllegalArgumentException("capability denied");
        }

        long now = System.currentTimeMillis();
        GateSecret gateSecret = null;
        for (GateSecret item : gateSecrets) {
            if (item.id.equals(secretID) && item.notBeforeMs <= now && now <= item.expiresAtMs) {
                gateSecret = item;
                break;
            }
        }
        if (gateSecret == null) {
            throw new IllegalArgumentException("unknown gate secret");
        }

        byte[] expected = computeHMAC(gateSecret.secret, canonicalGatePayload(method, path, timestamp, nonce, capabilityToken));
        byte[] provided = Base64.getDecoder().decode(signature);
        if (!MessageDigest.isEqual(expected, provided)) {
            throw new IllegalArgumentException("invalid gate signature");
        }

        return Map.of(
            "token", capabilityToken,
            "metadata", new LinkedHashMap<>(capability.metadata)
        );
    }

    public Map<String, Object> handleHandshake(Map<String, Object> request, Map<String, String> headers, String clientIP) {
        byte[] clientPublicKey = decodeBase64(asString(request.get("client_public_key"), ""), "client_public_key");
        byte[] deviceSignature = decodeBase64(asString(request.get("device_signature"), ""), "device_signature");
        String deviceID = asString(request.get("device_id"), "").trim();
        String userToken = asString(request.get("user_token"), "").trim();
        long timestamp = asLong(request.get("timestamp"), 0L);
        long drift = System.currentTimeMillis() - timestamp * 1000L;
        if (timestamp <= 0L || Math.abs(drift) > maxClockSkewMs) {
            throw new IllegalArgumentException("timestamp skew");
        }

        if (requireDevice) {
            byte[] deviceSecret = deviceSecretResolver.apply(deviceID);
            if (deviceSecret == null || deviceSecret.length == 0) {
                throw new IllegalArgumentException("unknown device");
            }
            byte[] payload = concat(clientPublicKey, uint64BE(timestamp));
            byte[] expected = computeHMAC(deviceSecret, payload);
            if (!MessageDigest.isEqual(expected, deviceSignature)) {
                throw new IllegalArgumentException("invalid device signature");
            }
        }

        Map<String, Object> userContext = null;
        if (!userToken.isBlank()) {
            userContext = userAuthenticator.apply(userToken);
            if (userContext == null) {
                throw new IllegalArgumentException("invalid user token");
            }
        } else if (requireUser) {
            throw new IllegalArgumentException("missing user token");
        }

        byte[] sharedSecret = deriveSharedSecret(serverKeyPair.getPrivate(), clientPublicKey);
        byte[][] keys = deriveKeys(sharedSecret);
        String sessionID = Base64.getEncoder().encodeToString(randomBytes(24));
        Map<String, String> metadata = new LinkedHashMap<>();
        if (!deviceID.isBlank()) {
            metadata.put("device_id", deviceID);
        }
        if (userContext != null) {
            Object userID = userContext.get("id");
            if (userID != null) {
                metadata.put("user_id", userID.toString());
            }
            Object roles = userContext.get("roles");
            if (roles instanceof List<?> roleList && !roleList.isEmpty()) {
                List<String> mapped = new ArrayList<>();
                for (Object role : roleList) {
                    if (role != null) {
                        mapped.add(role.toString());
                    }
                }
                if (!mapped.isEmpty()) {
                    metadata.put("user_roles", String.join(",", mapped));
                }
            }
            Object userMetadata = userContext.get("metadata");
            if (userMetadata instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null) {
                        metadata.put("user_meta_" + entry.getKey(), entry.getValue().toString());
                    }
                }
            }
        }
        String fingerprint = fingerprintForRequest(lowercase(headers), clientIP);
        if (!fingerprint.isBlank()) {
            metadata.put("session_fp", fingerprint);
        }

        long expiresAtMs = System.currentTimeMillis() + sessionTTLms;
        sessions.put(sessionID, new SecureSession(sessionID, keys[0], keys[1], expiresAtMs, metadata));

        return Map.of(
            "server_public_key", Base64.getEncoder().encodeToString(extractPublicKeyRaw(serverKeyPair.getPublic())),
            "session_id", Base64.getEncoder().encodeToString(sessionID.getBytes(StandardCharsets.UTF_8)),
            "device_id", deviceID,
            "expires_at", expiresAtMs / 1000L,
            "timestamp", Instant.now().getEpochSecond()
        );
    }

    public DecryptedRequest decryptRequest(Map<String, Object> message, Map<String, String> headers, String clientIP) {
        ResolvedSession resolved = resolveSession(headers, clientIP);
        byte[] plaintext = resolved.session.decrypt(message, messageTTLms);
        return new DecryptedRequest(
            resolved.session,
            resolved.session.sessionID,
            resolved.session.metadata.getOrDefault("device_id", ""),
            resolved.userContext,
            plaintext
        );
    }

    public Map<String, Object> encryptResponse(String sessionID, Object payload) {
        SecureSession session = sessions.get(sessionID);
        if (session == null) {
            throw new IllegalArgumentException("invalid session");
        }
        if (payload == null) {
            return null;
        }
        byte[] plaintext;
        if (payload instanceof byte[] bytes) {
            plaintext = bytes;
        } else {
            plaintext = payload.toString().getBytes(StandardCharsets.UTF_8);
        }
        if (plaintext.length == 0) {
            return null;
        }
        return session.encrypt(plaintext);
    }

    public Map<String, Object> buildLoginResponse(
        String userID,
        String baseURL,
        String bootstrapPath,
        String handshakePath,
        boolean cookieAuth,
        String csrfCookieName,
        String csrfHeaderName,
        String accessToken,
        String refreshToken,
        String csrfToken
    ) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", 200);
        response.put("success", true);
        response.put("userID", userID);
        response.put("user_id", userID);
        response.put("bootstrapPath", normalizePath(bootstrapPath == null ? "/auth/bootstrap" : bootstrapPath));
        response.put("handshakePath", normalizePath(handshakePath == null ? this.handshakePath : handshakePath));
        response.put("baseURL", baseURL == null ? "" : baseURL);
        response.put("cookieAuth", cookieAuth);
        response.put("csrfCookieName", csrfCookieName == null ? "securehttp_csrf" : csrfCookieName);
        response.put("csrfHeaderName", csrfHeaderName == null ? "X-CSRF-Token" : csrfHeaderName);
        if (!cookieAuth) {
            response.put("accessToken", accessToken == null ? "" : accessToken);
            response.put("refreshToken", refreshToken == null ? "" : refreshToken);
            response.put("csrfToken", csrfToken == null ? "" : csrfToken);
        }
        return response;
    }

    public Map<String, Object> buildBootstrapConfig(
        String baseURL,
        String deviceID,
        String userToken,
        String capabilityToken,
        String handshakePath
    ) {
        List<Map<String, String>> exportedGateSecrets = new ArrayList<>();
        Map<String, Object> gateSecretStrings = asMap(config.get("gateSecretStrings"));
        for (GateSecret gateSecret : gateSecrets) {
            String exported = asString(gateSecretStrings.get(gateSecret.id), "").trim();
            if (!exported.isBlank()) {
                exportedGateSecrets.add(Map.of("id", gateSecret.id, "secret", exported));
            }
        }
        String deviceSecret = asString(asMap(config.get("deviceSecretStrings")).get(deviceID), "").trim();
        if (deviceSecret.isBlank()) {
            throw new IllegalArgumentException("device secret not found for " + deviceID);
        }
        if (capabilityToken == null || capabilityToken.isBlank()) {
            throw new IllegalArgumentException("capabilityToken is required");
        }
        if (exportedGateSecrets.isEmpty()) {
            throw new IllegalArgumentException("at least one gate secret must be exported");
        }
        return Map.of(
            "baseURL", baseURL == null ? "" : baseURL,
            "deviceID", deviceID,
            "deviceSecret", deviceSecret,
            "userToken", userToken == null ? "" : userToken,
            "handshakePath", normalizePath(handshakePath == null ? this.handshakePath : handshakePath),
            "capabilityToken", capabilityToken,
            "gateSecrets", exportedGateSecrets
        );
    }

    public static final class DecryptedRequest {
        public final SecureSession session;
        public final String sessionID;
        public final String deviceID;
        public final Map<String, Object> userContext;
        public final byte[] plaintext;

        public DecryptedRequest(SecureSession session, String sessionID, String deviceID, Map<String, Object> userContext, byte[] plaintext) {
            this.session = session;
            this.sessionID = sessionID;
            this.deviceID = deviceID;
            this.userContext = userContext;
            this.plaintext = plaintext;
        }

        public String bodyAsString() {
            return new String(plaintext, StandardCharsets.UTF_8);
        }
    }

    public static final class SecureSession {
        public final String sessionID;
        public final byte[] encKey;
        public final byte[] macKey;
        public final long expiresAtMs;
        public final Map<String, String> metadata;

        private SecureSession(String sessionID, byte[] encKey, byte[] macKey, long expiresAtMs, Map<String, String> metadata) {
            this.sessionID = sessionID;
            this.encKey = encKey.clone();
            this.macKey = macKey.clone();
            this.expiresAtMs = expiresAtMs;
            this.metadata = new LinkedHashMap<>(metadata);
        }

        public Map<String, Object> encrypt(byte[] plaintext) {
            try {
                byte[] nonce = randomBytes(12);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new GCMParameterSpec(128, nonce));
                byte[] ciphertext = cipher.doFinal(plaintext);
                long timestamp = Instant.now().getEpochSecond();
                byte[] hmac = computeHMAC(macKey, concat(nonce, ciphertext, uint64BE(timestamp)));
                return Map.of(
                    "nonce", Base64.getEncoder().encodeToString(nonce),
                    "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
                    "hmac", Base64.getEncoder().encodeToString(hmac),
                    "timestamp", timestamp
                );
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("encryption failed", ex);
            }
        }

        public byte[] decrypt(Map<String, Object> message, long messageTTLms) {
            try {
                byte[] nonce = decodeBase64(asString(message.get("nonce"), ""), "nonce");
                byte[] ciphertext = decodeBase64(asString(message.get("ciphertext"), ""), "ciphertext");
                byte[] providedHMAC = decodeBase64(asString(message.get("hmac"), ""), "hmac");
                long timestamp = asLong(message.get("timestamp"), 0L);
                long drift = System.currentTimeMillis() - timestamp * 1000L;
                if (Math.abs(drift) > messageTTLms) {
                    throw new IllegalArgumentException("message expired");
                }
                byte[] expectedHMAC = computeHMAC(macKey, concat(nonce, ciphertext, uint64BE(timestamp)));
                if (!MessageDigest.isEqual(expectedHMAC, providedHMAC)) {
                    throw new IllegalArgumentException("HMAC verification failed");
                }
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new GCMParameterSpec(128, nonce));
                return cipher.doFinal(ciphertext);
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException("decryption failed", ex);
            }
        }
    }

    private ResolvedSession resolveSession(Map<String, String> headers, String clientIP) {
        Map<String, String> normalizedHeaders = lowercase(headers);
        String sessionID = normalizedHeaders.getOrDefault(transportHeaders.get("sessionID").toLowerCase(Locale.ROOT), "").trim();
        if (sessionID.isBlank()) {
            throw new IllegalArgumentException("missing session");
        }
        SecureSession session = sessions.get(sessionID);
        if (session == null || System.currentTimeMillis() > session.expiresAtMs) {
            sessions.remove(sessionID);
            throw new IllegalArgumentException("invalid session");
        }
        String fingerprint = fingerprintForRequest(normalizedHeaders, clientIP);
        if (session.metadata.containsKey("session_fp") && !Objects.equals(session.metadata.get("session_fp"), fingerprint)) {
            sessions.remove(sessionID);
            throw new IllegalArgumentException("fingerprint mismatch");
        }

        Map<String, Object> userContext = null;
        String userToken = normalizedHeaders.getOrDefault(transportHeaders.get("userToken").toLowerCase(Locale.ROOT), "").trim();
        if (!userToken.isBlank()) {
            userContext = userAuthenticator.apply(userToken);
            if (userContext == null) {
                throw new IllegalArgumentException("invalid user token");
            }
        } else if (requireUser && !session.metadata.containsKey("user_id")) {
            throw new IllegalArgumentException("missing user token");
        } else if (session.metadata.containsKey("user_id")) {
            userContext = new LinkedHashMap<>();
            userContext.put("id", session.metadata.get("user_id"));
            String roles = session.metadata.getOrDefault("user_roles", "");
            userContext.put("roles", roles.isBlank() ? List.of() : List.of(roles.split(",")));
            Map<String, String> metadata = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : session.metadata.entrySet()) {
                if (entry.getKey().startsWith("user_meta_")) {
                    metadata.put(entry.getKey().substring("user_meta_".length()), entry.getValue());
                }
            }
            userContext.put("metadata", metadata);
        }
        return new ResolvedSession(session, userContext);
    }

    private static byte[] deriveSharedSecret(PrivateKey privateKey, byte[] clientPublicKeyRaw) {
        try {
            PublicKey clientPublicKey = publicKeyFromRawPoint(clientPublicKeyRaw);
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(privateKey);
            agreement.doPhase(clientPublicKey, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("key derivation failed", ex);
        }
    }

    private static byte[][] deriveKeys(byte[] sharedSecret) {
        byte[] okm = hkdfSha512(sharedSecret, HKDF_INFO.getBytes(StandardCharsets.UTF_8), 64);
        return new byte[][] {
            slice(okm, 0, 32),
            slice(okm, 32, 64)
        };
    }

    private static byte[] hkdfSha512(byte[] ikm, byte[] info, int length) {
        try {
            byte[] prk = computeHMAC(new byte[0], ikm);
            byte[] result = new byte[length];
            byte[] previous = new byte[0];
            int offset = 0;
            int counter = 1;
            while (offset < length) {
                Mac mac = Mac.getInstance("HmacSHA512");
                mac.init(new SecretKeySpec(prk, "HmacSHA512"));
                mac.update(previous);
                mac.update(info);
                mac.update((byte) counter);
                previous = mac.doFinal();
                int bytesToCopy = Math.min(previous.length, length - offset);
                System.arraycopy(previous, 0, result, offset, bytesToCopy);
                offset += bytesToCopy;
                counter++;
            }
            return result;
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HKDF failed", ex);
        }
    }

    private static byte[] computeHMAC(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(payload);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC failed", ex);
        }
    }

    private static byte[] canonicalGatePayload(String method, String path, String timestamp, String nonce, String capability) {
        String value = String.join("\n",
            method == null ? "" : method.trim().toUpperCase(Locale.ROOT),
            normalizePath(path),
            timestamp,
            nonce,
            capability
        );
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] uint64BE(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }

    private static String normalizePath(String rawPath) {
        String value = rawPath == null ? "" : rawPath.trim();
        if (value.isBlank()) {
            return "/";
        }
        try {
            URI uri = new URI(value);
            String path = uri.getPath();
            if (path == null || path.isBlank()) {
                path = value.split("\\?", 2)[0];
            }
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            return path;
        } catch (URISyntaxException ex) {
            String path = value.split("\\?", 2)[0];
            return path.startsWith("/") ? path : "/" + path;
        }
    }

    private static boolean pathMatches(String pattern, String path) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        if (pattern.endsWith("*")) {
            return path.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        return pattern.equals(path);
    }

    private static String normalizeOrigin(String origin) {
        String value = origin == null ? "" : origin.trim().toLowerCase(Locale.ROOT);
        if (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isBlank()) {
            return "";
        }
        try {
            URI uri = new URI(value);
            if (uri.getScheme() != null && uri.getHost() != null) {
                String port = uri.getPort() >= 0 ? ":" + uri.getPort() : "";
                return (uri.getScheme() + "://" + uri.getHost() + port).toLowerCase(Locale.ROOT);
            }
        } catch (URISyntaxException ignored) {
        }
        return value;
    }

    private static String fingerprintForRequest(Map<String, String> headers, String clientIP) {
        String userAgent = headers.getOrDefault("user-agent", "").trim();
        String ip = clientIP == null ? "" : clientIP.trim();
        if (ip.isBlank() && userAgent.isBlank()) {
            return "";
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return bytesToHex(digest.digest((ip + "|" + userAgent).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("fingerprint failed", ex);
        }
    }

    private static long parseEpochMs(Object value, long defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        String stringValue = value.toString().trim();
        if (stringValue.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(stringValue);
        } catch (NumberFormatException ignored) {
        }
        try {
            return Instant.parse(stringValue).toEpochMilli();
        } catch (DateTimeParseException ignored) {
            return defaultValue;
        }
    }

    private static KeyPair generateServerKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("failed to create EC keypair", ex);
        }
    }

    private static PublicKey publicKeyFromRawPoint(byte[] rawPoint) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            int fieldSize = (ecParameterSpec.getCurve().getField().getFieldSize() + 7) / 8;
            if (rawPoint.length != (1 + fieldSize * 2) || rawPoint[0] != 0x04) {
                throw new IllegalArgumentException("invalid public key point");
            }
            byte[] x = slice(rawPoint, 1, 1 + fieldSize);
            byte[] y = slice(rawPoint, 1 + fieldSize, 1 + fieldSize * 2);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(
                new ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y)),
                ecParameterSpec
            );
            return KeyFactory.getInstance("EC").generatePublic(keySpec);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("failed to parse client public key", ex);
        }
    }

    private static byte[] extractPublicKeyRaw(PublicKey publicKey) {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        int fieldSize = (ecPublicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        byte[] x = leftPad(ecPublicKey.getW().getAffineX().toByteArray(), fieldSize);
        byte[] y = leftPad(ecPublicKey.getW().getAffineY().toByteArray(), fieldSize);
        ByteBuffer buffer = ByteBuffer.allocate(1 + fieldSize * 2);
        buffer.put((byte) 0x04);
        buffer.put(x);
        buffer.put(y);
        return buffer.array();
    }

    private static Map<String, String> mergeHeaders(Map<String, String> defaults, Map<String, Object> overrides) {
        Map<String, String> merged = new LinkedHashMap<>(defaults);
        for (Map.Entry<String, Object> entry : overrides.entrySet()) {
            if (entry.getValue() != null) {
                merged.put(entry.getKey(), entry.getValue().toString());
            }
        }
        return merged;
    }

    private static Function<String, byte[]> buildDeviceResolver(Object deviceSecrets) {
        Map<String, Object> secrets = asMap(deviceSecrets);
        return deviceID -> {
            Object value = secrets.get(deviceID);
            return value == null ? null : bytesValue(value);
        };
    }

    private static Map<String, String> lowercase(Map<String, String> headers) {
        Map<String, String> normalized = new HashMap<>();
        if (headers == null) {
            return normalized;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            normalized.put(entry.getKey().toLowerCase(Locale.ROOT), entry.getValue());
        }
        return normalized;
    }

    private static byte[] decodeBase64(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " is required");
        }
        return Base64.getDecoder().decode(value);
    }

    private static String asString(Object value, String defaultValue) {
        return value == null ? defaultValue : value.toString();
    }

    private static long asLong(Object value, long defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException ex) {
            return defaultValue;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null) {
                    result.put(entry.getKey().toString(), entry.getValue());
                }
            }
            return result;
        }
        return Collections.emptyMap();
    }

    private static List<Object> asList(Object value) {
        if (value instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        return List.of();
    }

    private static byte[] bytesValue(Object value) {
        if (value instanceof byte[] bytes) {
            return bytes.clone();
        }
        return value == null ? new byte[0] : value.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] randomBytes(int length) {
        byte[] value = new byte[length];
        RANDOM.nextBytes(value);
        return value;
    }

    private static byte[] concat(byte[]... values) {
        int size = 0;
        for (byte[] value : values) {
            size += value.length;
        }
        ByteBuffer buffer = ByteBuffer.allocate(size);
        for (byte[] value : values) {
            buffer.put(value);
        }
        return buffer.array();
    }

    private static byte[] slice(byte[] source, int start, int end) {
        byte[] out = new byte[end - start];
        System.arraycopy(source, start, out, 0, end - start);
        return out;
    }

    private static byte[] leftPad(byte[] input, int size) {
        if (input.length == size) {
            return input;
        }
        byte[] normalized = new byte[size];
        int copyLength = Math.min(input.length, size);
        System.arraycopy(input, input.length - copyLength, normalized, size - copyLength, copyLength);
        return normalized;
    }

    private static String bytesToHex(byte[] input) {
        StringBuilder builder = new StringBuilder(input.length * 2);
        for (byte value : input) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private record ResolvedSession(SecureSession session, Map<String, Object> userContext) {}

    private record GateSecret(String id, byte[] secret, long notBeforeMs, long expiresAtMs) {}

    private static final class CapabilityMatcher {
        private final String token;
        private final Map<String, String> metadata;
        private final Set<String> methods;
        private final List<String> paths;
        private final List<RouteMatcher> routes;

        private CapabilityMatcher(Map<String, Object> definition) {
            this.token = asString(definition.get("token"), "").trim();
            this.metadata = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : asMap(definition.get("metadata")).entrySet()) {
                if (entry.getValue() != null) {
                    metadata.put(entry.getKey(), entry.getValue().toString());
                }
            }
            this.methods = ConcurrentHashMap.newKeySet();
            for (Object item : asList(definition.get("methods"))) {
                String method = Objects.toString(item, "").trim().toUpperCase(Locale.ROOT);
                if (!method.isBlank()) {
                    methods.add(method);
                }
            }
            this.paths = new ArrayList<>();
            for (Object item : asList(definition.get("paths"))) {
                String path = Objects.toString(item, "").trim();
                if (!path.isBlank()) {
                    paths.add(path);
                }
            }
            this.routes = new ArrayList<>();
            for (Object item : asList(definition.get("routes"))) {
                Map<String, Object> route = asMap(item);
                String path = asString(route.get("path"), "").trim();
                if (!path.isBlank()) {
                    this.routes.add(new RouteMatcher(path, asList(route.get("methods"))));
                }
            }
        }

        private boolean allows(String method, String path) {
            String normalizedMethod = method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
            String normalizedPath = normalizePath(path);
            if (!routes.isEmpty()) {
                for (RouteMatcher route : routes) {
                    if (route.matches(normalizedMethod, normalizedPath)) {
                        return true;
                    }
                }
                return false;
            }
            if (!methods.isEmpty() && !methods.contains(normalizedMethod)) {
                return false;
            }
            if (paths.isEmpty()) {
                return true;
            }
            for (String pattern : paths) {
                if (pathMatches(pattern, normalizedPath)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class RouteMatcher {
        private final String path;
        private final Set<String> methods = ConcurrentHashMap.newKeySet();

        private RouteMatcher(String path, List<Object> methods) {
            this.path = path;
            for (Object item : methods) {
                String method = Objects.toString(item, "").trim().toUpperCase(Locale.ROOT);
                if (!method.isBlank()) {
                    this.methods.add(method);
                }
            }
        }

        private boolean matches(String method, String path) {
            return pathMatches(this.path, path) && (methods.isEmpty() || methods.contains(method));
        }
    }
}
