package stdlib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	securecrypto "github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
)

const MaxMessageSize = 10 * 1024 * 1024

type contextKey string

const (
	contextKeyPlaintextBody  contextKey = "securehttp_plaintext_body"
	contextKeySession        contextKey = "securehttp_session"
	contextKeySessionID      contextKey = "securehttp_session_id"
	contextKeyDeviceID       contextKey = "securehttp_device_id"
	contextKeyUserContext    contextKey = "securehttp_user_context"
	contextKeyCapability     contextKey = "securehttp_capability"
	contextKeyCapabilityMeta contextKey = "securehttp_capability_meta"
)

// Config defines how the stdlib middleware behaves.
type Config struct {
	Policy               *security.SecurityPolicy
	Headers              security.HeaderNames
	SessionManagerConfig securecrypto.SessionManagerConfig
}

// Middleware provides standard net/http handlers for the secure transport.
type Middleware struct {
	sessionManager *securecrypto.SessionManager
	policy         *security.SecurityPolicy
	headers        security.HeaderNames
}

// New builds stdlib middleware with default options.
func New(policy *security.SecurityPolicy) (*Middleware, error) {
	return NewWithConfig(Config{Policy: policy})
}

// NewWithConfig builds stdlib middleware with advanced options.
func NewWithConfig(cfg Config) (*Middleware, error) {
	policy := cfg.Policy
	if policy == nil {
		policy = security.DefaultSecurityPolicy()
	}
	if err := policy.ValidateReady(); err != nil {
		return nil, err
	}
	headers := cfg.Headers.WithDefaults()
	sessionCfg := cfg.SessionManagerConfig
	if sessionCfg.SessionTimeout <= 0 {
		sessionCfg.SessionTimeout = policy.SessionTTL
	}
	if sessionCfg.MessageTTL <= 0 {
		sessionCfg.MessageTTL = policy.MessageTTL
	}
	if sessionCfg.CleanupInterval <= 0 {
		sessionCfg.CleanupInterval = 5 * time.Minute
	}
	sm, err := securecrypto.NewSessionManagerWithConfig(sessionCfg)
	if err != nil {
		return nil, err
	}
	return &Middleware{
		sessionManager: sm,
		policy:         policy,
		headers:        headers,
	}, nil
}

// SessionManager exposes the active session manager.
func (m *Middleware) SessionManager() *securecrypto.SessionManager {
	if m == nil {
		return nil
	}
	return m.sessionManager
}

// HandshakeHandler handles the secure session key exchange.
func (m *Middleware) HandshakeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			respondNotFound(w)
			return
		}
		var req securecrypto.HandshakeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "invalid payload", err)
			respondNotFound(w)
			return
		}

		if m.policy != nil {
			skew := m.policy.MaxClockSkew
			if skew <= 0 {
				skew = time.Minute
			}
			ts := time.Unix(req.Timestamp, 0)
			delta := time.Since(ts)
			if delta > skew || delta < -skew {
				m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "timestamp out of range", fmt.Errorf("timestamp skew"))
				respondNotFound(w)
				return
			}
		}

		if m.policy != nil && m.policy.RequireDevice {
			if req.DeviceID == "" || len(req.DeviceSignature) == 0 {
				m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "missing device identity", fmt.Errorf("missing device"))
				respondNotFound(w)
				return
			}
			payload := security.DeviceAuthenticationPayload(req.ClientPublicKey, req.Timestamp)
			if err := m.policy.DeviceRegistry.Validate(req.DeviceID, req.DeviceSignature, payload); err != nil {
				m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "device validation failed", err)
				respondNotFound(w)
				return
			}
		}

		var userCtx *security.UserContext
		if m.policy != nil && m.policy.UserAuthenticator != nil {
			if req.UserToken == "" {
				if m.policy.RequireUser {
					m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "missing user token", fmt.Errorf("missing user token"))
					respondNotFound(w)
					return
				}
			} else {
				ctx, err := m.policy.UserAuthenticator.Validate(req.UserToken)
				if err != nil {
					m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "user token invalid", err)
					respondNotFound(w)
					return
				}
				userCtx = ctx
			}
		} else if m.policy != nil && m.policy.RequireUser {
			m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "user verification disabled", fmt.Errorf("user verification disabled"))
			respondNotFound(w)
			return
		}

		metadata := make(map[string]string)
		if req.DeviceID != "" {
			metadata[security.MetadataDeviceID] = req.DeviceID
		}
		if userCtx != nil {
			security.AttachUserContext(metadata, userCtx)
		}
		fingerprint := clientFingerprint(r)
		if fingerprint != "" {
			security.StoreSessionFingerprint(metadata, fingerprint)
		}
		if len(metadata) == 0 {
			metadata = nil
		}

		sessionID, err := m.sessionManager.CreateSession(req.ClientPublicKey, metadata)
		if err != nil {
			m.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, userCtx, "session creation failed", err)
			respondNotFound(w)
			return
		}

		nowTime := time.Now()
		resp := securecrypto.HandshakeResponse{
			ServerPublicKey: m.sessionManager.GetPublicKey(),
			SessionID:       []byte(sessionID),
			DeviceID:        req.DeviceID,
			ExpiresAt:       nowTime.Add(m.policy.SessionTTL).Unix(),
			Timestamp:       nowTime.Unix(),
		}

		m.logEvent(security.AuditEventHandshakeSuccess, sessionID, req.DeviceID, userCtx, "session established", nil)
		writeJSON(w, http.StatusOK, resp)
	})
}

// GateMiddleware validates pre-routing gate headers.
func GateMiddleware(gate *security.Gatekeeper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if gate == nil {
				respondNotFound(w)
				return
			}
			capability, err := gate.Evaluate(security.GateRequest{
				Method:     r.Method,
				Path:       canonicalPath(r),
				Headers:    flattenHeaders(r.Header),
				RemoteAddr: clientIP(r),
			})
			if err != nil {
				respondNotFound(w)
				return
			}
			ctx := r.Context()
			if capability != nil {
				ctx = context.WithValue(ctx, contextKeyCapability, capability.Token)
				ctx = context.WithValue(ctx, contextKeyCapabilityMeta, capability.Metadata)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Decrypt validates the secure session and replaces the request body with plaintext.
func (m *Middleware) Decrypt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			respondNotFound(w)
			return
		}
		sessionID := strings.TrimSpace(r.Header.Get(m.headers.SessionID))
		if sessionID == "" {
			m.logEvent(security.AuditEventDecryptFailure, "", "", nil, "missing session header", fmt.Errorf("missing session"))
			respondNotFound(w)
			return
		}
		session, ok := m.sessionManager.GetSession(sessionID)
		if !ok {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, "", nil, "session not found", fmt.Errorf("session invalid"))
			respondNotFound(w)
			return
		}
		fingerprint := clientFingerprint(r)
		if !security.VerifySessionFingerprint(session.Metadata, fingerprint) {
			m.sessionManager.DeleteSession(sessionID)
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "fingerprint mismatch", fmt.Errorf("session fingerprint mismatch"))
			respondNotFound(w)
			return
		}

		var userCtx *security.UserContext
		if m.policy != nil && m.policy.UserAuthenticator != nil {
			token := strings.TrimSpace(r.Header.Get(m.headers.UserToken))
			if token != "" {
				ctx, err := m.policy.UserAuthenticator.Validate(token)
				if err != nil {
					m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "user token invalid", err)
					respondNotFound(w)
					return
				}
				userCtx = ctx
			} else if m.policy.RequireUser {
				userCtx = security.ExtractUserContext(session.Metadata)
				if userCtx == nil {
					m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "missing user token", fmt.Errorf("user token missing"))
					respondNotFound(w)
					return
				}
			}
		} else if m.policy != nil && m.policy.RequireUser {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "user verification disabled", fmt.Errorf("user verification disabled"))
			respondNotFound(w)
			return
		} else {
			userCtx = security.ExtractUserContext(session.Metadata)
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageSize+1))
		if err != nil {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "failed to read body", err)
			respondNotFound(w)
			return
		}
		if len(body) == 0 {
			if isSafeEmptyBodyMethod(r.Method) {
				next.ServeHTTP(w, withRequestContext(r, session, sessionID, nil, userCtx))
				return
			}
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "empty body", fmt.Errorf("empty body"))
			respondNotFound(w)
			return
		}
		if len(body) > MaxMessageSize {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "payload too large", fmt.Errorf("payload too large"))
			respondNotFound(w)
			return
		}

		var encMsg securecrypto.EncryptedMessage
		if err := json.Unmarshal(body, &encMsg); err != nil {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "invalid envelope", err)
			respondNotFound(w)
			return
		}
		plaintext, err := session.Decrypt(&encMsg)
		if err != nil {
			m.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "decrypt failure", err)
			respondNotFound(w)
			return
		}

		m.logEvent(security.AuditEventDecryptSuccess, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "payload decrypted", nil)
		next.ServeHTTP(w, withRequestContext(r, session, sessionID, plaintext, userCtx))
	})
}

// Encrypt wraps downstream responses in the secure envelope.
func (m *Middleware) Encrypt(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newResponseRecorder()
		next.ServeHTTP(rec, r)

		session := SessionFromContext(r.Context())
		if session == nil {
			copyResponse(w, rec)
			return
		}
		body := rec.body.Bytes()
		if len(body) == 0 || rec.status >= http.StatusBadRequest {
			copyResponse(w, rec)
			return
		}

		encMsg, err := session.Encrypt(body)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}
		payload, err := json.Marshal(encMsg)
		if err != nil {
			http.Error(w, "Failed to marshal encrypted response", http.StatusInternalServerError)
			return
		}

		copyHeaders(w.Header(), rec.header)
		w.Header().Set("Content-Type", "application/octet-stream")
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(payload)
	})
}

// Secure composes request decryption and response encryption around a handler.
func (m *Middleware) Secure(next http.Handler) http.Handler {
	return m.Decrypt(m.Encrypt(next))
}

// PlaintextBodyFromContext returns the decrypted request payload.
func PlaintextBodyFromContext(ctx context.Context) []byte {
	value, _ := ctx.Value(contextKeyPlaintextBody).([]byte)
	if len(value) == 0 {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

// SessionFromContext returns the resolved secure session.
func SessionFromContext(ctx context.Context) *securecrypto.Session {
	session, _ := ctx.Value(contextKeySession).(*securecrypto.Session)
	return session
}

// SessionIDFromContext returns the active secure session ID.
func SessionIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKeySessionID).(string)
	return value
}

// DeviceIDFromContext returns the device ID that created the secure session.
func DeviceIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKeyDeviceID).(string)
	return value
}

// UserContextFromContext returns the authenticated user context.
func UserContextFromContext(ctx context.Context) *security.UserContext {
	userCtx, _ := ctx.Value(contextKeyUserContext).(*security.UserContext)
	return userCtx
}

// CapabilityTokenFromContext returns the gate capability token.
func CapabilityTokenFromContext(ctx context.Context) string {
	value, _ := ctx.Value(contextKeyCapability).(string)
	return value
}

// CapabilityMetadataFromContext returns gate capability metadata.
func CapabilityMetadataFromContext(ctx context.Context) map[string]string {
	value, _ := ctx.Value(contextKeyCapabilityMeta).(map[string]string)
	if len(value) == 0 {
		return nil
	}
	out := make(map[string]string, len(value))
	for k, v := range value {
		out[k] = v
	}
	return out
}

// DecodeJSON decodes the plaintext secure payload into out.
func DecodeJSON(r *http.Request, out any) error {
	body := PlaintextBodyFromContext(r.Context())
	if len(body) == 0 {
		return io.EOF
	}
	return json.Unmarshal(body, out)
}

func withRequestContext(r *http.Request, session *securecrypto.Session, sessionID string, plaintext []byte, userCtx *security.UserContext) *http.Request {
	ctx := r.Context()
	if len(plaintext) > 0 {
		body := make([]byte, len(plaintext))
		copy(body, plaintext)
		ctx = context.WithValue(ctx, contextKeyPlaintextBody, body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	} else {
		r.Body = http.NoBody
		r.ContentLength = 0
	}
	ctx = context.WithValue(ctx, contextKeySession, session)
	ctx = context.WithValue(ctx, contextKeySessionID, sessionID)
	if session != nil && session.Metadata != nil {
		if deviceID := session.Metadata[security.MetadataDeviceID]; deviceID != "" {
			ctx = context.WithValue(ctx, contextKeyDeviceID, deviceID)
		}
	}
	if userCtx == nil && session != nil {
		userCtx = security.ExtractUserContext(session.Metadata)
	}
	if userCtx != nil {
		ctx = context.WithValue(ctx, contextKeyUserContext, userCtx)
	}
	return r.WithContext(ctx)
}

func isSafeEmptyBodyMethod(method string) bool {
	return method == http.MethodGet ||
		method == http.MethodHead ||
		method == http.MethodOptions ||
		method == http.MethodDelete
}

func flattenHeaders(source http.Header) map[string]string {
	if len(source) == 0 {
		return nil
	}
	headers := make(map[string]string, len(source))
	for key, values := range source {
		if len(values) == 0 {
			continue
		}
		headers[key] = values[0]
	}
	return headers
}

func canonicalPath(r *http.Request) string {
	if r == nil || r.URL == nil || strings.TrimSpace(r.URL.Path) == "" {
		return "/"
	}
	return r.URL.Path
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func clientFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	return security.ComputeSessionFingerprint(clientIP(r), r.UserAgent())
}

func respondNotFound(w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (m *Middleware) logEvent(eventType security.AuditEventType, sessionID, deviceID string, userCtx *security.UserContext, detail string, err error) {
	if m == nil || m.policy == nil || m.policy.Logger == nil {
		return
	}
	evt := security.AuditEvent{
		Type:      eventType,
		SessionID: sessionID,
		DeviceID:  deviceID,
		Detail:    detail,
		Err:       err,
		Timestamp: time.Now(),
	}
	if userCtx != nil {
		evt.UserID = userCtx.ID
	}
	m.policy.Logger.Record(evt)
}

type responseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
}

func copyHeaders(dst, src http.Header) {
	for key := range dst {
		dst.Del(key)
	}
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copyResponse(w http.ResponseWriter, rec *responseRecorder) {
	if w == nil || rec == nil {
		return
	}
	copyHeaders(w.Header(), rec.header)
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(rec.body.Bytes())
}
