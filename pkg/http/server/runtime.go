package server

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/securehttp/pkg/config"
	securecrypto "github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
)

type contextKey string

const (
	contextKeyTokenClaims contextKey = "securehttp_token_claims"
	contextKeyUserID      contextKey = "securehttp_user_id"
	contextKeyDeviceID    contextKey = "securehttp_device_id"
	contextKeyUserRoles   contextKey = "securehttp_user_roles"
	contextKeyTokenID     contextKey = "securehttp_token_id"
	contextKeyAuthSource  contextKey = "securehttp_auth_source"
	contextKeyUserContext contextKey = "securehttp_user_context"
)

// RuntimeOptions controls reusable dependency initialization for net/http-compatible servers.
type RuntimeOptions struct {
	Config     *config.ServerConfig
	ListenAddr string
}

// Dependencies exposes the initialized security stack for reuse across HTTP frameworks.
type Dependencies struct {
	Config            *config.ServerConfig
	AuditLogger       security.AuditLogger
	SessionManager    *securecrypto.SessionManager
	Gatekeeper        *security.Gatekeeper
	Authenticator     *security.StatelessAuthenticator
	DeviceRegistry    security.DeviceRegistry
	UserAuthenticator security.UserAuthenticator
}

// Runtime contains initialized secure-http dependencies that can be mounted into any net/http-compatible server.
type Runtime struct {
	deps       Dependencies
	listenAddr string
	transport  *Middleware
	auth       *authMiddleware
	csrf       *csrfMiddleware
	cleanup    func()
}

// NewRuntimeFromFile loads the config file and initializes reusable dependencies.
func NewRuntimeFromFile(path string, opts RuntimeOptions) (*Runtime, error) {
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		return nil, err
	}
	opts.Config = cfg
	return NewRuntime(opts)
}

// NewRuntime builds reusable secure-http dependencies without binding to a specific HTTP router.
func NewRuntime(opts RuntimeOptions) (*Runtime, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, fmt.Errorf("server config is required")
	}

	authKey := []byte(cfg.Auth.JWTSigningKey)
	if len(authKey) == 0 {
		return nil, fmt.Errorf("jwt signing key is required")
	}
	statelessAuth, err := security.NewStatelessAuthenticator(security.StatelessAuthConfig{
		SigningKey:         authKey,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenTTL:    7 * 24 * time.Hour,
		Algorithm:          "HS512",
		Issuer:             "secure-http-server",
		Audience:           "secure-http-api",
		RequireFingerprint: true,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize stateless auth: %w", err)
	}

	auditLogger, cleanup, err := cfg.BuildAuditLogger()
	if err != nil {
		return nil, fmt.Errorf("initialize audit logger: %w", err)
	}
	fail := func(err error) (*Runtime, error) {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}

	capStore, err := cfg.BuildCapabilityStore()
	if err != nil {
		return fail(fmt.Errorf("build capability store: %w", err))
	}

	gateCfg, err := cfg.GatekeeperConfig(capStore, auditLogger)
	if err != nil {
		return fail(fmt.Errorf("compose gatekeeper config: %w", err))
	}
	gatekeeper, err := security.NewGatekeeper(gateCfg)
	if err != nil {
		return fail(fmt.Errorf("initialize gatekeeper: %w", err))
	}

	deviceRegistry, err := cfg.BuildDeviceRegistry()
	if err != nil {
		return fail(fmt.Errorf("build device registry: %w", err))
	}

	userAuth, err := cfg.BuildUserAuthenticator()
	if err != nil {
		return fail(fmt.Errorf("build user authenticator: %w", err))
	}

	policy := &security.SecurityPolicy{
		RequireDevice:     cfg.Auth.RequireDevice,
		RequireUser:       cfg.Auth.RequireUser,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
		Logger:            auditLogger,
	}

	transport, err := NewTransport(policy)
	if err != nil {
		return fail(fmt.Errorf("initialize stdlib transport: %w", err))
	}

	listenAddr := cfg.ListenAddr
	if override := strings.TrimSpace(opts.ListenAddr); override != "" {
		listenAddr = override
	}

	deps := Dependencies{
		Config:            cfg,
		AuditLogger:       auditLogger,
		SessionManager:    transport.SessionManager(),
		Gatekeeper:        gatekeeper,
		Authenticator:     statelessAuth,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
	}

	return &Runtime{
		deps:       deps,
		listenAddr: listenAddr,
		transport:  transport,
		auth: &authMiddleware{
			auth:       statelessAuth,
			cookieName: cfg.Auth.SessionCookie.Name,
		},
		csrf: &csrfMiddleware{
			enabled:    cfg.Auth.CSRF.Enabled,
			cookieName: cfg.Auth.CSRF.CookieName,
			headerName: cfg.Auth.CSRF.HeaderName,
		},
		cleanup: cleanup,
	}, nil
}

// Dependencies returns initialized security dependencies.
func (r *Runtime) Dependencies() Dependencies {
	if r == nil {
		return Dependencies{}
	}
	return r.deps
}

// ListenAddr returns the configured or overridden listen address.
func (r *Runtime) ListenAddr() string {
	if r == nil {
		return ""
	}
	return r.listenAddr
}

// GateMiddleware returns the pre-routing gate middleware.
func (r *Runtime) GateMiddleware() func(http.Handler) http.Handler {
	if r == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return GateMiddleware(r.deps.Gatekeeper)
}

// HandshakeHandler returns the secure handshake endpoint handler.
func (r *Runtime) HandshakeHandler() http.Handler {
	if r == nil || r.transport == nil {
		return http.NotFoundHandler()
	}
	return r.transport.HandshakeHandler()
}

// HealthHandler returns a lightweight health check handler.
func (r *Runtime) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sessions := 0
		if r != nil && r.deps.SessionManager != nil {
			sessions = r.deps.SessionManager.SessionCount()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"status":"healthy","sessions":%d}`, sessions)))
	})
}

// RequireAuth applies access-token validation.
func (r *Runtime) RequireAuth(next http.Handler) http.Handler {
	if r == nil || r.auth == nil {
		return http.NotFoundHandler()
	}
	return r.auth.Verify(next)
}

// RequireCSRF applies CSRF validation for cookie-backed authenticated requests.
func (r *Runtime) RequireCSRF(next http.Handler) http.Handler {
	if r == nil || r.csrf == nil {
		return http.NotFoundHandler()
	}
	return r.csrf.Verify(next)
}

// Secure applies gate validation and secure transport handling, plus optional access-token/CSRF checks.
func (r *Runtime) Secure(next http.Handler, requireAccessToken bool) http.Handler {
	if r == nil || r.transport == nil {
		return http.NotFoundHandler()
	}
	handler := r.transport.Secure(next)
	if requireAccessToken {
		handler = r.RequireCSRF(handler)
		handler = r.RequireAuth(handler)
	}
	return r.GateMiddleware()(handler)
}

// Close releases any runtime cleanup resources.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.cleanup != nil {
		r.cleanup()
		r.cleanup = nil
	}
	return nil
}

// TokenClaimsFromRequest returns token claims injected by RequireAuth.
func TokenClaimsFromRequest(r *http.Request) *security.StatelessTokenClaims {
	if r == nil {
		return nil
	}
	claims, _ := r.Context().Value(contextKeyTokenClaims).(*security.StatelessTokenClaims)
	return claims
}

// UserContextFromRequest returns the normalized user context injected by RequireAuth.
func UserContextFromRequest(r *http.Request) *security.UserContext {
	if r == nil {
		return nil
	}
	userCtx, _ := r.Context().Value(contextKeyUserContext).(*security.UserContext)
	return userCtx
}

type authMiddleware struct {
	auth       *security.StatelessAuthenticator
	cookieName string
}

func (m *authMiddleware) Verify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, source, err := m.resolveToken(r)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		fingerprint := security.ComputeSessionFingerprint(clientIP(r), r.UserAgent())
		claims, err := m.auth.ValidateToken(token, "access", fingerprint)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		userCtx := &security.UserContext{
			ID:       claims.UserID,
			Roles:    append([]string{}, claims.Roles...),
			Metadata: copyStringMap(claims.Metadata),
		}

		ctx := context.WithValue(r.Context(), contextKeyTokenClaims, claims)
		ctx = context.WithValue(ctx, contextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, contextKeyDeviceID, claims.DeviceID)
		ctx = context.WithValue(ctx, contextKeyUserRoles, append([]string{}, claims.Roles...))
		ctx = context.WithValue(ctx, contextKeyTokenID, claims.TokenID)
		ctx = context.WithValue(ctx, contextKeyAuthSource, source)
		ctx = context.WithValue(ctx, contextKeyUserContext, userCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *authMiddleware) resolveToken(r *http.Request) (string, string, error) {
	if m == nil || r == nil {
		return "", "", fmt.Errorf("request is required")
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			return "", "", fmt.Errorf("invalid authorization format")
		}
		token := strings.TrimSpace(parts[1])
		if token == "" {
			return "", "", fmt.Errorf("missing bearer token")
		}
		return token, "header", nil
	}
	cookieName := strings.TrimSpace(m.cookieName)
	if cookieName == "" {
		cookieName = "securehttp_access"
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		if token := strings.TrimSpace(cookie.Value); token != "" {
			return token, "cookie", nil
		}
	}
	return "", "", fmt.Errorf("missing authorization token")
}

type csrfMiddleware struct {
	enabled    bool
	cookieName string
	headerName string
}

func (m *csrfMiddleware) Verify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || !m.enabled || isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		source, _ := r.Context().Value(contextKeyAuthSource).(string)
		if source != "cookie" {
			next.ServeHTTP(w, r)
			return
		}
		claims := TokenClaimsFromRequest(r)
		if claims == nil || len(claims.Metadata) == 0 {
			http.NotFound(w, r)
			return
		}
		expected := strings.TrimSpace(claims.Metadata["csrf_token"])
		if expected == "" {
			http.NotFound(w, r)
			return
		}
		headerName := strings.TrimSpace(m.headerName)
		if headerName == "" {
			headerName = "X-CSRF-Token"
		}
		headerValue := strings.TrimSpace(r.Header.Get(headerName))
		if headerValue == "" || subtle.ConstantTimeCompare([]byte(headerValue), []byte(expected)) != 1 {
			http.NotFound(w, r)
			return
		}
		cookieName := strings.TrimSpace(m.cookieName)
		if cookieName == "" {
			cookieName = "securehttp_csrf"
		}
		cookie, err := r.Cookie(cookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(cookie.Value)), []byte(expected)) != 1 {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
