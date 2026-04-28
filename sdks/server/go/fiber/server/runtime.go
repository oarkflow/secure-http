package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/security"
	httpmw "github.com/oarkflow/securehttp/sdks/server/go/fiber/middleware"
)

const defaultAPIPrefix = "/api"

// RuntimeOptions controls reusable dependency initialization without owning the Fiber app.
type RuntimeOptions struct {
	Config     *config.ServerConfig
	ListenAddr string
}

// MountOptions controls how the reusable runtime is attached to an existing Fiber app.
type MountOptions struct {
	APIPrefix            string
	WebRoot              string
	StaticPrefix         string
	EnableStatic         bool
	EnableDemoRoutes     bool
	RequireAccessToken   bool
	RegisterAPIRoutes    func(fiber.Router, Dependencies)
	RegisterPublicRoutes func(fiber.Router, Dependencies)
}

// MountedRoutes describes the secured routers attached to a Fiber app.
type MountedRoutes struct {
	API fiber.Router
}

// Runtime contains initialized secure-http dependencies that can be mounted into any Fiber app.
type Runtime struct {
	deps       Dependencies
	listenAddr string
	uploads    uploadPolicy
	gate       *httpmw.GateMiddleware
	auth       *httpmw.StatelessAuthMiddleware
	csrf       *httpmw.CSRFMiddleware
	closeOnce  sync.Once
	cleanup    func()
}

// DefaultFiberConfig returns the default Fiber config used by the compatibility server wrapper.
func DefaultFiberConfig() fiber.Config {
	return fiber.Config{
		BodyLimit: 10 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			c.Response().Reset()
			return c.SendStatus(fiber.StatusNotFound)
		},
	}
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

// NewRuntime builds reusable secure-http dependencies without creating a Fiber app.
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

	cryptoMiddleware, err := httpmw.NewCryptoMiddleware(policy)
	if err != nil {
		return fail(fmt.Errorf("initialize crypto middleware: %w", err))
	}

	listenAddr := cfg.ListenAddr
	if override := strings.TrimSpace(opts.ListenAddr); override != "" {
		listenAddr = override
	}

	deps := Dependencies{
		Config:            cfg,
		AuditLogger:       auditLogger,
		SessionManager:    cryptoMiddleware.GetSessionManager(),
		CryptoMiddleware:  cryptoMiddleware,
		Gatekeeper:        gatekeeper,
		Authenticator:     statelessAuth,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
	}

	return &Runtime{
		deps:       deps,
		listenAddr: listenAddr,
		uploads:    newUploadPolicy(cfg.Uploads),
		gate:       httpmw.NewGateMiddleware(gatekeeper),
		auth: httpmw.NewStatelessAuthMiddlewareWithConfig(statelessAuth, httpmw.StatelessAuthConfig{
			CookieName: cfg.Auth.SessionCookie.Name,
		}),
		csrf: httpmw.NewCSRFMiddleware(httpmw.CSRFConfig{
			Enabled:    cfg.Auth.CSRF.Enabled,
			CookieName: cfg.Auth.CSRF.CookieName,
			HeaderName: cfg.Auth.CSRF.HeaderName,
		}),
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
func (r *Runtime) GateMiddleware() fiber.Handler {
	if r == nil || r.gate == nil {
		return func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusNotFound)
		}
	}
	return r.gate.Handle()
}

// HandshakeHandler returns the secure handshake endpoint handler.
func (r *Runtime) HandshakeHandler() fiber.Handler {
	if r == nil || r.deps.CryptoMiddleware == nil {
		return func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusNotFound)
		}
	}
	return r.deps.CryptoMiddleware.Handshake()
}

// HealthHandler returns a lightweight health check handler.
func (r *Runtime) HealthHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessions := 0
		if r != nil && r.deps.SessionManager != nil {
			sessions = r.deps.SessionManager.SessionCount()
		}
		return c.JSON(fiber.Map{
			"status":   "healthy",
			"sessions": sessions,
		})
	}
}

// Secure wires the gate/auth/crypto middleware chain into a router and returns it for route registration.
func (r *Runtime) Secure(router fiber.Router, requireAccessToken bool) fiber.Router {
	if r == nil || router == nil {
		return router
	}
	router.Use(r.GateMiddleware())
	if requireAccessToken {
		router.Use(r.auth.Verify())
		router.Use(r.csrf.Verify())
	}
	router.Use(r.deps.CryptoMiddleware.Decrypt())
	router.Use(r.deps.CryptoMiddleware.Encrypt())
	return router
}

// Mount attaches the secure-http routes and middleware to an existing Fiber app.
func (r *Runtime) Mount(app *fiber.App, opts MountOptions) (*MountedRoutes, error) {
	if r == nil {
		return nil, fmt.Errorf("runtime is not initialized")
	}
	if app == nil {
		return nil, fmt.Errorf("fiber app is required")
	}

	applyAppMiddleware(app, r.deps.Config)

	app.Post("/handshake", r.GateMiddleware(), r.HandshakeHandler())
	app.Get("/health", r.HealthHandler())

	if opts.EnableDemoRoutes && !r.deps.Config.IsStrictMode() {
		app.Post("/login", handleLogon(r.deps.Config, r.deps.UserAuthenticator, r.deps.DeviceRegistry, r.deps.Authenticator))
		app.Post("/bootstrap", r.auth.Verify(), r.csrf.Verify(), handleBootstrap(r.deps))
	}
	if opts.RegisterPublicRoutes != nil {
		opts.RegisterPublicRoutes(app, r.deps)
	}

	apiPrefix := normalizeAPIPrefix(opts.APIPrefix)
	api := r.Secure(app.Group(apiPrefix), opts.RequireAccessToken)
	if opts.EnableDemoRoutes {
		registerDemoRoutes(api, r.deps, r.uploads)
	}
	if opts.RegisterAPIRoutes != nil {
		opts.RegisterAPIRoutes(api, r.deps)
	}

	if opts.EnableStatic {
		webRoot := opts.WebRoot
		if strings.TrimSpace(webRoot) == "" {
			webRoot = "dist"
		}
		if err := ensureStaticBundle(webRoot); err != nil {
			return nil, fmt.Errorf("static assets: %w", err)
		}
		registerStaticRoutes(app, normalizePrefix(opts.StaticPrefix), webRoot)
	}

	return &MountedRoutes{API: api}, nil
}

// Close releases runtime resources.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.cleanup != nil {
			r.cleanup()
		}
	})
	return nil
}

func applyAppMiddleware(app *fiber.App, cfg *config.ServerConfig) {
	app.Use(recover.New())
	app.Use(logger.New())

	allowOrigins := ""
	if cfg != nil {
		allowOrigins = cfg.CORSAllowOrigins()
	}
	if allowOrigins == "" {
		return
	}

	allowedOriginSet := make(map[string]struct{}, len(cfg.Gate.AllowedOrigins))
	for _, origin := range cfg.Gate.AllowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			allowedOriginSet[trimmed] = struct{}{}
		}
	}

	app.Use(func(c *fiber.Ctx) error {
		origin := strings.TrimSpace(c.Get("Origin"))
		if origin != "" {
			if _, ok := allowedOriginSet[origin]; ok {
				c.Set("Access-Control-Allow-Origin", origin)
				c.Set("Vary", "Origin")
				c.Set("Access-Control-Allow-Credentials", "true")
				c.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS")
				c.Set("Access-Control-Allow-Headers", accessControlAllowHeaders())
			}
		}
		if c.Method() == fiber.MethodOptions {
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	})
	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowOrigins,
		AllowMethods:     "GET,POST,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     accessControlAllowHeaders(),
		AllowCredentials: true,
		MaxAge:           86400,
	}))
}

func normalizeAPIPrefix(prefix string) string {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return defaultAPIPrefix
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	if trimmed == "/" {
		return defaultAPIPrefix
	}
	return strings.TrimRight(trimmed, "/")
}

func accessControlAllowHeaders() string {
	return "Origin,Referer,Content-Type,Accept,Authorization,X-CSRF-Token,X-Gate-Time,X-Gate-Sign,X-Gate-Purpose,X-Gate-Seq,X-Gate-Key,X-Gate-Nonce,X-Gate-Timestamp,X-Gate-Signature,X-Capability-Token,X-Session-ID,X-User-Token,X-Original-Content-Type"
}
