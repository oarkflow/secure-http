package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/crypto"
	httpmw "github.com/oarkflow/securehttp/pkg/http/middleware"
	"github.com/oarkflow/securehttp/pkg/security"
)

type loginRequest struct {
	Username string `json:"username"`
	Purpose  string `json:"purpose"`
	Nonce    string `json:"nonce"`
}

type pentestRequest struct {
	Vector  string                 `json:"vector"`
	Payload map[string]interface{} `json:"payload"`
	Notes   string                 `json:"notes"`
}

func main() {
	var (
		configPath   = flag.String("config", defaultConfigPath(), "Path to server configuration JSON")
		webRoot      = flag.String("web", "web/securefetch-demo", "Static asset directory (includes index.html + securefetch.wasm)")
		staticPrefix = flag.String("static-prefix", "/demo", "URL prefix that serves the WASM + static bundle")
		addrOverride = flag.String("addr", "", "Override listen address (defaults to listen_addr in config)")
	)
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("load server config: %v", err)
	}
	if err := ensureStaticBundle(*webRoot); err != nil {
		log.Fatalf("static assets: %v", err)
	}

	auditLogger, cleanup, err := cfg.BuildAuditLogger()
	if err != nil {
		log.Fatalf("initialize audit logger: %v", err)
	}
	defer cleanup()

	capStore, err := cfg.BuildCapabilityStore()
	if err != nil {
		log.Fatalf("build capability store: %v", err)
	}

	gateCfg, err := cfg.GatekeeperConfig(capStore, auditLogger)
	if err != nil {
		log.Fatalf("compose gatekeeper config: %v", err)
	}
	gatekeeper, err := security.NewGatekeeper(gateCfg)
	if err != nil {
		log.Fatalf("initialize gatekeeper: %v", err)
	}

	deviceRegistry, err := cfg.BuildDeviceRegistry()
	if err != nil {
		log.Fatalf("build device registry: %v", err)
	}

	userAuth, err := cfg.BuildUserAuthenticator()
	if err != nil {
		log.Fatalf("build user authenticator: %v", err)
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
		log.Fatalf("initialize crypto middleware: %v", err)
	}

	listenAddr := cfg.ListenAddr
	if override := strings.TrimSpace(*addrOverride); override != "" {
		listenAddr = override
	}

	app := fiber.New(fiber.Config{
		BodyLimit: 10 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			c.Response().Reset()
			return c.SendStatus(fiber.StatusNotFound)
		},
	})

	app.Use(recover.New())
	app.Use(logger.New())

	prefix := normalizePrefix(*staticPrefix)
	app.Static(prefix, *webRoot, fiber.Static{
		Compress:      true,
		Browse:        true,
		Index:         "index.html",
		CacheDuration: 30 * time.Minute,
		MaxAge:        600,
	})
	app.Get("/", func(c *fiber.Ctx) error {
		target := prefix
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}
		return c.Redirect(target, fiber.StatusTemporaryRedirect)
	})

	gateMiddleware := httpmw.NewGateMiddleware(gatekeeper)
	app.Use(gateMiddleware.Handle())

	app.Post("/handshake", cryptoMiddleware.Handshake())
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":   "healthy",
			"sessions": cryptoMiddleware.GetSessionManager().SessionCount(),
		})
	})

	api := app.Group("/api")
	api.Use(cryptoMiddleware.Decrypt())
	api.Use(cryptoMiddleware.Encrypt())

	registerSecureRoutes(api, auditLogger, cryptoMiddleware.GetSessionManager())

	log.Printf("🧪 Full-stack secure demo available on %s", listenAddr)
	log.Printf("   • Static lab: http://localhost%s%s/", listenAddr, prefix)
	log.Printf("   • Handshake + encrypted APIs continue to require gate headers")
	log.Fatal(app.Listen(listenAddr))
}

func registerSecureRoutes(api fiber.Router, auditLogger security.AuditLogger, sessionManager *crypto.SessionManager) {
	api.Post("/echo", handleEcho())
	api.Post("/user/info", handleUserInfo())
	api.Post("/resource/create", handleResourceCreate())
	api.Post("/login", handleSecureLogin(auditLogger))
	api.Post("/session/state", handleSessionState())
	api.Post("/pentest/probe", handlePentestProbe(auditLogger))
	api.Post("/logout", handleLogout(sessionManager, auditLogger))
}

func handleEcho() fiber.Handler {
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid JSON in decrypted body"})
		}
		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "Echo response",
			"data": fiber.Map{
				"received":     req,
				"processed_at": time.Now(),
				"security":     securityEnvelope(c),
			},
		})
	}
}

func handleUserInfo() fiber.Handler {
	type userRequest struct {
		Name string `json:"name"`
	}
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req userRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}
		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "User info retrieved",
			"data": fiber.Map{
				"user":     req.Name,
				"bio":      "This is sensitive user data",
				"email":    fmt.Sprintf("%s@example.com", strings.ReplaceAll(req.Name, " ", ".")),
				"security": securityEnvelope(c),
			},
		})
	}
}

func handleResourceCreate() fiber.Handler {
	type resourceRequest struct {
		Name   string `json:"name"`
		Owner  string `json:"owner"`
		Reason string `json:"reason"`
	}
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req resourceRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}
		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "Resource created successfully",
			"data": fiber.Map{
				"resource_id": fmt.Sprintf("res_%d", time.Now().UnixNano()),
				"name":        req.Name,
				"created_by":  req.Owner,
				"reason":      req.Reason,
				"security":    securityEnvelope(c),
			},
		})
	}
}

func handleSecureLogin(auditLogger security.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req loginRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid credentials envelope"})
		}
		userCtx, _ := c.Locals("user_context").(*security.UserContext)
		if userCtx == nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "User token missing or invalid"})
		}
		if req.Username != "" && !strings.EqualFold(req.Username, userCtx.ID) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Username/token mismatch"})
		}
		sessionID, _ := c.Locals("session_id").(string)
		deviceID, _ := c.Locals("device_id").(string)
		auditLogger.Record(security.AuditEvent{
			Type:      security.AuditEventDecryptSuccess,
			SessionID: sessionID,
			DeviceID:  deviceID,
			UserID:    userCtx.ID,
			Detail:    fmt.Sprintf("login confirmed purpose=%s", req.Purpose),
			Timestamp: time.Now(),
		})
		return c.JSON(fiber.Map{
			"status":    200,
			"success":   true,
			"message":   "Login confirmed via secure session",
			"session":   sessionDescriptor(c),
			"user":      userCtx,
			"purpose":   req.Purpose,
			"nonce":     req.Nonce,
			"device_id": deviceID,
		})
	}
}

func handleSessionState() fiber.Handler {
	return func(c *fiber.Ctx) error {
		session, err := requireSession(c)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
		}
		sessionID, _ := c.Locals("session_id").(string)
		deviceID, _ := c.Locals("device_id").(string)
		fingerprintMatch := security.VerifySessionFingerprint(session.Metadata, currentFingerprint(c))
		expiresAt := session.CreatedAt.Add(session.SessionTTL)
		if session.SessionTTL <= 0 {
			expiresAt = session.CreatedAt.Add(crypto.SessionTimeout)
		}
		return c.JSON(fiber.Map{
			"status":              200,
			"success":             true,
			"message":             "Session state inspected",
			"session_id":          sessionID,
			"device_id":           deviceID,
			"issued_at":           session.CreatedAt,
			"last_activity":       session.LastUsed,
			"expires_at":          expiresAt,
			"fingerprint_matches": fingerprintMatch,
			"metadata_keys":       len(session.Metadata),
		})
	}
}

func handlePentestProbe(auditLogger security.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req pentestRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid pentest payload"})
		}
		sessionID, _ := c.Locals("session_id").(string)
		deviceID, _ := c.Locals("device_id").(string)
		userCtx, _ := c.Locals("user_context").(*security.UserContext)
		auditLogger.Record(security.AuditEvent{
			Type:      security.AuditEventPentestProbe,
			SessionID: sessionID,
			DeviceID:  deviceID,
			UserID:    userID(userCtx),
			Detail:    fmt.Sprintf("vector=%s payload_keys=%d", req.Vector, len(req.Payload)),
			Timestamp: time.Now(),
		})
		return c.JSON(fiber.Map{
			"status":       200,
			"success":      true,
			"message":      "Pentest probe recorded",
			"vector":       req.Vector,
			"notes":        req.Notes,
			"payload_keys": len(req.Payload),
		})
	}
}

func handleLogout(sessionManager *crypto.SessionManager, auditLogger security.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if sessionManager == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "session manager unavailable"})
		}
		session, err := requireSession(c)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
		}
		sessionID, _ := c.Locals("session_id").(string)
		deviceID, _ := c.Locals("device_id").(string)
		userCtx, _ := c.Locals("user_context").(*security.UserContext)
		sessionManager.DeleteSession(sessionID)
		if auditLogger != nil {
			auditLogger.Record(security.AuditEvent{
				Type:      security.AuditEventLogout,
				SessionID: sessionID,
				DeviceID:  deviceID,
				UserID:    userID(userCtx),
				Detail:    "session terminated via API",
				Timestamp: time.Now(),
			})
		}
		return c.JSON(fiber.Map{
			"status":         200,
			"success":        true,
			"message":        "Session terminated",
			"session_id":     sessionID,
			"device_id":      deviceID,
			"issued_at":      session.CreatedAt,
			"terminated_at":  time.Now(),
			"lifetime_secs":  time.Since(session.CreatedAt).Seconds(),
			"fingerprint_ok": security.VerifySessionFingerprint(session.Metadata, currentFingerprint(c)),
		})
	}
}

func securityEnvelope(c *fiber.Ctx) fiber.Map {
	payload := fiber.Map{}
	if deviceID, ok := c.Locals("device_id").(string); ok && deviceID != "" {
		payload["device_id"] = deviceID
	}
	if userCtx, ok := c.Locals("user_context").(*security.UserContext); ok && userCtx != nil {
		payload["user_id"] = userCtx.ID
		if len(userCtx.Roles) > 0 {
			payload["roles"] = userCtx.Roles
		}
	}
	return payload
}

func sessionDescriptor(c *fiber.Ctx) fiber.Map {
	session, err := requireSession(c)
	if err != nil {
		return fiber.Map{"error": err.Error()}
	}
	sessionID, _ := c.Locals("session_id").(string)
	return fiber.Map{
		"id":         sessionID,
		"issued_at":  session.CreatedAt,
		"last_used":  session.LastUsed,
		"expires_in": session.SessionTTL - time.Since(session.CreatedAt),
	}
}

func decryptedBody(c *fiber.Ctx) ([]byte, error) {
	raw, ok := c.Locals("decrypted_body").([]byte)
	if !ok {
		return nil, errors.New("secure payload missing")
	}
	if len(raw) == 0 {
		return nil, errors.New("secure payload empty")
	}
	return raw, nil
}

func requireSession(c *fiber.Ctx) (*crypto.Session, error) {
	session, ok := c.Locals("session").(*crypto.Session)
	if !ok || session == nil {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func ensureStaticBundle(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat static dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	required := []string{"index.html"}
	for _, file := range required {
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			return fmt.Errorf("missing %s in %s: %w", file, root, err)
		}
	}
	warnIfMissing(filepath.Join(root, "securefetch.wasm"))
	warnIfMissing(filepath.Join(root, "wasm_exec.js"))
	return nil
}

func warnIfMissing(path string) {
	if _, err := os.Stat(path); err != nil {
		log.Printf("⚠️  optional asset missing: %s (%v)", path, err)
	}
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "/demo"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if len(prefix) > 1 && strings.HasSuffix(prefix, "/") {
		prefix = strings.TrimSuffix(prefix, "/")
	}
	return prefix
}

func defaultConfigPath() string {
	if val := os.Getenv("SECURE_HTTP_CONFIG"); val != "" {
		return val
	}
	return "config/server.json"
}

func currentFingerprint(c *fiber.Ctx) string {
	if c == nil {
		return ""
	}
	return security.ComputeSessionFingerprint(c.IP(), string(c.Context().UserAgent()))
}

func userID(ctx *security.UserContext) string {
	if ctx == nil {
		return ""
	}
	return ctx.ID
}
