package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
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

	// Initialize stateless authenticator
	authKey := []byte(cfg.Auth.JWTSigningKey) // Use key from config
	if len(authKey) == 0 {
		// Fallback to a default key for development (should be in config for production)
		authKey = []byte("your-secure-256-bit-secret-key-minimum-32-chars")
		log.Println("⚠️  Using default JWT signing key - set jwt_signing_key in config for production")
	}
	statelessAuth, err := security.NewStatelessAuthenticator(security.StatelessAuthConfig{
		SigningKey:       authKey,
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  7 * 24 * time.Hour,
		Algorithm:        "HS512",
		Issuer:           "secure-http-server",
		Audience:         "secure-http-api",
	})
	if err != nil {
		log.Fatalf("initialize stateless auth: %v", err)
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
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3010,http://localhost:8080",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Gate-Time,X-Gate-Sign,X-Gate-Purpose,X-Gate-Seq",
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	prefix := normalizePrefix(*staticPrefix)
	// Mount the entire web directory at the root to ensure cross-module imports work
	// e.g. /demo/app.js can import from /client/src/index.js
	app.Static("/", "web", fiber.Static{
		Compress:      true,
		Browse:        true,
		Index:         "index.html",
		CacheDuration: 30 * time.Minute,
		MaxAge:        600,
	})

	// Also keep the demo prefix static for backward compatibility if needed,
	// but mapping to the specific demo folder.
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

	// JWT middleware for protected routes
	jwtMiddleware := httpmw.NewStatelessAuthMiddleware(statelessAuth)

	// Apply GateMiddleware only to routes that require gate tokens
	app.Post("/handshake", gateMiddleware.Handle(), cryptoMiddleware.Handshake())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":   "healthy",
			"sessions": cryptoMiddleware.GetSessionManager().SessionCount(),
		})
	})

	api := app.Group("/api")
	api.Use(gateMiddleware.Handle()) // Gate applies to all encrypted APIs
	api.Use(jwtMiddleware.Verify())  // JWT auth for all API routes
	api.Use(cryptoMiddleware.Decrypt())
	api.Use(cryptoMiddleware.Encrypt())

	app.Post("/login", handleLogon(cfg, userAuth, deviceRegistry, statelessAuth))

	registerSecureRoutes(api, auditLogger, cryptoMiddleware.GetSessionManager())

	log.Printf("🧪 Full-stack secure demo available on %s", listenAddr)
	log.Printf("   • Static lab: http://localhost%s%s/", listenAddr, prefix)
	log.Printf("   • Handshake + encrypted APIs continue to require gate headers")
	log.Fatal(app.Listen(listenAddr))
}

func registerSecureRoutes(api fiber.Router, auditLogger security.AuditLogger, sessionManager *crypto.SessionManager) {
	// Support all HTTP methods
	api.Get("/echo", handleEcho())
	api.Post("/echo", handleEcho())
	api.Put("/echo", handleEcho())
	api.Delete("/echo", handleEcho())
	api.Patch("/echo", handleEcho())

	api.Post("/user/info", handleUserInfo())
	api.Post("/resource/create", handleResourceCreate())
	api.Post("/login", handleSecureLogin(auditLogger))
	api.Post("/session/state", handleSessionState())
	api.Post("/pentest/probe", handlePentestProbe(auditLogger))
	api.Post("/logout", handleLogout(sessionManager, auditLogger))
	api.Post("/upload", handleFileUpload(auditLogger))
	api.Get("/files", handleListFiles())
	api.Get("/files/:filename", handleDownloadFile())

}

func handleEcho() fiber.Handler {
	return func(c *fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req map[string]interface{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				// Not JSON, treat as raw data
				req = map[string]interface{}{
					"raw_data": string(body),
				}
			}
		} else {
			req = map[string]interface{}{}
		}
		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "Echo response",
			"method":  c.Method(),
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

func handleFileUpload(auditLogger security.AuditLogger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get decrypted multipart body
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		// Get original content type from header
		originalContentType := c.Get("X-Original-Content-Type", "")
		if originalContentType == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing original content type"})
		}

		// Parse multipart form from decrypted body
		boundary := ""
		if parts := strings.Split(originalContentType, "boundary="); len(parts) == 2 {
			boundary = strings.Trim(parts[1], `"`)
		}
		if boundary == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid multipart boundary"})
		}

		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		form, err := reader.ReadForm(32 << 20) // 32 MB max
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Failed to parse form: %v", err)})
		}
		defer form.RemoveAll()

		// Create uploads directory if it doesn't exist
		uploadsDir := "uploads"
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create uploads directory"})
		}

		// Extract file info and save files
		var fileInfo []fiber.Map
		for fieldName, files := range form.File {
			for _, fileHeader := range files {
				file, err := fileHeader.Open()
				if err != nil {
					continue
				}
				data, _ := io.ReadAll(file)
				file.Close()

				// Generate unique filename with timestamp
				timestamp := time.Now().Format("20060102-150405")
				ext := filepath.Ext(fileHeader.Filename)
				baseName := strings.TrimSuffix(fileHeader.Filename, ext)
				uniqueFilename := fmt.Sprintf("%s-%s%s", baseName, timestamp, ext)
				filePath := filepath.Join(uploadsDir, uniqueFilename)

				// Save file to disk
				if err := os.WriteFile(filePath, data, 0644); err != nil {
					log.Printf("Failed to save file %s: %v", uniqueFilename, err)
					continue
				}

				fileInfo = append(fileInfo, fiber.Map{
					"field":         fieldName,
					"filename":      fileHeader.Filename,
					"saved_as":      uniqueFilename,
					"path":          filePath,
					"size":          len(data),
					"type":          fileHeader.Header.Get("Content-Type"),
					"uploaded_at":   time.Now().Format(time.RFC3339),
				})

				// Log file upload
				if auditLogger != nil {
					auditLogger.Record(security.AuditEvent{
						Type:      security.AuditEventPentestProbe,
						Timestamp: time.Now(),
						Detail:    fmt.Sprintf("File uploaded: %s -> %s (%d bytes)", fileHeader.Filename, uniqueFilename, len(data)),
					})
				}
			}
		}

		// Extract form values
		formValues := make(map[string][]string)
		for key, values := range form.Value {
			formValues[key] = values
		}

		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "File upload successful",
			"data": fiber.Map{
				"files":        fileInfo,
				"form_values":  formValues,
				"processed_at": time.Now(),
				"security":     securityEnvelope(c),
			},
		})
	}
}

func handleListFiles() fiber.Handler {
	return func(c *fiber.Ctx) error {
		uploadsDir := "uploads"

		// Create directory if it doesn't exist
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to access uploads directory"})
		}

		// Read directory contents
		entries, err := os.ReadDir(uploadsDir)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read uploads directory"})
		}

		var files []fiber.Map
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			files = append(files, fiber.Map{
				"filename":    entry.Name(),
				"size":        info.Size(),
				"modified_at": info.ModTime().Format(time.RFC3339),
				"download_url": fmt.Sprintf("/api/files/%s", entry.Name()),
			})
		}

		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "Files retrieved successfully",
			"data": fiber.Map{
				"files":        files,
				"total":        len(files),
				"directory":    uploadsDir,
			},
		})
	}
}

func handleDownloadFile() fiber.Handler {
	return func(c *fiber.Ctx) error {
		filename := c.Params("filename")
		if filename == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Filename required"})
		}

		// Sanitize filename to prevent directory traversal
		filename = filepath.Base(filename)
		filePath := filepath.Join("uploads", filename)

		// Check if file exists
		info, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "File not found"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to access file"})
		}

		if info.IsDir() {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid file"})
		}

		// Read file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}

		// Return file info and content (encrypted in response)
		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "File retrieved successfully",
			"data": fiber.Map{
				"filename":    filename,
				"size":        len(data),
				"content":     base64.StdEncoding.EncodeToString(data),
				"modified_at": info.ModTime().Format(time.RFC3339),
			},
		})
	}
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

func handleLogon(cfg *config.ServerConfig, userAuth security.UserAuthenticator, deviceRegistry security.DeviceRegistry, statelessAuth *security.StatelessAuthenticator) fiber.Handler {
	type loginReq struct {
		UserID    string `json:"user_id"`
		UserToken string `json:"user_token"`
	}
	return func(c *fiber.Ctx) error {
		var req loginReq
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Validate user token
		userCtx, err := userAuth.Validate(req.UserToken)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid token"})
		}

		if req.UserID != "" && userCtx.ID != req.UserID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "User ID mismatch"})
		}

		// Calculate device secret based on user token for "natural" derivation
		// For demo: hmac(token, "device-key")
		h := hmac.New(sha256.New, []byte("demo-device-derivation-key"))
		h.Write([]byte(req.UserToken))
		derivedSecret := h.Sum(nil)

		deviceID := fmt.Sprintf("%s-device", userCtx.ID)

		// Map it into the registry so the Handshake middleware can find it later
		if err := deviceRegistry.Register(deviceID, derivedSecret); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register device"})
		}

		gateSecrets := make([]fiber.Map, 0)
		for _, s := range cfg.Gate.Secrets {
			gateSecrets = append(gateSecrets, fiber.Map{
				"id":     s.ID,
				"secret": s.Material,
			})
		}

		var capabilityToken string
		if len(cfg.Capabilities) > 0 {
			capabilityToken = cfg.Capabilities[0].Token
		}

		// Generate JWT access and refresh tokens
		accessToken, refreshToken, err := statelessAuth.GenerateTokenPair(
			userCtx.ID,
			deviceID,
			userCtx.Roles,
			"", // fingerprint - could be extracted from request headers
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate tokens"})
		}

		return c.JSON(fiber.Map{
			"status":   200,
			"success":  true,
			"deviceID": deviceID,
			// Return as base64: prefixed string for the JS client
			"deviceSecret":    "base64:" + base64.StdEncoding.EncodeToString(derivedSecret),
			"gateSecrets":     gateSecrets,
			"capabilityToken": capabilityToken,
			"handshakePath":   "/handshake",
			"baseURL":         "",
			"userToken":       req.UserToken,
			"userID":          userCtx.ID,
			"accessToken":     accessToken,
			"refreshToken":    refreshToken,
		})
	}
}
