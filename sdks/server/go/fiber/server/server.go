package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
	httpmw "github.com/oarkflow/securehttp/sdks/server/go/fiber/middleware"
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

type uploadPolicy struct {
	Directory      string
	MaxBytes       int
	MaxFiles       int
	AllowedTypes   map[string]struct{}
	AllowDownloads bool
	AllowListing   bool
}

// Dependencies exposes the initialized security stack for reuse.
type Dependencies struct {
	Config            *config.ServerConfig
	AuditLogger       security.AuditLogger
	SessionManager    *crypto.SessionManager
	CryptoMiddleware  *httpmw.CryptoMiddleware
	Gatekeeper        *security.Gatekeeper
	Authenticator     *security.StatelessAuthenticator
	DeviceRegistry    security.DeviceRegistry
	UserAuthenticator security.UserAuthenticator
}

// Options controls how the reusable server is assembled.
type Options struct {
	Config               *config.ServerConfig
	ListenAddr           string
	WebRoot              string
	StaticPrefix         string
	EnableStatic         bool
	EnableDemoRoutes     bool
	RequireAccessToken   bool
	RegisterAPIRoutes    func(fiber.Router, Dependencies)
	RegisterPublicRoutes func(fiber.Router, Dependencies)
}

// Server wraps the Fiber app plus initialized dependencies.
type Server struct {
	app        *fiber.App
	api        fiber.Router
	deps       Dependencies
	listenAddr string
	closeOnce  sync.Once
	cleanup    func()
}

type AuthSession struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
}

// NewFromFile loads the config file and builds a reusable server.
func NewFromFile(path string, opts Options) (*Server, error) {
	runtime, err := NewRuntimeFromFile(path, RuntimeOptions{
		ListenAddr: opts.ListenAddr,
	})
	if err != nil {
		return nil, err
	}
	return newServerFromRuntime(runtime, opts)
}

// New builds a reusable server app from an in-memory config.
func New(opts Options) (*Server, error) {
	runtime, err := NewRuntime(RuntimeOptions{
		Config:     opts.Config,
		ListenAddr: opts.ListenAddr,
	})
	if err != nil {
		return nil, err
	}
	return newServerFromRuntime(runtime, opts)
}

func newServerFromRuntime(runtime *Runtime, opts Options) (*Server, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is not initialized")
	}
	app := fiber.New(DefaultFiberConfig())
	mounted, err := runtime.Mount(app, mountOptionsFromOptions(opts))
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}

	return &Server{
		app:        app,
		api:        mounted.API,
		deps:       runtime.Dependencies(),
		listenAddr: runtime.ListenAddr(),
		cleanup: func() {
			_ = runtime.Close()
		},
	}, nil
}

func mountOptionsFromOptions(opts Options) MountOptions {
	return MountOptions{
		WebRoot:              opts.WebRoot,
		StaticPrefix:         opts.StaticPrefix,
		EnableStatic:         opts.EnableStatic,
		EnableDemoRoutes:     opts.EnableDemoRoutes,
		RequireAccessToken:   opts.RequireAccessToken,
		RegisterAPIRoutes:    opts.RegisterAPIRoutes,
		RegisterPublicRoutes: opts.RegisterPublicRoutes,
	}
}

// App returns the underlying Fiber app.
func (s *Server) App() *fiber.App {
	if s == nil {
		return nil
	}
	return s.app
}

// API returns the secured /api router.
func (s *Server) API() fiber.Router {
	if s == nil {
		return nil
	}
	return s.api
}

// Dependencies returns initialized security dependencies.
func (s *Server) Dependencies() Dependencies {
	if s == nil {
		return Dependencies{}
	}
	return s.deps
}

// Listen starts the Fiber app on the configured or overridden address.
func (s *Server) Listen(addr string) error {
	if s == nil || s.app == nil {
		return fmt.Errorf("server is not initialized")
	}
	if strings.TrimSpace(addr) == "" {
		addr = s.listenAddr
	}
	return s.app.Listen(addr)
}

// Close shuts down the app and runs cleanup hooks once.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var shutdownErr error
	s.closeOnce.Do(func() {
		if s.app != nil {
			shutdownErr = s.app.Shutdown()
		}
		if s.cleanup != nil {
			s.cleanup()
		}
	})
	return shutdownErr
}

func registerDemoRoutes(api fiber.Router, deps Dependencies, uploads uploadPolicy) {
	api.Get("/echo", handleEcho())
	api.Post("/echo", handleEcho())
	api.Put("/echo", handleEcho())
	api.Delete("/echo", handleEcho())
	api.Patch("/echo", handleEcho())

	api.Post("/user/info", handleUserInfo())
	api.Post("/resource/create", handleResourceCreate())
	api.Post("/login", handleSecureLogin(deps.AuditLogger))
	api.Post("/session/state", handleSessionState())
	api.Post("/pentest/probe", handlePentestProbe(deps.AuditLogger))
	api.Post("/logout", handleLogout(deps.SessionManager, deps.AuditLogger, deps.Config.Auth))
	api.Post("/upload", handleFileUpload(deps.AuditLogger, uploads))
	api.Get("/files", handleListFiles(uploads))
	api.Get("/files/:filename", handleDownloadFile(uploads))
	api.Get("/protected", handleProtected())
	api.Get("/assets/:filename", handleSecureAsset(deps.AuditLogger))
}

func registerStaticRoutes(app *fiber.App, prefix string, webRoot string) {
	app.Get(prefix+"*", static.New("", static.Config{
		FS:            os.DirFS(webRoot),
		Compress:      true,
		Browse:        false,
		IndexNames:    []string{"index.html"},
		CacheDuration: 30 * time.Minute,
		MaxAge:        600,
	}))
	app.Get("/", func(c fiber.Ctx) error {
		target := prefix
		if !strings.HasSuffix(target, "/") {
			target += "/"
		}
		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(target)
	})
}

func newUploadPolicy(cfg config.UploadConfig) uploadPolicy {
	policy := uploadPolicy{
		Directory:      cfg.Directory,
		MaxBytes:       cfg.MaxBytes,
		MaxFiles:       cfg.MaxFiles,
		AllowedTypes:   make(map[string]struct{}, len(cfg.AllowedTypes)),
		AllowDownloads: cfg.AllowDownloads,
		AllowListing:   cfg.AllowListing,
	}
	for _, item := range cfg.AllowedTypes {
		trimmed := strings.TrimSpace(strings.ToLower(item))
		if trimmed != "" {
			policy.AllowedTypes[trimmed] = struct{}{}
		}
	}
	return policy
}

func (p uploadPolicy) isAllowedType(contentType string) bool {
	if len(p.AllowedTypes) == 0 {
		return true
	}
	normalized := strings.ToLower(strings.TrimSpace(contentType))
	if normalized == "" {
		return false
	}
	if _, ok := p.AllowedTypes[normalized]; ok {
		return true
	}
	if idx := strings.Index(normalized, ";"); idx > 0 {
		normalized = strings.TrimSpace(normalized[:idx])
		_, ok := p.AllowedTypes[normalized]
		return ok
	}
	return false
}

func sanitizeUploadName(name string) string {
	trimmed := strings.TrimSpace(filepath.Base(name))
	if trimmed == "" || trimmed == "." || trimmed == ".." {
		return "upload.bin"
	}
	replacer := strings.NewReplacer("..", "", "/", "_", "\\", "_", " ", "_")
	safe := replacer.Replace(trimmed)
	if safe == "" {
		return "upload.bin"
	}
	return safe
}

func handleEcho() fiber.Handler {
	return func(c fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var req map[string]interface{}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				req = map[string]interface{}{"raw_data": string(body)}
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

func handleProtected() fiber.Handler {
	return func(c fiber.Ctx) error {
		userCtx := c.Locals("user")
		return c.JSON(fiber.Map{
			"success": true,
			"message": "This is a protected endpoint",
			"data": fiber.Map{
				"timestamp": time.Now().Format(time.RFC3339),
				"user":      userCtx,
				"security": fiber.Map{
					"encrypted":     true,
					"authenticated": true,
				},
			},
		})
	}
}

func handleUserInfo() fiber.Handler {
	type userRequest struct {
		Name string `json:"name"`
	}
	return func(c fiber.Ctx) error {
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
	return func(c fiber.Ctx) error {
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
	return func(c fiber.Ctx) error {
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
	return func(c fiber.Ctx) error {
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
	return func(c fiber.Ctx) error {
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

func handleLogout(sessionManager *crypto.SessionManager, auditLogger security.AuditLogger, authCfg config.AuthConfig) fiber.Handler {
	return func(c fiber.Ctx) error {
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
		ClearAuthSession(c, Dependencies{
			Config: &config.ServerConfig{
				Auth: authCfg,
			},
		})
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

func securityEnvelope(c fiber.Ctx) fiber.Map {
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

func sessionDescriptor(c fiber.Ctx) fiber.Map {
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

func decryptedBody(c fiber.Ctx) ([]byte, error) {
	raw, ok := c.Locals("decrypted_body").([]byte)
	if !ok {
		return nil, errors.New("secure payload missing")
	}
	if len(raw) == 0 {
		return nil, errors.New("secure payload empty")
	}
	return raw, nil
}

func requireSession(c fiber.Ctx) (*crypto.Session, error) {
	session, ok := c.Locals("session").(*crypto.Session)
	if !ok || session == nil {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func handleFileUpload(auditLogger security.AuditLogger, policy uploadPolicy) fiber.Handler {
	return func(c fiber.Ctx) error {
		body, err := decryptedBody(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}

		originalContentType := c.Query("_ct", "")
		if originalContentType == "" {
			originalContentType = c.Get("X-Original-Content-Type", "")
		}
		if originalContentType == "" {
			scanLen := 200
			if len(body) < scanLen {
				scanLen = len(body)
			}
			bodyStr := string(body[:scanLen])
			if strings.Contains(bodyStr, "multipart/form-data") {
				if idx := strings.Index(bodyStr, "boundary="); idx != -1 {
					boundaryStart := idx + len("boundary=")
					boundaryEnd := strings.IndexAny(bodyStr[boundaryStart:], "\r\n;")
					if boundaryEnd == -1 {
						boundaryEnd = len(bodyStr) - boundaryStart
					}
					boundary := strings.Trim(bodyStr[boundaryStart:boundaryStart+boundaryEnd], `"`)
					originalContentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
				}
			}
			if originalContentType == "" {
				if idx := bytes.Index(body, []byte("--")); idx != -1 {
					endIdx := bytes.IndexByte(body[idx+2:], '\r')
					if endIdx == -1 {
						endIdx = bytes.IndexByte(body[idx+2:], '\n')
					}
					if endIdx > 0 {
						boundary := string(body[idx+2 : idx+2+endIdx])
						originalContentType = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
					}
				}
			}
		}

		if originalContentType == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Could not determine multipart content type",
				"hint":  "Content type should be passed via query param _ct or header X-Original-Content-Type",
			})
		}

		boundary := ""
		if parts := strings.Split(originalContentType, "boundary="); len(parts) == 2 {
			boundary = strings.Trim(parts[1], `"`)
		}
		if boundary == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid multipart boundary"})
		}

		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		form, err := reader.ReadForm(32 << 20)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("Failed to parse form: %v", err)})
		}
		defer form.RemoveAll()

		fileContentType := "application/octet-stream"
		if ctValues := form.Value["__file_content_type__"]; len(ctValues) > 0 {
			fileContentType = ctValues[0]
		}

		if err := os.MkdirAll(policy.Directory, 0755); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create uploads directory"})
		}

		var fileInfo []fiber.Map
		fileCount := 0
		for fieldName, files := range form.File {
			for _, fileHeader := range files {
				fileCount++
				if policy.MaxFiles > 0 && fileCount > policy.MaxFiles {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Too many files in upload"})
				}
				file, err := fileHeader.Open()
				if err != nil {
					continue
				}
				data, _ := io.ReadAll(file)
				file.Close()
				if policy.MaxBytes > 0 && len(data) > policy.MaxBytes {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Uploaded file exceeds configured size limit"})
				}

				timestamp := time.Now().Format("20060102-150405")
				safeName := sanitizeUploadName(fileHeader.Filename)
				ext := filepath.Ext(safeName)
				baseName := strings.TrimSuffix(safeName, ext)
				uniqueFilename := fmt.Sprintf("%s-%s%s", baseName, timestamp, ext)
				filePath := filepath.Join(policy.Directory, uniqueFilename)

				if err := os.WriteFile(filePath, data, 0644); err != nil {
					log.Printf("Failed to save file %s: %v", uniqueFilename, err)
					continue
				}

				detectedType := fileContentType
				if headerType := fileHeader.Header.Get("Content-Type"); headerType != "" && headerType != "application/octet-stream" {
					detectedType = headerType
				}
				if !policy.isAllowedType(detectedType) {
					_ = os.Remove(filePath)
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Uploaded file type is not allowed"})
				}

				fileInfo = append(fileInfo, fiber.Map{
					"field":       fieldName,
					"filename":    safeName,
					"saved_as":    uniqueFilename,
					"path":        filePath,
					"size":        len(data),
					"type":        detectedType,
					"uploaded_at": time.Now().Format(time.RFC3339),
				})

				if auditLogger != nil {
					auditLogger.Record(security.AuditEvent{
						Type:      security.AuditEventPentestProbe,
						Timestamp: time.Now(),
						Detail:    fmt.Sprintf("File uploaded: %s -> %s (%d bytes)", fileHeader.Filename, uniqueFilename, len(data)),
					})
				}
			}
		}

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

func handleListFiles(policy uploadPolicy) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !policy.AllowListing {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "File listing disabled"})
		}
		if err := os.MkdirAll(policy.Directory, 0755); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to access uploads directory"})
		}

		entries, err := os.ReadDir(policy.Directory)
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
				"filename":     entry.Name(),
				"size":         info.Size(),
				"modified_at":  info.ModTime().Format(time.RFC3339),
				"download_url": fmt.Sprintf("/api/files/%s", entry.Name()),
			})
		}

		return c.JSON(fiber.Map{
			"status":  200,
			"success": true,
			"message": "Files retrieved successfully",
			"data": fiber.Map{
				"files":     files,
				"total":     len(files),
				"directory": policy.Directory,
			},
		})
	}
}

func handleDownloadFile(policy uploadPolicy) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !policy.AllowDownloads {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "File download disabled"})
		}
		filename := c.Params("filename")
		if filename == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Filename required"})
		}

		filename = filepath.Base(filename)
		filePath := filepath.Join(policy.Directory, filename)

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

		data, err := os.ReadFile(filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}

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

func handleSecureAsset(auditLogger security.AuditLogger) fiber.Handler {
	return func(c fiber.Ctx) error {
		filename := c.Params("filename")
		if filename == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Filename required"})
		}

		filename = filepath.Base(filename)
		filePath := filepath.Join("web", "wasm", "assets", filename)

		info, err := os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Asset not found"})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to access asset"})
		}
		if info.IsDir() {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid asset"})
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read asset"})
		}

		sessionID, _ := c.Locals("session_id").(string)
		deviceID, _ := c.Locals("device_id").(string)
		userCtx, _ := c.Locals("user_context").(*security.UserContext)

		if auditLogger != nil {
			auditLogger.Record(security.AuditEvent{
				Type:      security.AuditEventDecryptSuccess,
				SessionID: sessionID,
				DeviceID:  deviceID,
				UserID:    userID(userCtx),
				Detail:    fmt.Sprintf("secure asset access: %s", filename),
				Timestamp: time.Now(),
			})
		}

		var responseData interface{}
		if strings.HasSuffix(filename, ".json") {
			var jsonData interface{}
			if err := json.Unmarshal(data, &jsonData); err == nil {
				responseData = jsonData
			} else {
				responseData = string(data)
			}
		} else {
			responseData = base64.StdEncoding.EncodeToString(data)
		}

		return c.JSON(responseData)
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
	warnIfMissing(filepath.Join(root, "fetch.wasm"))
	warnIfMissing(filepath.Join(root, "wasm_exec.js"))
	return nil
}

func warnIfMissing(path string) {
	if _, err := os.Stat(path); err != nil {
		log.Printf("optional asset missing: %s (%v)", path, err)
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

func currentFingerprint(c fiber.Ctx) string {
	if c == nil {
		return ""
	}
	return security.ComputeSessionFingerprint(c.IP(), string(c.RequestCtx().UserAgent()))
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
	return func(c fiber.Ctx) error {
		var req loginReq
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
		}

		userCtx, err := userAuth.Validate(req.UserToken)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Invalid token"})
		}
		if req.UserID != "" && userCtx.ID != req.UserID {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "User ID mismatch"})
		}

		deviceID := fmt.Sprintf("%s-device", userCtx.ID)
		derivedSecret := deriveDemoDeviceSecret(deviceID)
		if err := deviceRegistry.Register(deviceID, derivedSecret); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register device"})
		}

		session, err := IssueAuthSession(c, Dependencies{
			Config:        cfg,
			Authenticator: statelessAuth,
		}, userCtx.ID, deviceID, userCtx.Roles, map[string]string{
			"user_token": req.UserToken,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate tokens"})
		}

		return c.JSON(BuildBrowserLoginResponse(cfg, session, userCtx.ID, BrowserLoginResponseOptions{
			BootstrapPath: "/bootstrap",
			HandshakePath: "/handshake",
		}))
	}
}

func handleBootstrap(deps Dependencies) fiber.Handler {
	return func(c fiber.Ctx) error {
		payload, err := BuildBrowserBootstrap(c, deps, BrowserBootstrapOptions{
			HandshakePath: "/handshake",
		})
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(payload)
	}
}

func IssueAuthSession(c fiber.Ctx, deps Dependencies, userID, deviceID string, roles []string, metadata map[string]string) (*AuthSession, error) {
	if deps.Config == nil || deps.Authenticator == nil {
		return nil, fmt.Errorf("auth dependencies are incomplete")
	}
	csrfToken, err := randomCSRFToken(24)
	if err != nil {
		return nil, err
	}
	enriched := cloneStringMap(metadata)
	enriched["csrf_token"] = csrfToken
	accessToken, refreshToken, err := deps.Authenticator.GenerateTokenPairWithMetadata(
		userID,
		deviceID,
		roles,
		currentFingerprint(c),
		enriched,
	)
	if err != nil {
		return nil, err
	}
	setSessionCookie(c, deps.Config.Auth.SessionCookie, accessToken, deps.Authenticator)
	setCSRFCookie(c, deps.Config.Auth.CSRF, csrfToken)
	return &AuthSession{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
	}, nil
}

func ClearAuthSession(c fiber.Ctx, deps Dependencies) {
	if deps.Config == nil {
		return
	}
	clearSessionCookie(c, deps.Config.Auth.SessionCookie)
	clearCSRFCookie(c, deps.Config.Auth.CSRF)
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return make(map[string]string, 1)
	}
	dst := make(map[string]string, len(src)+1)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func randomCSRFToken(size int) (string, error) {
	if size < 16 {
		size = 16
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setSessionCookie(c fiber.Ctx, cfg config.SessionCookieConfig, accessToken string, auth *security.StatelessAuthenticator) {
	if c == nil || !cfg.Enabled || strings.TrimSpace(accessToken) == "" {
		return
	}
	expiresAt := time.Now().Add(15 * time.Minute)
	if claims, err := auth.ValidateToken(accessToken, "access", currentFingerprint(c)); err == nil && claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}
	c.Cookie(&fiber.Cookie{
		Name:     cfg.Name,
		Value:    accessToken,
		Path:     cookiePath(cfg.Path),
		Domain:   strings.TrimSpace(cfg.Domain),
		HTTPOnly: cfg.HTTPOnly,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
		Expires:  expiresAt,
	})
}

func setCSRFCookie(c fiber.Ctx, cfg config.CSRFConfig, token string) {
	if c == nil || !cfg.Enabled || strings.TrimSpace(token) == "" {
		return
	}
	c.Cookie(&fiber.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Path:     cookiePath(cfg.Path),
		Domain:   strings.TrimSpace(cfg.Domain),
		HTTPOnly: false,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
	})
}

func clearSessionCookie(c fiber.Ctx, cfg config.SessionCookieConfig) {
	if c == nil || !cfg.Enabled {
		return
	}
	c.Cookie(&fiber.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cookiePath(cfg.Path),
		Domain:   strings.TrimSpace(cfg.Domain),
		HTTPOnly: cfg.HTTPOnly,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func clearCSRFCookie(c fiber.Ctx, cfg config.CSRFConfig) {
	if c == nil || !cfg.Enabled {
		return
	}
	c.Cookie(&fiber.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     cookiePath(cfg.Path),
		Domain:   strings.TrimSpace(cfg.Domain),
		HTTPOnly: false,
		Secure:   cfg.Secure,
		SameSite: parseSameSite(cfg.SameSite),
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func cookiePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	return path
}

func parseSameSite(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strict":
		return "Strict"
	case "none":
		return "None"
	default:
		return "Lax"
	}
}

// fiber:context-methods migrated
