package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/oarkflow/securehttp/pkg/security"
	httpmw "github.com/oarkflow/securehttp/sdks/server/go/fiber/middleware"
	httpserver "github.com/oarkflow/securehttp/sdks/server/go/fiber/server"
)

type account struct {
	Username     string
	UserID       string
	Password     string
	PasswordHash []byte
	UserToken    string
	Roles        []string
}

type todo struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	Done             bool      `json:"done"`
	ImageDataURL     string    `json:"image_data_url,omitempty"`
	ImageContentType string    `json:"image_content_type,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type todoStore struct {
	mu    sync.RWMutex
	items map[string]map[string]todo
}

func newTodoStore() *todoStore {
	return &todoStore{items: make(map[string]map[string]todo)}
}

func (s *todoStore) list(userID string) []todo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	owned := s.items[userID]
	out := make([]todo, 0, len(owned))
	for _, item := range owned {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *todoStore) put(userID string, item todo) todo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[userID] == nil {
		s.items[userID] = make(map[string]todo)
	}
	s.items[userID][item.ID] = item
	return item
}

func (s *todoStore) get(userID, id string) (todo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.items[userID][id]
	return item, ok
}

func (s *todoStore) delete(userID, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items[userID] == nil {
		return false
	}
	if _, ok := s.items[userID][id]; !ok {
		return false
	}
	delete(s.items[userID], id)
	return true
}

func main() {
	configPath := flag.String("config", defaultConfigPath(), "Path to sample server config")
	addr := flag.String("addr", "", "Override listen address")
	webRoot := flag.String("web", "", "Static asset directory for the React frontend (optional)")
	staticPrefix := flag.String("static-prefix", "/", "URL prefix that serves the React frontend")
	flag.Parse()

	accounts, err := seedAccounts()
	if err != nil {
		log.Fatalf("seed accounts: %v", err)
	}
	todos := newTodoStore()

	srv, err := httpserver.NewFromFile(*configPath, httpserver.Options{
		ListenAddr:         *addr,
		WebRoot:            *webRoot,
		StaticPrefix:       *staticPrefix,
		EnableStatic:       strings.TrimSpace(*webRoot) != "",
		RequireAccessToken: true,
		RegisterPublicRoutes: func(app fiber.Router, deps httpserver.Dependencies) {
			registerAuthRoutes(app, deps, accounts)
		},
		RegisterAPIRoutes: func(api fiber.Router, deps httpserver.Dependencies) {
			registerTodoRoutes(api, deps, todos)
		},
	})
	if err != nil {
		log.Fatalf("build todo sample server: %v", err)
	}
	defer srv.Close()

	if strings.TrimSpace(*webRoot) != "" {
		log.Printf("Todo password sample listening on %s (frontend at %s)", serverAddr(*addr, srv), displayStaticPrefix(*staticPrefix))
	} else {
		log.Printf("Todo password sample listening on %s", serverAddr(*addr, srv))
	}
	log.Fatal(srv.Listen(""))
}

func displayStaticPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "/" {
		return "/"
	}
	return strings.TrimSuffix(prefix, "/")
}

func serverAddr(override string, srv *httpserver.Server) string {
	if strings.TrimSpace(override) != "" {
		return override
	}
	if srv == nil {
		return ""
	}
	return srv.Dependencies().Config.ListenAddr
}

func browserBaseURL(c *fiber.Ctx, listenAddr string) string {
	if c != nil {
		if forwardedProto := strings.TrimSpace(c.Get("X-Forwarded-Proto")); forwardedProto != "" {
			if forwardedHost := strings.TrimSpace(c.Get("X-Forwarded-Host")); forwardedHost != "" {
				return forwardedProto + "://" + forwardedHost
			}
		}
	}

	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		if c != nil {
			return c.BaseURL()
		}
		return ""
	}
	if strings.Contains(listenAddr, "://") {
		return listenAddr
	}

	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
		port = ""
	}

	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}

	if port != "" {
		return "http://" + net.JoinHostPort(host, port)
	}
	return "http://" + host
}

func registerAuthRoutes(app fiber.Router, deps httpserver.Dependencies, accounts map[string]account) {
	jwt := httpmw.NewStatelessAuthMiddlewareWithConfig(deps.Authenticator, httpmw.StatelessAuthConfig{
		CookieName: deps.Config.Auth.SessionCookie.Name,
	})
	csrf := httpmw.NewCSRFMiddleware(httpmw.CSRFConfig{
		Enabled:    deps.Config.Auth.CSRF.Enabled,
		CookieName: deps.Config.Auth.CSRF.CookieName,
		HeaderName: deps.Config.Auth.CSRF.HeaderName,
	})

	app.Post("/auth/login", func(c *fiber.Ctx) error {
		var req struct {
			Username   string `json:"username"`
			UserID     string `json:"user_id"`
			Login      string `json:"login"`
			Identifier string `json:"identifier"`
			Password   string `json:"password"`
			UserToken  string `json:"user_token"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
		}

		identifier := strings.ToLower(strings.TrimSpace(req.Username))
		if identifier == "" {
			identifier = strings.ToLower(strings.TrimSpace(req.UserID))
		}
		if identifier == "" {
			identifier = strings.ToLower(strings.TrimSpace(req.Login))
		}
		if identifier == "" {
			identifier = strings.ToLower(strings.TrimSpace(req.Identifier))
		}
		if identifier == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}
		password := req.Password
		if strings.TrimSpace(password) == "" {
			password = req.UserToken
		}
		password = strings.TrimSpace(password)
		if password == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

		acc, ok := accounts[identifier]
		if !ok {
			for _, candidate := range accounts {
				if strings.EqualFold(candidate.UserID, identifier) {
					acc = candidate
					ok = true
					break
				}
			}
		}
		passwordMatches := ok && (password == acc.Password ||
			password == acc.UserToken ||
			bcrypt.CompareHashAndPassword(acc.PasswordHash, []byte(password)) == nil)
		if !passwordMatches {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}

		deviceID := fmt.Sprintf("%s-device", acc.UserID)
		deviceSecret := deriveDeviceSecret(deviceID)
		if err := deps.DeviceRegistry.Register(deviceID, deviceSecret); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to register device"})
		}

		session, err := httpserver.IssueAuthSession(c, deps, acc.UserID, deviceID, acc.Roles, map[string]string{
			"user_token": acc.UserToken,
			"username":   acc.Username,
		})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "failed to issue auth session"})
		}

		return c.JSON(httpserver.BuildBrowserLoginResponse(deps.Config, session, acc.UserID, httpserver.BrowserLoginResponseOptions{
			BaseURL:       browserBaseURL(c, deps.Config.ListenAddr),
			BootstrapPath: "/auth/bootstrap",
			HandshakePath: "/handshake",
		}))
	})

	app.Post("/auth/bootstrap", jwt.Verify(), csrf.Verify(), func(c *fiber.Ctx) error {
		payload, err := httpserver.BuildBrowserBootstrap(c, deps, httpserver.BrowserBootstrapOptions{
			BaseURL:       browserBaseURL(c, deps.Config.ListenAddr),
			HandshakePath: "/handshake",
			RestoreDevice: func(c *fiber.Ctx, deps httpserver.Dependencies, deviceID string) error {
				return deps.DeviceRegistry.Register(deviceID, deriveDeviceSecret(deviceID))
			},
			ResolveDeviceSecret: func(c *fiber.Ctx, deps httpserver.Dependencies, deviceID string) (string, error) {
				return "base64:" + base64.StdEncoding.EncodeToString(deriveDeviceSecret(deviceID)), nil
			},
		})
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(payload)
	})

	app.Post("/auth/logout", jwt.Verify(), csrf.Verify(), func(c *fiber.Ctx) error {
		httpserver.ClearAuthSession(c, deps)
		return c.JSON(fiber.Map{"success": true})
	})
}

func registerTodoRoutes(api fiber.Router, _ httpserver.Dependencies, store *todoStore) {
	api.Get("/todos", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"items": store.list(currentUser(c))})
	})

	api.Post("/todos", func(c *fiber.Ctx) error {
		var req struct {
			Title            string `json:"title"`
			Description      string `json:"description"`
			ImageDataURL     string `json:"image_data_url"`
			ImageContentType string `json:"image_content_type"`
		}
		if err := decodeEncryptedJSON(c, &req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		imageDataURL, imageContentType, err := normalizeTodoImage(req.ImageDataURL, req.ImageContentType)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		now := time.Now()
		item := todo{
			ID:               fmt.Sprintf("todo-%d", now.UnixNano()),
			Title:            strings.TrimSpace(req.Title),
			Description:      strings.TrimSpace(req.Description),
			ImageDataURL:     imageDataURL,
			ImageContentType: imageContentType,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if item.Title == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "title is required"})
		}
		return c.JSON(store.put(currentUser(c), item))
	})

	api.Put("/todos/:id", func(c *fiber.Ctx) error {
		var req struct {
			Title            string `json:"title"`
			Description      string `json:"description"`
			Done             bool   `json:"done"`
			ImageDataURL     string `json:"image_data_url"`
			ImageContentType string `json:"image_content_type"`
		}
		if err := decodeEncryptedJSON(c, &req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		imageDataURL, imageContentType, err := normalizeTodoImage(req.ImageDataURL, req.ImageContentType)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		userID := currentUser(c)
		item, ok := store.get(userID, c.Params("id"))
		if !ok {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "todo not found"})
		}
		item.Title = strings.TrimSpace(req.Title)
		item.Description = strings.TrimSpace(req.Description)
		item.Done = req.Done
		item.ImageDataURL = imageDataURL
		item.ImageContentType = imageContentType
		item.UpdatedAt = time.Now()
		return c.JSON(store.put(userID, item))
	})

	api.Delete("/todos/:id", func(c *fiber.Ctx) error {
		if !store.delete(currentUser(c), c.Params("id")) {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "todo not found"})
		}
		return c.JSON(fiber.Map{"success": true})
	})
}

func decodeEncryptedJSON(c *fiber.Ctx, out any) error {
	body, _ := c.Locals("decrypted_body").([]byte)
	if len(body) == 0 {
		return fmt.Errorf("missing request body")
	}
	return json.Unmarshal(body, out)
}

func currentUser(c *fiber.Ctx) string {
	userCtx, _ := c.Locals("user_context").(*security.UserContext)
	if userCtx == nil {
		return ""
	}
	return userCtx.ID
}

func normalizeTodoImage(dataURL, contentType string) (string, string, error) {
	dataURL = strings.TrimSpace(dataURL)
	contentType = strings.TrimSpace(contentType)
	if dataURL == "" {
		return "", "", nil
	}
	if !strings.HasPrefix(dataURL, "data:") {
		return "", "", fmt.Errorf("image must be a data URL")
	}
	if !strings.Contains(dataURL, ";base64,") {
		return "", "", fmt.Errorf("image must be base64 encoded")
	}
	parts := strings.SplitN(dataURL, ",", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("image data is invalid")
	}
	meta := parts[0]
	if contentType == "" {
		contentType = strings.TrimPrefix(strings.SplitN(strings.TrimPrefix(meta, "data:"), ";", 2)[0], " ")
	}
	switch contentType {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
	default:
		return "", "", fmt.Errorf("unsupported image type")
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("image data is invalid")
	}
	if len(decoded) > 2*1024*1024 {
		return "", "", fmt.Errorf("image must be 2MB or smaller")
	}
	return dataURL, contentType, nil
}

func seedAccounts() (map[string]account, error) {
	type seed struct {
		Username  string
		UserID    string
		Password  string
		UserToken string
		Roles     []string
	}
	seeds := []seed{
		{Username: "alice", UserID: "todo-alice", Password: "alice-password", UserToken: "todo-user-token-alice", Roles: []string{"todo-user"}},
		{Username: "bob", UserID: "todo-bob", Password: "bob-password", UserToken: "todo-user-token-bob", Roles: []string{"todo-user"}},
	}
	accounts := make(map[string]account, len(seeds))
	for _, item := range seeds {
		hash, err := bcrypt.GenerateFromPassword([]byte(item.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		acc := account{
			Username:     item.Username,
			UserID:       item.UserID,
			Password:     item.Password,
			PasswordHash: hash,
			UserToken:    item.UserToken,
			Roles:        item.Roles,
		}
		accounts[strings.ToLower(item.Username)] = acc
		accounts[strings.ToLower(item.UserID)] = acc
	}
	return accounts, nil
}

func deriveDeviceSecret(deviceID string) []byte {
	h := hmac.New(sha256.New, []byte("todo-password-sample-device-secret"))
	h.Write([]byte(deviceID))
	return h.Sum(nil)
}

func defaultConfigPath() string {
	if val := os.Getenv("SECURE_HTTP_TODO_CONFIG"); val != "" {
		return val
	}
	return "config.dev.json"
}
