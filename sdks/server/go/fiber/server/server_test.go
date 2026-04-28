package server

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/config"
	clientpkg "github.com/oarkflow/securehttp/pkg/http/client"
	"github.com/oarkflow/securehttp/pkg/security"
)

func TestSanitizeUploadName(t *testing.T) {
	got := sanitizeUploadName("../unsafe name.txt")
	if got != "unsafe_name.txt" {
		t.Fatalf("sanitizeUploadName() = %q", got)
	}
}

func TestUploadPolicyAllowedType(t *testing.T) {
	policy := uploadPolicy{
		AllowedTypes: map[string]struct{}{
			"application/json": {},
		},
	}
	if !policy.isAllowedType("application/json; charset=utf-8") {
		t.Fatalf("expected content type to be allowed")
	}
	if policy.isAllowedType("text/html") {
		t.Fatalf("expected content type to be rejected")
	}
}

func TestHandleListFilesRespectsPolicy(t *testing.T) {
	app := fiber.New()
	app.Get("/files", handleListFiles(uploadPolicy{AllowListing: false}))

	req := httptest.NewRequest("GET", "/files", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusForbidden)
	}
}

func TestNewServerReusableAPI(t *testing.T) {
	cfg := &config.ServerConfig{
		ListenAddr: ":0",
		Runtime:    config.RuntimeConfig{Mode: "dev"},
		Auth: config.AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
			JWTSigningKey: "test-signing-key",
		},
		Gate: config.GateConfig{
			Headers: security.GateHeaders{},
			Secrets: []config.SecretDefinition{
				{ID: "gate-1", Material: "gate-secret-1"},
			},
			AllowedOrigins: []string{"http://localhost"},
		},
		Capabilities: []config.CapabilityDefinition{
			{
				Token:   "cap-root",
				Paths:   []string{"/handshake", "/api/echo"},
				Methods: []string{"POST"},
			},
		},
		Devices: []config.DeviceDefinition{
			{ID: "device-1", Secret: "device-secret-1"},
		},
		Users: []config.UserDefinition{
			{ID: "user-1", Token: "user-token-1", Roles: []string{"admin"}},
		},
	}

	srv, err := New(Options{
		Config: cfg,
		RegisterAPIRoutes: func(api fiber.Router, deps Dependencies) {
			api.Post("/echo", func(c *fiber.Ctx) error {
				body, _ := c.Locals("decrypted_body").([]byte)
				return c.JSON(fiber.Map{"echo": string(body)})
			})
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer srv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()
	go func() { _ = srv.App().Listener(ln) }()

	client, err := clientpkg.NewSecureClient(clientpkg.Config{
		BaseURL:      "http://" + ln.Addr().String(),
		DeviceID:     "device-1",
		DeviceSecret: []byte("device-secret-1"),
		UserToken:    "user-token-1",
		Gate: clientpkg.GateClientConfig{
			Secrets:         []clientpkg.GateSecret{{ID: "gate-1", Secret: []byte("gate-secret-1")}},
			CapabilityToken: "cap-root",
		},
	})
	if err != nil {
		t.Fatalf("NewSecureClient() error = %v", err)
	}

	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}

	responseBody, err := client.Post("/api/echo", map[string]string{"message": "hello"})
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}

	var response struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Echo == "" {
		t.Fatalf("expected echoed response body")
	}
}

func TestRuntimeMountReusableAPI(t *testing.T) {
	cfg := &config.ServerConfig{
		ListenAddr: ":0",
		Runtime:    config.RuntimeConfig{Mode: "dev"},
		Auth: config.AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
			JWTSigningKey: "test-signing-key",
		},
		Gate: config.GateConfig{
			Headers: security.GateHeaders{},
			Secrets: []config.SecretDefinition{
				{ID: "gate-1", Material: "gate-secret-1"},
			},
			AllowedOrigins: []string{"http://localhost"},
		},
		Capabilities: []config.CapabilityDefinition{
			{
				Token:   "cap-root",
				Paths:   []string{"/handshake", "/api/echo"},
				Methods: []string{"POST"},
			},
		},
		Devices: []config.DeviceDefinition{
			{ID: "device-1", Secret: "device-secret-1"},
		},
		Users: []config.UserDefinition{
			{ID: "user-1", Token: "user-token-1", Roles: []string{"admin"}},
		},
	}

	runtime, err := NewRuntime(RuntimeOptions{Config: cfg})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	app := fiber.New(DefaultFiberConfig())
	_, err = runtime.Mount(app, MountOptions{
		RegisterAPIRoutes: func(api fiber.Router, deps Dependencies) {
			api.Post("/echo", func(c *fiber.Ctx) error {
				body, _ := c.Locals("decrypted_body").([]byte)
				return c.JSON(fiber.Map{"echo": string(body)})
			})
		},
	})
	if err != nil {
		t.Fatalf("runtime.Mount() error = %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()
	go func() { _ = app.Listener(ln) }()

	client, err := clientpkg.NewSecureClient(clientpkg.Config{
		BaseURL:      "http://" + ln.Addr().String(),
		DeviceID:     "device-1",
		DeviceSecret: []byte("device-secret-1"),
		UserToken:    "user-token-1",
		Gate: clientpkg.GateClientConfig{
			Secrets:         []clientpkg.GateSecret{{ID: "gate-1", Secret: []byte("gate-secret-1")}},
			CapabilityToken: "cap-root",
		},
	})
	if err != nil {
		t.Fatalf("NewSecureClient() error = %v", err)
	}

	if err := client.Handshake(); err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}

	responseBody, err := client.Post("/api/echo", map[string]string{"message": "hello"})
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}

	var response struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Echo == "" {
		t.Fatalf("expected echoed response body")
	}
}
