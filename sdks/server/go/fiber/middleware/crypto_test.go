package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	clientpkg "github.com/oarkflow/securehttp/pkg/http/client"
	"github.com/oarkflow/securehttp/pkg/security"
)

func TestCryptoMiddlewareHandshakeAndEncryptedRequest(t *testing.T) {
	deviceRegistry := security.NewInMemoryDeviceRegistry()
	if err := deviceRegistry.Register("device-1", []byte("device-secret-1")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	userAuth := security.NewStaticUserAuthenticator()
	userAuth.Register("user-token-1", &security.UserContext{ID: "user-1", Roles: []string{"admin"}})

	cm, err := NewCryptoMiddleware(&security.SecurityPolicy{
		RequireDevice:     true,
		RequireUser:       true,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
		SessionTTL:        time.Minute,
		MessageTTL:        time.Minute,
	})
	if err != nil {
		t.Fatalf("NewCryptoMiddleware() error = %v", err)
	}

	app := fiber.New()
	app.Post("/handshake", cm.Handshake())
	api := app.Group("/api")
	api.Use(cm.Decrypt())
	api.Use(cm.Encrypt())
	api.Post("/echo", func(c *fiber.Ctx) error {
		body, _ := c.Locals("decrypted_body").([]byte)
		return c.JSON(fiber.Map{"echo": string(body)})
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()
	go func() { _ = app.Listener(ln) }()
	defer app.Shutdown()

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

func TestStatelessAuthMiddlewareAcceptsCookie(t *testing.T) {
	auth, err := security.NewStatelessAuthenticator(security.StatelessAuthConfig{
		SigningKey:         []byte("01234567890123456789012345678901"),
		Issuer:             "issuer",
		Audience:           "aud",
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		Algorithm:          "HS512",
		RequireFingerprint: false,
	})
	if err != nil {
		t.Fatalf("NewStatelessAuthenticator() error = %v", err)
	}

	accessToken, _, err := auth.GenerateTokenPair("user-1", "device-1", []string{"admin"}, "")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	app := fiber.New()
	sam := NewStatelessAuthMiddlewareWithConfig(auth, StatelessAuthConfig{CookieName: "securehttp_access"})
	app.Get("/protected", sam.Verify(), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"user_id": c.Locals("user_id")})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "securehttp_access", Value: accessToken})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusOK)
	}
}

func TestCSRFMiddlewareRejectsCookieAuthWithoutHeader(t *testing.T) {
	app := fiber.New()
	csrf := NewCSRFMiddleware(CSRFConfig{
		Enabled:    true,
		CookieName: "securehttp_csrf",
		HeaderName: "X-CSRF-Token",
	})
	app.Post("/protected", func(c *fiber.Ctx) error {
		c.Locals("auth_source", "cookie")
		c.Locals("token_claims", &security.StatelessTokenClaims{
			Metadata: map[string]string{"csrf_token": "csrf-1"},
		})
		return c.Next()
	}, csrf.Verify(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("POST", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "securehttp_csrf", Value: "csrf-1"})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNotFound)
	}
}

func TestOpaqueAuthFailurePreservesExistingCORSHeaders(t *testing.T) {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderAccessControlAllowOrigin, "http://localhost:5173")
		c.Set(fiber.HeaderAccessControlAllowCredentials, "true")
		return c.Next()
	})
	auth, err := security.NewStatelessAuthenticator(security.StatelessAuthConfig{
		SigningKey:         []byte("01234567890123456789012345678901"),
		Issuer:             "issuer",
		Audience:           "aud",
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		Algorithm:          "HS512",
		RequireFingerprint: false,
	})
	if err != nil {
		t.Fatalf("NewStatelessAuthenticator() error = %v", err)
	}
	sam := NewStatelessAuthMiddleware(auth)
	app.Post("/auth/bootstrap", sam.Verify(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/bootstrap", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNotFound)
	}
	if got := resp.Header.Get(fiber.HeaderAccessControlAllowOrigin); got != "http://localhost:5173" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := resp.Header.Get(fiber.HeaderAccessControlAllowCredentials); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
}

func TestStatelessAuthMiddlewareRejectsMissingTokenWithOpaqueNotFound(t *testing.T) {
	auth, err := security.NewStatelessAuthenticator(security.StatelessAuthConfig{
		SigningKey:         []byte("01234567890123456789012345678901"),
		Issuer:             "issuer",
		Audience:           "aud",
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		Algorithm:          "HS512",
		RequireFingerprint: false,
	})
	if err != nil {
		t.Fatalf("NewStatelessAuthenticator() error = %v", err)
	}

	app := fiber.New()
	sam := NewStatelessAuthMiddleware(auth)
	app.Get("/protected", sam.Verify(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, fiber.StatusNotFound)
	}
}
