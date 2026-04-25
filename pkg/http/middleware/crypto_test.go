package middleware

import (
	"encoding/json"
	"net"
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
