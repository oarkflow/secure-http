package stdlib

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	clientpkg "github.com/oarkflow/securehttp/pkg/http/client"
	"github.com/oarkflow/securehttp/pkg/security"
)

func TestStdlibMiddlewareHandshakeAndEncryptedRequest(t *testing.T) {
	deviceRegistry := security.NewInMemoryDeviceRegistry()
	if err := deviceRegistry.Register("device-1", []byte("device-secret-1")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	userAuth := security.NewStaticUserAuthenticator()
	userAuth.Register("user-token-1", &security.UserContext{ID: "user-1", Roles: []string{"admin"}})

	transport, err := New(&security.SecurityPolicy{
		RequireDevice:     true,
		RequireUser:       true,
		DeviceRegistry:    deviceRegistry,
		UserAuthenticator: userAuth,
		SessionTTL:        time.Minute,
		MessageTTL:        time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	capStore := security.NewMemoryCapabilityStore()
	capStore.Register(security.Capability{
		Token: "cap-root",
		Rules: []security.CapabilityRule{
			{Path: "/handshake", Methods: map[string]struct{}{http.MethodPost: {}}},
			{Path: "/api/echo", Methods: map[string]struct{}{http.MethodPost: {}}},
		},
	})
	gate, err := security.NewGatekeeper(security.GatekeeperConfig{
		Secrets: []security.RotatingSecret{{
			ID:     "gate-1",
			Secret: []byte("gate-secret-1"),
		}},
		CapabilityStore: capStore,
		AllowedOrigins:  []string{"http://localhost"},
	})
	if err != nil {
		t.Fatalf("NewGatekeeper() error = %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/handshake", GateMiddleware(gate)(transport.HandshakeHandler()))
	mux.Handle("/api/echo", GateMiddleware(gate)(transport.Secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := PlaintextBodyFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{
			"echo":    string(body),
			"device":  DeviceIDFromContext(r.Context()),
			"user_id": UserContextFromContext(r.Context()).ID,
		})
	}))))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()

	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()

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
		Echo   string `json:"echo"`
		Device string `json:"device"`
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.Echo == "" {
		t.Fatalf("expected echoed response body")
	}
	if response.Device != "device-1" {
		t.Fatalf("device = %q, want %q", response.Device, "device-1")
	}
	if response.UserID != "user-1" {
		t.Fatalf("user_id = %q, want %q", response.UserID, "user-1")
	}
}
