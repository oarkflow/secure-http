package serversdk

import (
	"testing"

	"github.com/oarkflow/securehttp/pkg/config"
)

func TestBuildManifestIncludesNormalizedDefaults(t *testing.T) {
	cfg := &config.ServerConfig{
		Runtime: config.RuntimeConfig{Mode: "dev"},
		Auth: config.AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
		},
		Gate: config.GateConfig{},
		Capabilities: []config.CapabilityDefinition{{
			Token:   "cap-root",
			Paths:   []string{"/handshake", "/api/*"},
			Methods: []string{"POST"},
		}},
	}

	manifest := BuildManifest(cfg, ManifestOptions{
		BaseURL:        "https://api.example.com",
		BootstrapPath:  "/auth/bootstrap",
		HandshakePath:  "/handshake",
		IncludeSecrets: false,
	})
	if manifest == nil {
		t.Fatalf("BuildManifest() returned nil")
	}
	if manifest.Auth.SessionCookie.Name != "securehttp_access" {
		t.Fatalf("session cookie name = %q", manifest.Auth.SessionCookie.Name)
	}
	if manifest.Auth.CSRF.HeaderName != "X-CSRF-Token" {
		t.Fatalf("csrf header name = %q", manifest.Auth.CSRF.HeaderName)
	}
	if manifest.Headers.Gate.SecretID != "X-Gate-Key" {
		t.Fatalf("gate secret header = %q", manifest.Headers.Gate.SecretID)
	}
	if manifest.BootstrapPath != "/auth/bootstrap" {
		t.Fatalf("bootstrap path = %q", manifest.BootstrapPath)
	}
	if len(manifest.Gate.Secrets) != 0 {
		t.Fatalf("expected secrets to be omitted")
	}
	if len(manifest.Capabilities) != 1 || manifest.Capabilities[0].Token != "cap-root" {
		t.Fatalf("capabilities = %#v", manifest.Capabilities)
	}
}
