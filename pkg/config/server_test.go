package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/securehttp/pkg/security"
)

func TestServerConfigValidateStrictModeRejectsPlaceholders(t *testing.T) {
	cfg := &ServerConfig{
		Runtime: RuntimeConfig{Mode: "strict"},
		Auth:    AuthConfig{JWTSigningKey: "your-secure-256-bit-secret-key-minimum-32-chars-for-production"},
		Gate: GateConfig{
			AllowedOrigins: []string{"http://localhost:8443"},
			Secrets: []SecretDefinition{{
				ID:       "2026-Q2",
				Material: "base64:cHJvZHVjdGlvbi1nYXRlLXNlY3JldA==",
			}},
		},
		Devices: []DeviceDefinition{{
			ID:     "device-1",
			Secret: "base64:ZGV2aWNlLXNlY3JldC0x",
		}},
	}
	cfg.normalize()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() expected strict-mode placeholder error")
	}
}

func TestServerConfigValidateDemoModeAllowsPlaceholders(t *testing.T) {
	cfg := &ServerConfig{
		Runtime: RuntimeConfig{Mode: "demo"},
		Auth:    AuthConfig{JWTSigningKey: "your-secure-256-bit-secret-key-minimum-32-chars-for-production"},
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestServerConfigValidateStrictModeRequiresSecureCookieSettings(t *testing.T) {
	cfg := &ServerConfig{
		Runtime: RuntimeConfig{Mode: "strict"},
		Auth: AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
			JWTSigningKey: "replace-with-real-32-byte-signing-key",
			SessionCookie: SessionCookieConfig{
				Enabled:  true,
				Name:     "securehttp_access",
				Path:     "/",
				HTTPOnly: true,
				Secure:   false,
				SameSite: "lax",
			},
			CSRF: CSRFConfig{
				Enabled:    true,
				CookieName: "securehttp_csrf",
				HeaderName: "X-CSRF-Token",
				Path:       "/",
				Secure:     false,
				SameSite:   "lax",
			},
		},
		Gate: GateConfig{
			StrictOrigin:   false,
			AllowedOrigins: []string{"https://app.example.com"},
			Secrets: []SecretDefinition{{
				ID:       "2026-Q2",
				Material: "base64:cHJvZHVjdGlvbi1nYXRlLXNlY3JldA==",
			}},
		},
		Devices: []DeviceDefinition{{
			ID:     "device-1",
			Secret: "base64:ZGV2aWNlLXNlY3JldC0x",
		}},
	}
	cfg.normalize()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() expected strict-mode cookie/origin hardening error")
	}
}

func TestServerConfigValidateStrictModeAcceptsSecureCookieSettings(t *testing.T) {
	cfg := &ServerConfig{
		Runtime: RuntimeConfig{Mode: "strict"},
		Auth: AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
			JWTSigningKey: "replace-with-real-32-byte-signing-key",
			SessionCookie: SessionCookieConfig{
				Enabled:  true,
				Name:     "securehttp_access",
				Path:     "/",
				HTTPOnly: true,
				Secure:   true,
				SameSite: "lax",
			},
			CSRF: CSRFConfig{
				Enabled:    true,
				CookieName: "securehttp_csrf",
				HeaderName: "X-CSRF-Token",
				Path:       "/",
				Secure:     true,
				SameSite:   "lax",
			},
		},
		Gate: GateConfig{
			StrictOrigin:   true,
			AllowedOrigins: []string{"https://app.example.com"},
			Secrets: []SecretDefinition{{
				ID:       "2026-Q2",
				Material: "base64:cHJvZHVjdGlvbi1nYXRlLXNlY3JldA==",
			}},
		},
		Devices: []DeviceDefinition{{
			ID:     "device-1",
			Secret: "base64:ZGV2aWNlLXNlY3JldC0x",
		}},
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestBuildAuditLoggerUsesDefaultFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	defer os.Chdir(wd)
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}

	cfg := &ServerConfig{}
	logger, cleanup, err := cfg.BuildAuditLogger()
	if err != nil {
		t.Fatalf("BuildAuditLogger() error = %v", err)
	}

	logger.Record(security.AuditEvent{
		Type:      security.AuditEventHandshakeSuccess,
		Detail:    "test-event",
		Timestamp: time.Now(),
	})
	cleanup()

	logPath := filepath.Join(tmpDir, "storage", "logs", "audit.log")
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v", logPath, err)
	}
	if info.Size() == 0 {
		t.Fatalf("audit log file is empty")
	}
}

func TestLoadProductionConfigTemplatePassesStrictValidation(t *testing.T) {
	cfg, err := LoadServerConfig(filepath.Join("..", "..", "config.production.json"))
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if !cfg.IsStrictMode() {
		t.Fatalf("expected production config to run in strict mode")
	}
}
