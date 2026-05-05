package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oarkflow/secure-http/pkg/security"
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
			JWTSigningKey: "strict-jwt-signing-key-32-bytes-ok",
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
				Material: "strict-gate-secret-material-32-ok",
			}},
		},
		Devices: []DeviceDefinition{{
			ID:     "device-1",
			Secret: "strict-device-secret-material-32-ok",
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
			JWTSigningKey: "strict-jwt-signing-key-32-bytes-ok",
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
				Material: "strict-gate-secret-material-32-ok",
			}},
		},
		Devices: []DeviceDefinition{{
			ID:     "device-1",
			Secret: "strict-device-secret-material-32-ok",
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
	setProductionConfigEnv(t)
	cfg, err := LoadServerConfig(filepath.Join("..", "..", "config.production.json"))
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if !cfg.IsStrictMode() {
		t.Fatalf("expected production config to run in strict mode")
	}
}

func TestLoadProductionConfigTemplateRequiresEnvSecrets(t *testing.T) {
	t.Setenv("SECURE_HTTP_JWT_SIGNING_KEY", "")
	if _, err := LoadServerConfig(filepath.Join("..", "..", "config.production.json")); err == nil {
		t.Fatalf("LoadServerConfig() expected missing env secret error")
	}
}

func TestLoadServerConfigResolvesEnvSecrets(t *testing.T) {
	t.Setenv("SECURE_HTTP_TEST_JWT", "strict-jwt-signing-key-32-bytes-ok")
	t.Setenv("SECURE_HTTP_TEST_GATE", "strict-gate-secret-material-32-ok")
	t.Setenv("SECURE_HTTP_TEST_DEVICE", "strict-device-secret-material-32-ok")
	cfg := &ServerConfig{
		Runtime: RuntimeConfig{Mode: "strict"},
		Auth: AuthConfig{
			RequireDevice: true,
			RequireUser:   true,
			JWTSigningKey: "env:SECURE_HTTP_TEST_JWT",
			SessionCookie: SessionCookieConfig{Enabled: true, HTTPOnly: true, Secure: true},
			CSRF:          CSRFConfig{Enabled: true, Secure: true},
		},
		Gate: GateConfig{
			StrictOrigin:   true,
			AllowedOrigins: []string{"https://app.example.com"},
			Secrets: []SecretDefinition{{
				ID:       "2026-Q2",
				Material: "env:SECURE_HTTP_TEST_GATE",
			}},
		},
		Devices: []DeviceDefinition{{ID: "device-1", Secret: "env:SECURE_HTTP_TEST_DEVICE"}},
	}
	cfg.normalize()
	if err := cfg.resolveSecrets(); err != nil {
		t.Fatalf("resolveSecrets() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.Auth.JWTSigningKey != "strict-jwt-signing-key-32-bytes-ok" {
		t.Fatalf("JWTSigningKey was not resolved")
	}
}

func setProductionConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SECURE_HTTP_JWT_SIGNING_KEY", "strict-jwt-signing-key-32-bytes-ok")
	t.Setenv("SECURE_HTTP_GATE_SECRET_Q2", "strict-gate-secret-material-32-ok")
	t.Setenv("SECURE_HTTP_TODO_CAPABILITY_TOKEN", "strict-capability-token-32-bytes")
	t.Setenv("SECURE_HTTP_SEED_DEVICE_SECRET", "strict-device-secret-material-32-ok")
	t.Setenv("SECURE_HTTP_USER_TOKEN_ALICE", "strict-user-token-alice-32-bytes")
	t.Setenv("SECURE_HTTP_USER_TOKEN_BOB", "strict-user-token-bob-32-bytes-ok")
}
