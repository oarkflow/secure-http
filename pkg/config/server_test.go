package config

import "testing"

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
