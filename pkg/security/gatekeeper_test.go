package security

import (
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestGatekeeperEvaluate(t *testing.T) {
	now := time.Now()
	secret := []byte("gate-secret-material")
	store := NewMemoryCapabilityStore()
	store.Register(Capability{
		Token: "cap-root",
		Rules: []CapabilityRule{{Path: "/api/*", Methods: map[string]struct{}{"POST": {}}}},
	})

	newRequest := func() GateRequest {
		timestamp := time.Now().Unix()
		nonce := "nonce-1"
		signature := base64.StdEncoding.EncodeToString(computeGateMAC(secret, "POST", "/api/echo", "123", nonce, "cap-root"))
		_ = timestamp
		return GateRequest{
			Method: "POST",
			Path:   "/api/echo",
			Headers: map[string]string{
				"Origin":             "http://localhost:8443",
				"X-Gate-Key":         "active",
				"X-Gate-Timestamp":   "123",
				"X-Gate-Nonce":       nonce,
				"X-Gate-Signature":   signature,
				"X-Capability-Token": "cap-root",
			},
			RemoteAddr: "127.0.0.1",
		}
	}

	buildSignedRequest := func(timestamp string, nonce string) GateRequest {
		req := newRequest()
		req.Headers["X-Gate-Timestamp"] = timestamp
		req.Headers["X-Gate-Nonce"] = nonce
		req.Headers["X-Gate-Signature"] = base64.StdEncoding.EncodeToString(
			computeGateMAC(secret, req.Method, req.Path, timestamp, nonce, "cap-root"),
		)
		return req
	}

	activeSecret := RotatingSecret{
		ID:        "active",
		Secret:    secret,
		NotBefore: now.Add(-time.Hour),
		ExpiresAt: now.Add(time.Hour),
	}

	t.Run("allows valid request", func(t *testing.T) {
		ts := time.Now().Unix()
		gate, err := NewGatekeeper(GatekeeperConfig{
			Secrets:         []RotatingSecret{activeSecret},
			CapabilityStore: store,
			AllowedOrigins:  []string{"http://localhost:8443"},
			StrictOrigin:    true,
			MaxClockSkew:    time.Minute,
		})
		if err != nil {
			t.Fatalf("NewGatekeeper() error = %v", err)
		}
		req := buildSignedRequest(int64ToString(ts), "nonce-valid")
		if _, err := gate.Evaluate(req); err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
	})

	t.Run("rejects nonce replay", func(t *testing.T) {
		ts := time.Now().Unix()
		gate, err := NewGatekeeper(GatekeeperConfig{
			Secrets:         []RotatingSecret{activeSecret},
			CapabilityStore: store,
			AllowedOrigins:  []string{"http://localhost:8443"},
			StrictOrigin:    true,
			MaxClockSkew:    time.Minute,
		})
		if err != nil {
			t.Fatalf("NewGatekeeper() error = %v", err)
		}
		req := buildSignedRequest(int64ToString(ts), "nonce-replay")
		if _, err := gate.Evaluate(req); err != nil {
			t.Fatalf("first Evaluate() error = %v", err)
		}
		if _, err := gate.Evaluate(req); !errors.Is(err, ErrGateNonceReplayed) {
			t.Fatalf("second Evaluate() error = %v, want %v", err, ErrGateNonceReplayed)
		}
	})

	t.Run("rejects invalid origin", func(t *testing.T) {
		ts := time.Now().Unix()
		gate, err := NewGatekeeper(GatekeeperConfig{
			Secrets:         []RotatingSecret{activeSecret},
			CapabilityStore: store,
			AllowedOrigins:  []string{"http://localhost:8443"},
			StrictOrigin:    true,
			MaxClockSkew:    time.Minute,
		})
		if err != nil {
			t.Fatalf("NewGatekeeper() error = %v", err)
		}
		req := buildSignedRequest(int64ToString(ts), "nonce-origin")
		req.Headers["Origin"] = "http://evil.example"
		if _, err := gate.Evaluate(req); !errors.Is(err, ErrOriginNotAllowed) {
			t.Fatalf("Evaluate() error = %v, want %v", err, ErrOriginNotAllowed)
		}
	})

	t.Run("rejects inactive secret", func(t *testing.T) {
		gate, err := NewGatekeeper(GatekeeperConfig{
			Secrets: []RotatingSecret{{
				ID:        "inactive",
				Secret:    secret,
				NotBefore: now.Add(time.Hour),
				ExpiresAt: now.Add(2 * time.Hour),
			}},
			CapabilityStore: store,
			MaxClockSkew:    2 * time.Hour,
		})
		if err != nil {
			t.Fatalf("NewGatekeeper() error = %v", err)
		}
		req := GateRequest{
			Method: "POST",
			Path:   "/api/echo",
			Headers: map[string]string{
				"X-Gate-Key":         "inactive",
				"X-Gate-Timestamp":   int64ToString(time.Now().Unix()),
				"X-Gate-Nonce":       "nonce-inactive",
				"X-Capability-Token": "cap-root",
			},
		}
		req.Headers["X-Gate-Signature"] = base64.StdEncoding.EncodeToString(
			computeGateMAC(secret, req.Method, req.Path, req.Headers["X-Gate-Timestamp"], req.Headers["X-Gate-Nonce"], "cap-root"),
		)
		if _, err := gate.Evaluate(req); !errors.Is(err, ErrGateSecretExpired) {
			t.Fatalf("Evaluate() error = %v, want %v", err, ErrGateSecretExpired)
		}
	})
}

func int64ToString(value int64) string {
	return strconv.FormatInt(value, 10)
}
