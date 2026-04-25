package client

import (
	"testing"
	"time"
)

func TestSelectActiveGateSecret(t *testing.T) {
	now := time.Now()
	secrets := []GateSecret{
		{
			ID:        "old",
			Secret:    []byte("old-secret"),
			NotBefore: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(time.Hour),
		},
		{
			ID:        "current",
			Secret:    []byte("current-secret"),
			NotBefore: now.Add(-time.Hour),
			ExpiresAt: now.Add(2 * time.Hour),
		},
		{
			ID:        "future",
			Secret:    []byte("future-secret"),
			NotBefore: now.Add(time.Hour),
			ExpiresAt: now.Add(3 * time.Hour),
		},
	}

	selected, err := selectActiveGateSecret(secrets, now)
	if err != nil {
		t.Fatalf("selectActiveGateSecret() error = %v", err)
	}
	if selected.ID != "current" {
		t.Fatalf("selectActiveGateSecret() id = %s, want current", selected.ID)
	}
}

func TestSelectActiveGateSecretReturnsErrorWhenNoneActive(t *testing.T) {
	_, err := selectActiveGateSecret([]GateSecret{{
		ID:        "expired",
		Secret:    []byte("expired-secret"),
		NotBefore: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}}, time.Now())
	if err == nil {
		t.Fatalf("selectActiveGateSecret() expected error")
	}
}
