package security

import (
	"errors"
	"testing"
	"time"
)

func TestStatelessAuthenticatorLifecycle(t *testing.T) {
	auth, err := NewStatelessAuthenticator(StatelessAuthConfig{
		SigningKey:         []byte("01234567890123456789012345678901"),
		Issuer:             "issuer",
		Audience:           "aud",
		AccessTokenTTL:     time.Minute,
		RefreshTokenTTL:    time.Hour,
		Algorithm:          "HS512",
		RequireFingerprint: true,
	})
	if err != nil {
		t.Fatalf("NewStatelessAuthenticator() error = %v", err)
	}

	accessToken, refreshToken, err := auth.GenerateTokenPair("user-1", "device-1", []string{"admin"}, "fp-1")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}

	claims, err := auth.ValidateToken(accessToken, "access", "fp-1")
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims.UserID != "user-1" || claims.DeviceID != "device-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	if _, err := auth.ValidateToken(accessToken, "access", "wrong-fp"); err == nil {
		t.Fatalf("ValidateToken() expected fingerprint error")
	}

	newAccessToken, err := auth.RefreshAccessToken(refreshToken, "fp-1")
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}
	if newAccessToken == accessToken {
		t.Fatalf("RefreshAccessToken() returned original token")
	}

	auth.RevokeToken(claims.TokenID)
	if _, err := auth.ValidateToken(accessToken, "access", "fp-1"); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("ValidateToken() after revoke error = %v, want %v", err, ErrTokenRevoked)
	}
}
