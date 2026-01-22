package security

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token expired")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrInvalidIssuer    = errors.New("invalid token issuer")
	ErrTokenRevoked     = errors.New("token revoked")
)

// StatelessTokenClaims represents the payload of a stateless JWT token
type StatelessTokenClaims struct {
	// Standard claims
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	TokenID   string `json:"jti"`

	// Custom claims
	UserID      string            `json:"user_id"`
	DeviceID    string            `json:"device_id"`
	Roles       []string          `json:"roles"`
	Permissions []string          `json:"permissions"`
	Metadata    map[string]string `json:"metadata,omitempty"`

	// Security
	ClientFingerprint string `json:"client_fp"` // Browser fingerprint
	TokenType         string `json:"token_type"` // "access" or "refresh"
}

// StatelessAuthConfig configures the stateless authentication system
type StatelessAuthConfig struct {
	SigningKey        []byte        // HMAC signing key or Ed25519 private key
	VerifyingKey      []byte        // Ed25519 public key (optional, for Ed25519)
	Issuer            string        // Token issuer identifier
	Audience          string        // Expected audience
	AccessTokenTTL    time.Duration // Access token lifetime
	RefreshTokenTTL   time.Duration // Refresh token lifetime
	Algorithm         string        // "HS256", "HS512", or "Ed25519"
	AllowedOrigins    []string      // Allowed request origins
	RequireFingerprint bool         // Require client fingerprint validation
}

// StatelessAuthenticator provides stateless JWT-based authentication
type StatelessAuthenticator struct {
	config     StatelessAuthConfig
	revokedIDs map[string]int64 // Token ID -> revocation timestamp
	revokedMu  syncMap
}

type syncMap struct {
	mu sync.RWMutex
	m  map[string]int64
}

// NewStatelessAuthenticator creates a new stateless authenticator
func NewStatelessAuthenticator(config StatelessAuthConfig) (*StatelessAuthenticator, error) {
	if len(config.SigningKey) == 0 {
		return nil, errors.New("signing key required")
	}

	if config.Issuer == "" {
		config.Issuer = "secure-http"
	}

	if config.Audience == "" {
		config.Audience = "secure-http-api"
	}

	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 15 * time.Minute
	}

	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7 * 24 * time.Hour
	}

	if config.Algorithm == "" {
		config.Algorithm = "HS512"
	}

	return &StatelessAuthenticator{
		config: config,
		revokedIDs: make(map[string]int64),
	}, nil
}

// GenerateTokenPair creates both access and refresh tokens
func (sa *StatelessAuthenticator) GenerateTokenPair(userID, deviceID string, roles []string, fingerprint string) (accessToken, refreshToken string, err error) {
	now := time.Now()

	// Generate access token
	accessClaims := StatelessTokenClaims{
		Issuer:            sa.config.Issuer,
		Subject:           userID,
		Audience:          sa.config.Audience,
		ExpiresAt:         now.Add(sa.config.AccessTokenTTL).Unix(),
		IssuedAt:          now.Unix(),
		NotBefore:         now.Unix(),
		TokenID:           generateTokenID(),
		UserID:            userID,
		DeviceID:          deviceID,
		Roles:             roles,
		ClientFingerprint: fingerprint,
		TokenType:         "access",
	}

	accessToken, err = sa.createToken(accessClaims)
	if err != nil {
		return "", "", fmt.Errorf("create access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := StatelessTokenClaims{
		Issuer:            sa.config.Issuer,
		Subject:           userID,
		Audience:          sa.config.Audience,
		ExpiresAt:         now.Add(sa.config.RefreshTokenTTL).Unix(),
		IssuedAt:          now.Unix(),
		NotBefore:         now.Unix(),
		TokenID:           generateTokenID(),
		UserID:            userID,
		DeviceID:          deviceID,
		Roles:             roles,
		ClientFingerprint: fingerprint,
		TokenType:         "refresh",
	}

	refreshToken, err = sa.createToken(refreshClaims)
	if err != nil {
		return "", "", fmt.Errorf("create refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// ValidateToken validates and parses a JWT token
func (sa *StatelessAuthenticator) ValidateToken(token string, expectedType string, currentFingerprint string) (*StatelessTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode header and payload
	_, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	if !sa.verifySignature([]byte(message), signatureBytes) {
		return nil, ErrInvalidSignature
	}

	// Parse claims
	var claims StatelessTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Validate claims
	now := time.Now().Unix()

	if claims.ExpiresAt < now {
		return nil, ErrExpiredToken
	}

	if claims.NotBefore > now {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != sa.config.Issuer {
		return nil, ErrInvalidIssuer
	}

	if claims.Audience != sa.config.Audience {
		return nil, ErrInvalidToken
	}

	if expectedType != "" && claims.TokenType != expectedType {
		return nil, fmt.Errorf("expected %s token, got %s", expectedType, claims.TokenType)
	}

	// Check if token is revoked
	if sa.isRevoked(claims.TokenID) {
		return nil, ErrTokenRevoked
	}

	// Validate fingerprint if required
	if sa.config.RequireFingerprint && claims.ClientFingerprint != "" {
		if currentFingerprint != claims.ClientFingerprint {
			return nil, errors.New("client fingerprint mismatch")
		}
	}

	return &claims, nil
}

// RevokeToken adds a token to the revocation list
func (sa *StatelessAuthenticator) RevokeToken(tokenID string) {
	sa.revokedMu.mu.Lock()
	defer sa.revokedMu.mu.Unlock()
	sa.revokedIDs[tokenID] = time.Now().Unix()
}

// RefreshAccessToken creates a new access token from a valid refresh token
func (sa *StatelessAuthenticator) RefreshAccessToken(refreshToken string, currentFingerprint string) (string, error) {
	claims, err := sa.ValidateToken(refreshToken, "refresh", currentFingerprint)
	if err != nil {
		return "", err
	}

	// Generate new access token with same user/device info
	accessToken, _, err := sa.GenerateTokenPair(claims.UserID, claims.DeviceID, claims.Roles, currentFingerprint)
	return accessToken, err
}

// createToken creates and signs a JWT token
func (sa *StatelessAuthenticator) createToken(claims StatelessTokenClaims) (string, error) {
	// Create header
	header := map[string]string{
		"alg": sa.config.Algorithm,
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Encode header and payload
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	message := encodedHeader + "." + encodedPayload

	// Sign
	signature := sa.sign([]byte(message))
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + encodedSignature, nil
}

// sign creates a signature for the message
func (sa *StatelessAuthenticator) sign(message []byte) []byte {
	switch sa.config.Algorithm {
	case "Ed25519":
		// Use Ed25519 signature
		privateKey := ed25519.PrivateKey(sa.config.SigningKey)
		return ed25519.Sign(privateKey, message)

	case "HS256":
		h := hmac.New(sha256.New, sa.config.SigningKey)
		h.Write(message)
		return h.Sum(nil)

	case "HS512":
		fallthrough
	default:
		h := hmac.New(sha512.New512_256, sa.config.SigningKey)
		h.Write(message)
		return h.Sum(nil)
	}
}

// verifySignature verifies a signature
func (sa *StatelessAuthenticator) verifySignature(message, signature []byte) bool {
	switch sa.config.Algorithm {
	case "Ed25519":
		publicKey := ed25519.PublicKey(sa.config.VerifyingKey)
		return ed25519.Verify(publicKey, message, signature)

	case "HS256", "HS512":
		expected := sa.sign(message)
		return hmac.Equal(signature, expected)

	default:
		return false
	}
}

// isRevoked checks if a token ID is revoked
func (sa *StatelessAuthenticator) isRevoked(tokenID string) bool {
	sa.revokedMu.mu.RLock()
	defer sa.revokedMu.mu.RUnlock()
	_, revoked := sa.revokedIDs[tokenID]
	return revoked
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// CleanupRevokedTokens removes expired tokens from revocation list
func (sa *StatelessAuthenticator) CleanupRevokedTokens() {
	sa.revokedMu.mu.Lock()
	defer sa.revokedMu.mu.Unlock()

	cutoff := time.Now().Add(-sa.config.RefreshTokenTTL).Unix()
	for id, timestamp := range sa.revokedIDs {
		if timestamp < cutoff {
			delete(sa.revokedIDs, id)
		}
	}
}
