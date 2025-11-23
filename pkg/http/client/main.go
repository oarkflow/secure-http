package client

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
)

const (
	headerSessionID = "X-Session-ID"
	headerUserToken = "X-User-Token"
)

// SecureClient handles encrypted communication with the server
type SecureClient struct {
	baseURL       string
	handshakePath string
	httpClient    *http.Client
	privateKey    *ecdh.PrivateKey
	publicKey     *ecdh.PublicKey
	session       *ClientSession
	deviceID      string
	deviceSecret  []byte
	userToken     string
	mu            sync.RWMutex
}

// ClientSession stores client-side session data
type ClientSession struct {
	SessionID string
	EncKey    []byte
	MacKey    []byte
	ExpiresAt time.Time
	mu        sync.Mutex
}

// Config describes SecureClient bootstrap parameters.
type Config struct {
	BaseURL       string
	DeviceID      string
	DeviceSecret  []byte
	UserToken     string
	HTTPClient    *http.Client
	HandshakePath string
}

// SetUserToken updates the active user token for subsequent requests.
func (c *SecureClient) SetUserToken(token string) {
	c.mu.Lock()
	c.userToken = token
	c.mu.Unlock()
}

func (cs *ClientSession) isExpired() bool {
	if cs == nil {
		return true
	}
	return !cs.ExpiresAt.IsZero() && time.Now().After(cs.ExpiresAt)
}

// NewSecureClient creates a new secure client bound to a device/user identity.
func NewSecureClient(cfg Config) (*SecureClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if cfg.DeviceID == "" {
		return nil, fmt.Errorf("device id is required")
	}
	if len(cfg.DeviceSecret) == 0 {
		return nil, fmt.Errorf("device secret is required")
	}
	privKey, pubKey, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	handshakePath := cfg.HandshakePath
	if handshakePath == "" {
		handshakePath = "/handshake"
	}
	if !strings.HasPrefix(handshakePath, "/") {
		handshakePath = "/" + handshakePath
	}
	secretCopy := make([]byte, len(cfg.DeviceSecret))
	copy(secretCopy, cfg.DeviceSecret)

	return &SecureClient{
		baseURL:       cfg.BaseURL,
		handshakePath: handshakePath,
		privateKey:    privKey,
		publicKey:     pubKey,
		httpClient:    httpClient,
		deviceID:      cfg.DeviceID,
		deviceSecret:  secretCopy,
		userToken:     cfg.UserToken,
	}, nil
}

// Handshake establishes a secure session with the server
func (c *SecureClient) Handshake() error {
	timestamp := time.Now().Unix()
	payload := security.DeviceAuthenticationPayload(c.publicKey.Bytes(), timestamp)
	signature := crypto.ComputeHMAC(c.deviceSecret, payload)
	req := crypto.HandshakeRequest{
		ClientPublicKey: c.publicKey.Bytes(),
		DeviceID:        c.deviceID,
		DeviceSignature: signature,
		UserToken:       c.userToken,
		Timestamp:       timestamp,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+c.handshakePath,
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("handshake failed with status %d: %s", resp.StatusCode, string(body))
	}

	var handshakeResp crypto.HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&handshakeResp); err != nil {
		return fmt.Errorf("failed to decode handshake response: %w", err)
	}
	if handshakeResp.DeviceID != "" && handshakeResp.DeviceID != c.deviceID {
		return fmt.Errorf("device mismatch: expected %s got %s", c.deviceID, handshakeResp.DeviceID)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := crypto.PerformECDH(c.privateKey, handshakeResp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive session keys
	encKey, macKey, err := crypto.DeriveKeys(sharedSecret)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	expiresAt := time.Unix(handshakeResp.ExpiresAt, 0)
	if handshakeResp.ExpiresAt == 0 {
		expiresAt = time.Now().Add(crypto.SessionTimeout)
	}

	// Store session
	c.mu.Lock()
	c.session = &ClientSession{
		SessionID: string(handshakeResp.SessionID),
		EncKey:    encKey,
		MacKey:    macKey,
		ExpiresAt: expiresAt,
	}
	c.mu.Unlock()

	return nil
}

// encrypt encrypts plaintext using the session keys
func (cs *ClientSession) encrypt(plaintext []byte) (*crypto.EncryptedMessage, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	session := &crypto.Session{
		EncKey: cs.EncKey,
		MacKey: cs.MacKey,
	}
	return session.Encrypt(plaintext)
}

// decrypt decrypts an encrypted message using the session keys
func (cs *ClientSession) decrypt(msg *crypto.EncryptedMessage) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	session := &crypto.Session{
		EncKey: cs.EncKey,
		MacKey: cs.MacKey,
	}
	return session.Decrypt(msg)
}

// Post sends an encrypted POST request
func (c *SecureClient) Post(endpoint string, data interface{}) ([]byte, error) {
	c.mu.RLock()
	session := c.session
	userToken := c.userToken
	c.mu.RUnlock()
	if session == nil || session.isExpired() {
		return nil, fmt.Errorf("session expired or missing, call Handshake")
	}

	// Marshal data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	// Encrypt the data
	encMsg, err := session.encrypt(jsonData)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Marshal encrypted message
	encBody, err := json.Marshal(encMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted message: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(
		http.MethodPost,
		c.baseURL+endpoint,
		bytes.NewReader(encBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(headerSessionID, session.SessionID)
	if userToken != "" {
		req.Header.Set(headerUserToken, userToken)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read encrypted response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Decrypt response
	var encResp crypto.EncryptedMessage
	if err := json.Unmarshal(respBody, &encResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %w", err)
	}

	plaintext, err := session.decrypt(&encResp)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// PostJSON sends encrypted request and decodes JSON response
func (c *SecureClient) PostJSON(endpoint string, request interface{}, response interface{}) error {
	respData, err := c.Post(endpoint, request)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(respData, response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return nil
}

// IsConnected checks if client has an active session
func (c *SecureClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session != nil
}
