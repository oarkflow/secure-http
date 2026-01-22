package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
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

// GateSecret identifies a rotating pre-routing secret.
type GateSecret struct {
	ID     string
	Secret []byte
}

// GateClientConfig describes the pre-routing crypto gate options.
type GateClientConfig struct {
	Secrets         []GateSecret
	CapabilityToken string
	Headers         security.GateHeaders
	NonceSize       int
}

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
	accessToken   string // JWT access token
	gateHeaders   security.GateHeaders
	gateSecrets   []GateSecret
	capability    string
	nonceSize     int
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
	Gate          GateClientConfig
}

// SetUserToken updates the active user token for subsequent requests.
func (c *SecureClient) SetUserToken(token string) {
	c.mu.Lock()
	c.userToken = token
	c.mu.Unlock()
}

// SetAccessToken updates the JWT access token for subsequent requests.
func (c *SecureClient) SetAccessToken(token string) {
	c.mu.Lock()
	c.accessToken = token
	c.mu.Unlock()
}

func cloneGateSecrets(src []GateSecret) []GateSecret {
	if len(src) == 0 {
		return nil
	}
	clones := make([]GateSecret, 0, len(src))
	for _, s := range src {
		if s.ID == "" || len(s.Secret) == 0 {
			continue
		}
		secretCopy := make([]byte, len(s.Secret))
		copy(secretCopy, s.Secret)
		clones = append(clones, GateSecret{ID: s.ID, Secret: secretCopy})
	}
	return clones
}

func (c *SecureClient) applyGateHeaders(req *http.Request, method, endpoint string) error {
	c.mu.RLock()
	headers := c.gateHeaders
	capability := c.capability
	nonceSize := c.nonceSize
	secrets := c.gateSecrets
	c.mu.RUnlock()

	if capability == "" {
		return fmt.Errorf("capability token missing")
	}
	if len(secrets) == 0 {
		return fmt.Errorf("gate secret missing")
	}
	secret := secrets[0]
	if secret.ID == "" || len(secret.Secret) == 0 {
		return fmt.Errorf("gate secret invalid")
	}
	nonce, err := randomNonce(nonceSize)
	if err != nil {
		return fmt.Errorf("gate nonce: %w", err)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	path := canonicalPath(endpoint)
	payload := gateCanonicalPayload(method, path, timestamp, nonce, capability)
	mac := crypto.ComputeHMAC(secret.Secret, payload)

	req.Header.Set(headers.SecretID, secret.ID)
	req.Header.Set(headers.Timestamp, timestamp)
	req.Header.Set(headers.Nonce, nonce)
	req.Header.Set(headers.Signature, base64.StdEncoding.EncodeToString(mac))
	req.Header.Set(headers.Capability, capability)
	return nil
}

func gateCanonicalPayload(method, path, timestamp, nonce, capability string) []byte {
	builder := strings.Builder{}
	builder.WriteString(strings.ToUpper(method))
	builder.WriteString("\n")
	builder.WriteString(path)
	builder.WriteString("\n")
	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")
	builder.WriteString(capability)
	return []byte(builder.String())
}

func canonicalPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		if parsed, err := url.Parse(trimmed); err == nil {
			if parsed.Path != "" {
				trimmed = parsed.Path
			} else {
				trimmed = "/"
			}
		}
	}
	if idx := strings.Index(trimmed, "?"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return trimmed
}

func randomNonce(size int) (string, error) {
	if size < 12 {
		size = 12
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (cs *ClientSession) isExpired() bool {
	if cs == nil {
		return true
	}
	return !cs.ExpiresAt.IsZero() && time.Now().After(cs.ExpiresAt)
}

func (c *SecureClient) needsHandshakeLocked() bool {
	if c.session == nil {
		return true
	}
	return c.session.isExpired()
}

// NeedsHandshake reports whether the current session is missing or expired.
func (c *SecureClient) NeedsHandshake() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.needsHandshakeLocked()
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
	gateSecrets := cloneGateSecrets(cfg.Gate.Secrets)
	if len(gateSecrets) == 0 {
		return nil, fmt.Errorf("gate secret is required")
	}
	if strings.TrimSpace(cfg.Gate.CapabilityToken) == "" {
		return nil, fmt.Errorf("capability token is required")
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
	nonceSize := cfg.Gate.NonceSize
	if nonceSize <= 0 {
		nonceSize = 16
	}
	gateHeaders := cfg.Gate.Headers.WithDefaults()

	return &SecureClient{
		baseURL:       cfg.BaseURL,
		handshakePath: handshakePath,
		privateKey:    privKey,
		publicKey:     pubKey,
		httpClient:    httpClient,
		deviceID:      cfg.DeviceID,
		deviceSecret:  secretCopy,
		userToken:     cfg.UserToken,
		gateHeaders:   gateHeaders,
		gateSecrets:   gateSecrets,
		capability:    strings.TrimSpace(cfg.Gate.CapabilityToken),
		nonceSize:     nonceSize,
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

	httpReq, err := http.NewRequest(
		http.MethodPost,
		c.baseURL+c.handshakePath,
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.applyGateHeaders(httpReq, http.MethodPost, c.handshakePath); err != nil {
		return err
	}

	resp, err := c.httpClient.Do(httpReq)
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
	return c.Do(http.MethodPost, endpoint, data, "application/json")
}

// Get sends an encrypted GET request
func (c *SecureClient) Get(endpoint string) ([]byte, error) {
	return c.Do(http.MethodGet, endpoint, nil, "")
}

// Put sends an encrypted PUT request
func (c *SecureClient) Put(endpoint string, data interface{}) ([]byte, error) {
	return c.Do(http.MethodPut, endpoint, data, "application/json")
}

// Delete sends an encrypted DELETE request
func (c *SecureClient) Delete(endpoint string) ([]byte, error) {
	return c.Do(http.MethodDelete, endpoint, nil, "")
}

// Patch sends an encrypted PATCH request
func (c *SecureClient) Patch(endpoint string, data interface{}) ([]byte, error) {
	return c.Do(http.MethodPatch, endpoint, data, "application/json")
}

// Do sends an encrypted HTTP request with any method
func (c *SecureClient) Do(method, endpoint string, data interface{}, contentType string) ([]byte, error) {
	c.mu.RLock()
	session := c.session
	userToken := c.userToken
	c.mu.RUnlock()
	if session == nil || session.isExpired() {
		return nil, fmt.Errorf("session expired or missing, call Handshake")
	}

	var plaintext []byte
	var err error

	// Handle different data types
	if data != nil {
		switch v := data.(type) {
		case []byte:
			plaintext = v
		case string:
			plaintext = []byte(v)
		default:
			// Marshal to JSON for objects
			plaintext, err = json.Marshal(data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal data: %w", err)
			}
		}
	}

	// Encrypt the data
	encMsg, err := session.encrypt(plaintext)
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
		method,
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

	// Add JWT Bearer token if available
	c.mu.RLock()
	accessToken := c.accessToken
	c.mu.RUnlock()
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	if err := c.applyGateHeaders(req, method, endpoint); err != nil {
		return nil, err
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
	if err = json.Unmarshal(respBody, &encResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %w", err)
	}

	decryptedResp, err := session.decrypt(&encResp)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decryptedResp, nil
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

// UploadFile uploads a file with encryption
func (c *SecureClient) UploadFile(endpoint string, fileData []byte, filename, fieldName string, formData map[string]string) ([]byte, error) {
	c.mu.RLock()
	session := c.session
	userToken := c.userToken
	c.mu.RUnlock()
	if session == nil || session.isExpired() {
		return nil, fmt.Errorf("session expired or missing, call Handshake")
	}

	// Build multipart form payload
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add form fields
	for key, val := range formData {
		if err := writer.WriteField(key, val); err != nil {
			return nil, fmt.Errorf("failed to write form field: %w", err)
		}
	}

	// Add file
	if fieldName == "" {
		fieldName = "file"
	}
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(fileData); err != nil {
		return nil, fmt.Errorf("failed to write file data: %w", err)
	}

	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close writer: %w", err)
	}

	// Encrypt the multipart payload
	encMsg, err := session.encrypt(buf.Bytes())
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

	// Set headers - encrypted content is always octet-stream
	// Original content type is preserved in encrypted payload
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(headerSessionID, session.SessionID)
	req.Header.Set("X-Original-Content-Type", contentType) // Store original type
	if userToken != "" {
		req.Header.Set(headerUserToken, userToken)
	}

	// Add JWT Bearer token if available
	c.mu.RLock()
	accessToken := c.accessToken
	c.mu.RUnlock()
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	if err := c.applyGateHeaders(req, http.MethodPost, endpoint); err != nil {
		return nil, err
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
	if err = json.Unmarshal(respBody, &encResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %w", err)
	}

	plaintext, err := session.decrypt(&encResp)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// IsConnected checks if client has an active session
func (c *SecureClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session != nil
}

// SessionData represents serializable session information
type SessionData struct {
	SessionID string    `json:"session_id"`
	EncKey    string    `json:"enc_key"`
	MacKey    string    `json:"mac_key"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetSessionData exports current session data for persistence
func (c *SecureClient) GetSessionData() *SessionData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.session == nil {
		return nil
	}

	return &SessionData{
		SessionID: c.session.SessionID,
		EncKey:    base64.StdEncoding.EncodeToString(c.session.EncKey),
		MacKey:    base64.StdEncoding.EncodeToString(c.session.MacKey),
		ExpiresAt: c.session.ExpiresAt,
	}
}

// RestoreSession restores a previously saved session
func (c *SecureClient) RestoreSession(data *SessionData) error {
	if data == nil {
		return fmt.Errorf("session data is nil")
	}

	// Check if session is expired
	if !data.ExpiresAt.IsZero() && time.Now().After(data.ExpiresAt) {
		return fmt.Errorf("session expired")
	}

	encKey, err := base64.StdEncoding.DecodeString(data.EncKey)
	if err != nil {
		return fmt.Errorf("failed to decode enc key: %w", err)
	}

	macKey, err := base64.StdEncoding.DecodeString(data.MacKey)
	if err != nil {
		return fmt.Errorf("failed to decode mac key: %w", err)
	}

	c.mu.Lock()
	c.session = &ClientSession{
		SessionID: data.SessionID,
		EncKey:    encKey,
		MacKey:    macKey,
		ExpiresAt: data.ExpiresAt,
	}
	c.mu.Unlock()

	return nil
}
