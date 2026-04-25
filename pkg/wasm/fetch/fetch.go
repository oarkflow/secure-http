//go:build js && wasm

package fetch

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/oarkflow/securehttp/pkg/browser"
	securecrypto "github.com/oarkflow/securehttp/pkg/crypto"
)

const (
	methodGet    = "GET"
	methodPost   = "POST"
	methodPut    = "PUT"
	methodDelete = "DELETE"
	methodPatch  = "PATCH"

	headerSessionID = "X-Session-ID"
	headerUserToken = "X-User-Token"
)

type wasmState struct {
	mu               sync.RWMutex
	client           *secureClient
	handshakeRunning bool
	waiters          []chan error
}

type wasmConfig struct {
	cfg           clientConfig
	autoHandshake bool
	accessToken   string
	bootstrapPath string
}

type wasmRequest struct {
	endpoint       string
	method         string
	body           js.Value
	responseType   string
	forceHandshake bool
	isFileUpload   bool
	filename       string
	fieldName      string
	formData       map[string]string
}

var (
	state          = &wasmState{}
	initFunc       js.Func
	fetchFunc      js.Func
	handshakeFunc  js.Func
	resetFunc      js.Func
	uint8ArrayCtor js.Value
	jsonGlobal     js.Value
	promiseCtor    js.Value
	errorCtor      js.Value
	headersCtor    js.Value
	fetchFuncJS    js.Value
)

type gateSecret struct {
	ID        string
	Secret    []byte
	NotBefore time.Time
	ExpiresAt time.Time
}

type gateClientConfig struct {
	Secrets         []gateSecret
	CapabilityToken string
	NonceSize       int
}

type clientConfig struct {
	BaseURL       string
	DeviceID      string
	DeviceSecret  []byte
	UserToken     string
	HandshakePath string
	CSRFHeader    string
	CSRFToken     string
	Gate          gateClientConfig
}

type secureClient struct {
	baseURL       string
	handshakePath string
	session       *clientSession
	deviceID      string
	deviceSecret  []byte
	userToken     string
	accessToken   string
	csrfHeader    string
	csrfToken     string
	gateSecrets   []gateSecret
	capability    string
	nonceSize     int
	rotateBefore  time.Duration
	mu            sync.RWMutex
}

type clientSession struct {
	SessionID string
	EncKey    []byte
	MacKey    []byte
	ExpiresAt time.Time
	mu        sync.Mutex
}

func newSecureClient(cfg clientConfig) (*secureClient, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("base URL is required")
	}
	if cfg.DeviceID == "" {
		return nil, errors.New("device id is required")
	}
	if len(cfg.DeviceSecret) == 0 {
		return nil, errors.New("device secret is required")
	}
	if len(cfg.Gate.Secrets) == 0 {
		return nil, errors.New("gate secret is required")
	}
	if strings.TrimSpace(cfg.Gate.CapabilityToken) == "" {
		return nil, errors.New("capability token is required")
	}
	handshakePath := normalizeEndpoint(firstNonEmpty(cfg.HandshakePath, "/handshake"))
	secretCopy := make([]byte, len(cfg.DeviceSecret))
	copy(secretCopy, cfg.DeviceSecret)
	nonceSize := cfg.Gate.NonceSize
	if nonceSize <= 0 {
		nonceSize = 16
	}
	return &secureClient{
		baseURL:       strings.TrimRight(cfg.BaseURL, "/"),
		handshakePath: handshakePath,
		deviceID:      cfg.DeviceID,
		deviceSecret:  secretCopy,
		userToken:     cfg.UserToken,
		csrfHeader:    firstNonEmpty(strings.TrimSpace(cfg.CSRFHeader), "X-CSRF-Token"),
		csrfToken:     strings.TrimSpace(cfg.CSRFToken),
		gateSecrets:   cloneGateSecrets(cfg.Gate.Secrets),
		capability:    strings.TrimSpace(cfg.Gate.CapabilityToken),
		nonceSize:     nonceSize,
		rotateBefore:  2 * time.Minute,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cloneGateSecrets(src []gateSecret) []gateSecret {
	if len(src) == 0 {
		return nil
	}
	clones := make([]gateSecret, 0, len(src))
	for _, s := range src {
		if s.ID == "" || len(s.Secret) == 0 {
			continue
		}
		secretCopy := make([]byte, len(s.Secret))
		copy(secretCopy, s.Secret)
		clones = append(clones, gateSecret{
			ID:        s.ID,
			Secret:    secretCopy,
			NotBefore: s.NotBefore,
			ExpiresAt: s.ExpiresAt,
		})
	}
	return clones
}

func (c *secureClient) SetAccessToken(token string) {
	c.mu.Lock()
	c.accessToken = token
	c.mu.Unlock()
}

func (c *secureClient) NeedsHandshake() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session == nil || c.session.isExpired() || c.session.needsRotation(time.Now(), c.rotateBefore)
}

func (cs *clientSession) isExpired() bool {
	return cs == nil || (!cs.ExpiresAt.IsZero() && time.Now().After(cs.ExpiresAt))
}

func (cs *clientSession) needsRotation(now time.Time, rotateBefore time.Duration) bool {
	if cs == nil || cs.ExpiresAt.IsZero() || rotateBefore <= 0 {
		return false
	}
	return !now.Before(cs.ExpiresAt.Add(-rotateBefore))
}

func (c *secureClient) Handshake() error {
	privateKey, publicKey, err := securecrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate handshake keypair: %w", err)
	}

	timestamp := time.Now().Unix()
	payload := deviceAuthenticationPayload(publicKey.Bytes(), timestamp)
	signature := securecrypto.ComputeHMAC(c.deviceSecret, payload)
	req := securecrypto.HandshakeRequest{
		ClientPublicKey: publicKey.Bytes(),
		DeviceID:        c.deviceID,
		DeviceSignature: signature,
		UserToken:       c.userToken,
		Timestamp:       timestamp,
	}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if err := c.applyGateHeaders(headers, methodPost, c.handshakePath); err != nil {
		return err
	}

	body, status, err := browserFetch(methodPost, c.baseURL+c.handshakePath, headers, reqBody)
	if err != nil {
		return fmt.Errorf("handshake request failed: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("handshake failed with status %d: %s", status, string(body))
	}
	if len(body) == 0 {
		return errors.New("handshake failed: server returned empty response")
	}

	var handshakeResp securecrypto.HandshakeResponse
	if err := json.Unmarshal(body, &handshakeResp); err != nil {
		preview := string(body)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		return fmt.Errorf("failed to decode handshake response (body: %q): %w", preview, err)
	}
	if handshakeResp.DeviceID != "" && handshakeResp.DeviceID != c.deviceID {
		return fmt.Errorf("device mismatch: expected %s got %s", c.deviceID, handshakeResp.DeviceID)
	}
	sharedSecret, err := securecrypto.PerformECDH(privateKey, handshakeResp.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}
	encKey, macKey, err := securecrypto.DeriveKeys(sharedSecret)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}
	expiresAt := time.Unix(handshakeResp.ExpiresAt, 0)
	if handshakeResp.ExpiresAt == 0 {
		expiresAt = time.Now().Add(securecrypto.SessionTimeout)
	}
	c.mu.Lock()
	c.session = &clientSession{
		SessionID: string(handshakeResp.SessionID),
		EncKey:    encKey,
		MacKey:    macKey,
		ExpiresAt: expiresAt,
	}
	c.mu.Unlock()
	return nil
}

func deviceAuthenticationPayload(publicKey []byte, timestamp int64) []byte {
	payload := make([]byte, 0, len(publicKey)+8)
	payload = append(payload, publicKey...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	payload = append(payload, ts...)
	return payload
}

func (c *secureClient) Get(endpoint string) ([]byte, error) {
	return c.Do(methodGet, endpoint, nil, "")
}

func (c *secureClient) Post(endpoint string, data []byte) ([]byte, error) {
	return c.Do(methodPost, endpoint, data, "application/json")
}

func (c *secureClient) Put(endpoint string, data []byte) ([]byte, error) {
	return c.Do(methodPut, endpoint, data, "application/json")
}

func (c *secureClient) Delete(endpoint string) ([]byte, error) {
	return c.Do(methodDelete, endpoint, nil, "")
}

func (c *secureClient) Patch(endpoint string, data []byte) ([]byte, error) {
	return c.Do(methodPatch, endpoint, data, "application/json")
}

func (c *secureClient) Do(method, endpoint string, data []byte, contentType string) ([]byte, error) {
	c.mu.RLock()
	session := c.session
	userToken := c.userToken
	csrfHeader := c.csrfHeader
	csrfToken := c.csrfToken
	accessToken := c.accessToken
	c.mu.RUnlock()
	if session == nil || session.isExpired() {
		return nil, errors.New("session expired or missing, call Handshake")
	}

	headers := map[string]string{}
	var body []byte
	isSafeMethod := method == methodGet || method == methodDelete
	if isSafeMethod && len(data) == 0 {
		body = nil
	} else {
		encMsg, err := session.encrypt(data)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
		body, err = json.Marshal(encMsg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal encrypted message: %w", err)
		}
		headers["Content-Type"] = "application/octet-stream"
	}
	headers[headerSessionID] = session.SessionID
	if userToken != "" {
		headers[headerUserToken] = userToken
	}
	if requiresCSRF(method) && csrfHeader != "" && csrfToken != "" {
		headers[csrfHeader] = csrfToken
	}
	if accessToken != "" {
		headers["Authorization"] = "Bearer " + accessToken
	}
	if err := c.applyGateHeaders(headers, method, endpoint); err != nil {
		return nil, err
	}

	respBody, status, err := browserFetch(method, c.baseURL+endpoint, headers, body)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("request failed with status %d: %s", status, string(respBody))
	}
	var encResp securecrypto.EncryptedMessage
	if err = json.Unmarshal(respBody, &encResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted response: %w", err)
	}
	decryptedResp, err := session.decrypt(&encResp)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return decryptedResp, nil
}

func (c *secureClient) UploadFile(endpoint string, fileData []byte, filename, fieldName string, formData map[string]string) ([]byte, error) {
	if fieldName == "" {
		fieldName = "file"
	}
	boundary := "securehttp-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var buf bytes.Buffer
	for key, val := range formData {
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString(`Content-Disposition: form-data; name="` + escapeMultipartQuote(key) + "\"\r\n\r\n")
		buf.WriteString(val + "\r\n")
	}
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString(`Content-Disposition: form-data; name="` + escapeMultipartQuote(fieldName) + `"; filename="` + escapeMultipartQuote(filename) + "\"\r\n")
	buf.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	buf.Write(fileData)
	buf.WriteString("\r\n--" + boundary + "--\r\n")
	endpointWithContentType := endpoint
	sep := "?"
	if strings.Contains(endpointWithContentType, "?") {
		sep = "&"
	}
	endpointWithContentType += sep + "_ct=multipart/form-data; boundary=" + boundary
	return c.Do(methodPost, endpointWithContentType, buf.Bytes(), "application/octet-stream")
}

func escapeMultipartQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return strings.ReplaceAll(s, `"`, `\"`)
}

func (cs *clientSession) encrypt(plaintext []byte) (*securecrypto.EncryptedMessage, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	session := &securecrypto.Session{EncKey: cs.EncKey, MacKey: cs.MacKey}
	return session.Encrypt(plaintext)
}

func (cs *clientSession) decrypt(msg *securecrypto.EncryptedMessage) ([]byte, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	session := &securecrypto.Session{EncKey: cs.EncKey, MacKey: cs.MacKey}
	return session.Decrypt(msg)
}

func (c *secureClient) applyGateHeaders(headers map[string]string, method, endpoint string) error {
	if c.capability == "" {
		return errors.New("capability token missing")
	}
	secret, err := selectActiveGateSecret(c.gateSecrets, time.Now())
	if err != nil {
		return err
	}
	nonce, err := randomNonce(c.nonceSize)
	if err != nil {
		return fmt.Errorf("gate nonce: %w", err)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	path := canonicalPath(endpoint)
	payload := gateCanonicalPayload(method, path, timestamp, nonce, c.capability)
	mac := securecrypto.ComputeHMAC(secret.Secret, payload)

	headers["X-Gate-Key"] = secret.ID
	headers["X-Gate-Timestamp"] = timestamp
	headers["X-Gate-Nonce"] = nonce
	headers["X-Gate-Signature"] = base64.StdEncoding.EncodeToString(mac)
	headers["X-Capability-Token"] = c.capability
	return nil
}

func selectActiveGateSecret(secrets []gateSecret, now time.Time) (gateSecret, error) {
	var selected gateSecret
	found := false
	for _, secret := range secrets {
		if secret.ID == "" || len(secret.Secret) == 0 {
			continue
		}
		if !secret.NotBefore.IsZero() && now.Before(secret.NotBefore) {
			continue
		}
		if !secret.ExpiresAt.IsZero() && now.After(secret.ExpiresAt) {
			continue
		}
		if !found || secret.NotBefore.After(selected.NotBefore) {
			selected = secret
			found = true
		}
	}
	if !found {
		return gateSecret{}, errors.New("no active gate secret available")
	}
	return selected, nil
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

func gateCanonicalPayload(method, path, timestamp, nonce, capability string) []byte {
	return []byte(strings.ToUpper(method) + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + capability)
}

func canonicalPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		if idx := strings.Index(trimmed, "://"); idx >= 0 {
			rest := trimmed[idx+3:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				trimmed = rest[slash:]
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

func requiresCSRF(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case methodGet:
		return false
	default:
		return true
	}
}

// Run bootstraps the WASM bindings and blocks forever.
func Run() {
	state.registerCallbacks()
	select {}
}

func (s *wasmState) registerCallbacks() {
	global := js.Global()
	uint8ArrayCtor = global.Get("Uint8Array")
	jsonGlobal = global.Get("JSON")
	promiseCtor = global.Get("Promise")
	errorCtor = global.Get("Error")
	headersCtor = global.Get("Headers")
	fetchFuncJS = global.Get("fetch")

	initFunc = js.FuncOf(s.init)
	fetchFunc = js.FuncOf(s.fetch)
	handshakeFunc = js.FuncOf(s.handshake)
	resetFunc = js.FuncOf(s.reset)

	global.Set("secureFetchInit", initFunc)
	global.Set("secureFetch", fetchFunc)
	global.Set("secureFetchHandshake", handshakeFunc)
	global.Set("secureFetchReset", resetFunc)
}

func (s *wasmState) init(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		if len(args) == 0 || args[0].IsNull() || args[0].IsUndefined() {
			rejectError(reject, errors.New("config object is required"))
			return
		}
		cfg, err := parseConfig(args[0])
		if err != nil {
			rejectError(reject, err)
			return
		}
		cfg, err = hydrateBootstrapConfig(cfg)
		if err != nil {
			rejectError(reject, err)
			return
		}

		secureClient, err := newSecureClient(cfg.cfg)
		if err != nil {
			rejectError(reject, err)
			return
		}

		// Set JWT access token if provided
		if cfg.accessToken != "" {
			secureClient.SetAccessToken(cfg.accessToken)
		}

		s.mu.Lock()
		s.client = secureClient
		s.waiters = nil
		s.handshakeRunning = false
		s.mu.Unlock()

		// Stateless mode: no session restoration from localStorage
		// JWT tokens handle authentication, encrypted channel is ephemeral

		if cfg.autoHandshake {
			if err := s.ensureSession(false); err != nil {
				rejectError(reject, err)
				return
			}
		}

		resolve.Invoke(js.Undefined())
	})
}

func (s *wasmState) fetch(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		if len(args) == 0 || args[0].IsNull() || args[0].IsUndefined() {
			rejectError(reject, errors.New("request object is required"))
			return
		}
		req, err := parseRequest(args[0])
		if err != nil {
			rejectError(reject, err)
			return
		}
		if err := s.ensureSession(req.forceHandshake); err != nil {
			rejectError(reject, err)
			return
		}

		var resp []byte

		// Handle file upload
		if req.isFileUpload {
			fileData, err := buildPayload(req.body)
			if err != nil {
				rejectError(reject, fmt.Errorf("failed to read file: %w", err))
				return
			}

			resp, err = s.client.UploadFile(req.endpoint, fileData, req.filename, req.fieldName, req.formData)
			if err != nil && strings.Contains(strings.ToLower(err.Error()), "handshake") {
				if handshakeErr := s.ensureSession(true); handshakeErr == nil {
					resp, err = s.client.UploadFile(req.endpoint, fileData, req.filename, req.fieldName, req.formData)
				} else {
					err = handshakeErr
				}
			}
		} else {
			// Handle regular request
			payload, err := buildPayload(req.body)
			if err != nil {
				rejectError(reject, err)
				return
			}
			if len(payload) == 0 && (req.method == methodPost || req.method == methodPut || req.method == methodPatch) {
				payload = []byte("null")
			}

			// Use appropriate method
			switch req.method {
			case methodGet:
				resp, err = s.client.Get(req.endpoint)
			case methodPost:
				resp, err = s.client.Post(req.endpoint, json.RawMessage(payload))
			case methodPut:
				resp, err = s.client.Put(req.endpoint, json.RawMessage(payload))
			case methodDelete:
				resp, err = s.client.Delete(req.endpoint)
			case methodPatch:
				resp, err = s.client.Patch(req.endpoint, json.RawMessage(payload))
			default:
				rejectError(reject, fmt.Errorf("unsupported method: %s", req.method))
				return
			}
			// Retry with fresh handshake on session error
			if err != nil && strings.Contains(strings.ToLower(err.Error()), "handshake") {
				if handshakeErr := s.ensureSession(true); handshakeErr == nil {
					switch req.method {
					case methodGet:
						resp, err = s.client.Get(req.endpoint)
					case methodPost:
						resp, err = s.client.Post(req.endpoint, json.RawMessage(payload))
					case methodPut:
						resp, err = s.client.Put(req.endpoint, json.RawMessage(payload))
					case methodDelete:
						resp, err = s.client.Delete(req.endpoint)
					case methodPatch:
						resp, err = s.client.Patch(req.endpoint, json.RawMessage(payload))
					}
				} else {
					err = handshakeErr
				}
			}
		}

		if err != nil {
			rejectError(reject, err)
			return
		}

		if err := resolveResponse(resp, req.responseType, resolve); err != nil {
			rejectError(reject, err)
			return
		}
	})
}

func (s *wasmState) handshake(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		force := false
		if len(args) > 0 && args[0].Type() == js.TypeBoolean {
			force = args[0].Bool()
		}
		if err := s.ensureSession(force); err != nil {
			rejectError(reject, err)
			return
		}
		resolve.Invoke(js.Undefined())
	})
}

func (s *wasmState) reset(this js.Value, args []js.Value) any {
	s.mu.Lock()
	waiters := s.waiters
	s.waiters = nil
	s.handshakeRunning = false
	s.client = nil
	s.mu.Unlock()

	for _, ch := range waiters {
		ch <- errors.New("secureFetch reset")
		close(ch)
	}

	// No localStorage to clear in stateless mode

	return js.Undefined()
}

func parseConfig(val js.Value) (wasmConfig, error) {
	var cfg wasmConfig

	str := func(key string) string {
		prop := val.Get(key)
		if prop.Type() == js.TypeString {
			return strings.TrimSpace(prop.String())
		}
		return ""
	}

	cfg.cfg.BaseURL = str("baseURL")
	if cfg.cfg.BaseURL == "" {
		cfg.cfg.BaseURL = str("url")
	}
	if cfg.cfg.BaseURL == "" {
		return cfg, errors.New("baseURL is required")
	}

	cfg.bootstrapPath = str("bootstrapPath")
	if cfg.bootstrapPath == "" {
		cfg.bootstrapPath = "/bootstrap"
	}

	cfg.cfg.DeviceID = str("deviceID")

	if secretVal := val.Get("deviceSecret"); !secretVal.IsUndefined() && !secretVal.IsNull() {
		secret, err := valueToBytes(secretVal)
		if err != nil {
			return cfg, fmt.Errorf("deviceSecret: %w", err)
		}
		cfg.cfg.DeviceSecret = secret
	}

	gateSecrets, err := collectGateSecrets(val)
	if err != nil {
		return cfg, err
	}
	cfg.cfg.Gate.Secrets = gateSecrets

	capability := str("capabilityToken")
	if capability == "" {
		capability = str("gateCapability")
	}
	cfg.cfg.Gate.CapabilityToken = capability

	if nonceVal := val.Get("gateNonceBytes"); nonceVal.Type() == js.TypeNumber {
		cfg.cfg.Gate.NonceSize = nonceVal.Int()
	} else if nonceVal := val.Get("gateNonceSize"); nonceVal.Type() == js.TypeNumber {
		cfg.cfg.Gate.NonceSize = nonceVal.Int()
	}

	if token := str("userToken"); token != "" {
		cfg.cfg.UserToken = token
	}
	if csrfToken := str("csrfToken"); csrfToken != "" {
		cfg.cfg.CSRFToken = csrfToken
	}
	if csrfHeader := str("csrfHeaderName"); csrfHeader != "" {
		cfg.cfg.CSRFHeader = csrfHeader
	}

	// Store JWT access token to be set after client creation
	if accessToken := str("accessToken"); accessToken != "" {
		cfg.accessToken = accessToken
	}

	if path := str("handshakePath"); path != "" {
		cfg.cfg.HandshakePath = path
	}

	cfg.autoHandshake = true
	if auto := val.Get("autoHandshake"); auto.Type() == js.TypeBoolean {
		cfg.autoHandshake = auto.Bool()
	}

	hasDirectSecrets := cfg.cfg.DeviceID != "" && len(cfg.cfg.DeviceSecret) > 0 && len(cfg.cfg.Gate.Secrets) > 0 && cfg.cfg.Gate.CapabilityToken != ""
	hasBootstrap := cfg.bootstrapPath != ""
	if !hasDirectSecrets && !hasBootstrap {
		return cfg, errors.New("either direct secure material or bootstrapPath is required")
	}

	return cfg, nil
}

func hydrateBootstrapConfig(cfg wasmConfig) (wasmConfig, error) {
	if cfg.cfg.DeviceID != "" && len(cfg.cfg.DeviceSecret) > 0 && len(cfg.cfg.Gate.Secrets) > 0 && cfg.cfg.Gate.CapabilityToken != "" {
		return cfg, nil
	}
	url := strings.TrimRight(cfg.cfg.BaseURL, "/") + normalizeEndpoint(cfg.bootstrapPath)
	headers := map[string]string{"Accept": "application/json"}
	if strings.TrimSpace(cfg.accessToken) != "" {
		headers["Authorization"] = "Bearer " + cfg.accessToken
	}
	if cfg.cfg.CSRFHeader != "" && cfg.cfg.CSRFToken != "" {
		headers[cfg.cfg.CSRFHeader] = cfg.cfg.CSRFToken
	}
	body, status, err := browserFetch(methodPost, url, headers, nil)
	if err != nil {
		return cfg, fmt.Errorf("bootstrap request failed: %w", err)
	}
	if status != 200 {
		return cfg, fmt.Errorf("bootstrap failed with status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var payload browser.BootstrapConfig
	if err := json.Unmarshal(body, &payload); err != nil {
		return cfg, fmt.Errorf("bootstrap decode failed: %w", err)
	}
	if strings.TrimSpace(payload.BaseURL) != "" {
		cfg.cfg.BaseURL = strings.TrimSpace(payload.BaseURL)
	}
	if cfg.cfg.DeviceID == "" {
		cfg.cfg.DeviceID = strings.TrimSpace(payload.DeviceID)
	}
	if len(cfg.cfg.DeviceSecret) == 0 {
		secret, err := decodeStringSecret(payload.DeviceSecret)
		if err != nil {
			return cfg, fmt.Errorf("bootstrap deviceSecret: %w", err)
		}
		cfg.cfg.DeviceSecret = secret
	}
	if cfg.cfg.UserToken == "" && strings.TrimSpace(payload.UserToken) != "" {
		cfg.cfg.UserToken = strings.TrimSpace(payload.UserToken)
	}
	if cfg.cfg.HandshakePath == "" && strings.TrimSpace(payload.HandshakePath) != "" {
		cfg.cfg.HandshakePath = strings.TrimSpace(payload.HandshakePath)
	}
	if cfg.cfg.Gate.CapabilityToken == "" {
		cfg.cfg.Gate.CapabilityToken = strings.TrimSpace(payload.CapabilityToken)
	}
	if len(cfg.cfg.Gate.Secrets) == 0 {
		secrets, err := decodeBootstrapGateSecrets(payload.GateSecrets)
		if err != nil {
			return cfg, err
		}
		cfg.cfg.Gate.Secrets = secrets
	}

	if cfg.cfg.DeviceID == "" {
		return cfg, errors.New("bootstrap deviceID is required")
	}
	if len(cfg.cfg.DeviceSecret) == 0 {
		return cfg, errors.New("bootstrap deviceSecret is required")
	}
	if cfg.cfg.Gate.CapabilityToken == "" {
		return cfg, errors.New("bootstrap capabilityToken is required")
	}
	if len(cfg.cfg.Gate.Secrets) == 0 {
		return cfg, errors.New("bootstrap gateSecrets are required")
	}
	return cfg, nil
}

func decodeStringSecret(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("secret is empty")
	}
	if strings.HasPrefix(raw, "base64:") {
		return base64.StdEncoding.DecodeString(raw[7:])
	}
	return []byte(raw), nil
}

func decodeBootstrapGateSecrets(entries []browser.GateSecret) ([]gateSecret, error) {
	secrets := make([]gateSecret, 0, len(entries))
	for _, entry := range entries {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			continue
		}
		secret, err := decodeStringSecret(entry.Secret)
		if err != nil {
			return nil, fmt.Errorf("gate secret %s: %w", id, err)
		}
		var notBefore time.Time
		if strings.TrimSpace(entry.NotBefore) != "" {
			notBefore, err = time.Parse(time.RFC3339, strings.TrimSpace(entry.NotBefore))
			if err != nil {
				return nil, fmt.Errorf("gate secret %s notBefore: %w", id, err)
			}
		}
		var expiresAt time.Time
		if strings.TrimSpace(entry.ExpiresAt) != "" {
			expiresAt, err = time.Parse(time.RFC3339, strings.TrimSpace(entry.ExpiresAt))
			if err != nil {
				return nil, fmt.Errorf("gate secret %s expiresAt: %w", id, err)
			}
		}
		secrets = append(secrets, gateSecret{
			ID:        id,
			Secret:    secret,
			NotBefore: notBefore,
			ExpiresAt: expiresAt,
		})
	}
	return secrets, nil
}

func parseRequest(val js.Value) (wasmRequest, error) {
	var req wasmRequest
	str := func(key string) string {
		prop := val.Get(key)
		if prop.Type() == js.TypeString {
			return strings.TrimSpace(prop.String())
		}
		return ""
	}

	req.endpoint = str("endpoint")
	if req.endpoint == "" {
		req.endpoint = str("url")
	}
	if req.endpoint == "" {
		return req, errors.New("endpoint is required")
	}

	req.method = strings.ToUpper(str("method"))
	if req.method == "" {
		req.method = methodPost
	}

	// Check if this is a file upload
	fileVal := val.Get("file")
	if !fileVal.IsUndefined() && !fileVal.IsNull() {
		req.isFileUpload = true
		req.filename = str("filename")
		if req.filename == "" {
			req.filename = "file"
		}
		req.fieldName = str("fieldName")
		if req.fieldName == "" {
			req.fieldName = "file"
		}

		// Parse form data
		formDataVal := val.Get("formData")
		if !formDataVal.IsUndefined() && !formDataVal.IsNull() {
			req.formData = make(map[string]string)
			keys := js.Global().Get("Object").Call("keys", formDataVal)
			length := keys.Length()
			for i := 0; i < length; i++ {
				key := keys.Index(i).String()
				value := formDataVal.Get(key)
				if value.Type() == js.TypeString {
					req.formData[key] = value.String()
				}
			}
		}

		req.body = fileVal
	} else {
		req.body = val.Get("body")
	}

	req.responseType = strings.ToLower(str("responseType"))
	if req.responseType == "" {
		req.responseType = "json"
	}

	if force := val.Get("forceHandshake"); force.Type() == js.TypeBoolean {
		req.forceHandshake = force.Bool()
	}

	req.endpoint = normalizeEndpoint(req.endpoint)
	return req, nil
}

func buildPayload(body js.Value) ([]byte, error) {
	if body.IsUndefined() || body.IsNull() {
		return nil, nil
	}

	if body.Type() == js.TypeObject && !uint8ArrayCtor.IsUndefined() && body.InstanceOf(uint8ArrayCtor) {
		buf := make([]byte, body.Length())
		js.CopyBytesToGo(buf, body)
		return buf, nil
	}

	if jsonGlobal.IsUndefined() {
		return nil, errors.New("JSON global is unavailable")
	}

	serialized := jsonGlobal.Call("stringify", body)
	if serialized.Type() != js.TypeString {
		return nil, errors.New("body must be JSON serializable")
	}
	return []byte(serialized.String()), nil
}

func valueToBytes(val js.Value) ([]byte, error) {
	if val.IsUndefined() || val.IsNull() {
		return nil, errors.New("value is undefined")
	}

	switch val.Type() {
	case js.TypeString:
		raw := val.String()
		if strings.HasPrefix(raw, "base64:") {
			decoded, err := base64.StdEncoding.DecodeString(raw[7:])
			if err != nil {
				return nil, err
			}
			return decoded, nil
		}
		return []byte(raw), nil
	case js.TypeObject:
		if !uint8ArrayCtor.IsUndefined() && val.InstanceOf(uint8ArrayCtor) {
			buf := make([]byte, val.Length())
			js.CopyBytesToGo(buf, val)
			return buf, nil
		}
	}

	return nil, fmt.Errorf("unsupported secret type: %s", val.Type().String())
}

func collectGateSecrets(val js.Value) ([]gateSecret, error) {
	var secrets []gateSecret
	if arr := val.Get("gateSecrets"); arr.Truthy() {
		length := arr.Length()
		for i := 0; i < length; i++ {
			secret, err := parseGateSecretEntry(arr.Index(i))
			if err != nil {
				return nil, err
			}
			if secret.ID != "" {
				secrets = append(secrets, secret)
			}
		}
	}
	if len(secrets) == 0 {
		single, err := parseSingleGateSecret(val)
		if err != nil {
			return nil, err
		}
		if single.ID != "" {
			secrets = append(secrets, single)
		}
	}
	return secrets, nil
}

func parseGateSecretEntry(entry js.Value) (gateSecret, error) {
	id := firstStringProp(entry, "id", "key", "name")
	secretVal := entry.Get("secret")
	if !secretVal.Truthy() {
		secretVal = entry.Get("value")
	}
	if id == "" || !secretVal.Truthy() {
		return gateSecret{}, errors.New("each gateSecret requires id and secret")
	}
	return buildGateSecret(
		id,
		secretVal,
		firstStringProp(entry, "notBefore", "not_before"),
		firstStringProp(entry, "expiresAt", "expires_at"),
	)
}

func parseSingleGateSecret(val js.Value) (gateSecret, error) {
	id := firstStringProp(val, "gateSecretID", "gateSecretId", "gateKeyID", "gateKeyId")
	secretVal := val.Get("gateSecret")
	if id == "" && (!secretVal.Truthy()) {
		return gateSecret{}, nil
	}
	if id == "" {
		return gateSecret{}, errors.New("gateSecretID is required")
	}
	if !secretVal.Truthy() {
		return gateSecret{}, errors.New("gateSecret value is required")
	}
	return buildGateSecret(id, secretVal, "", "")
}

func firstStringProp(val js.Value, keys ...string) string {
	for _, key := range keys {
		prop := val.Get(key)
		if prop.Type() == js.TypeString {
			trimmed := strings.TrimSpace(prop.String())
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func buildGateSecret(id string, secretVal js.Value, notBeforeRaw string, expiresAtRaw string) (gateSecret, error) {
	secretBytes, err := valueToBytes(secretVal)
	if err != nil {
		return gateSecret{}, err
	}
	if len(secretBytes) == 0 {
		return gateSecret{}, errors.New("gateSecret cannot be empty")
	}
	var notBefore time.Time
	if strings.TrimSpace(notBeforeRaw) != "" {
		notBefore, err = time.Parse(time.RFC3339, strings.TrimSpace(notBeforeRaw))
		if err != nil {
			return gateSecret{}, fmt.Errorf("invalid gateSecret notBefore: %w", err)
		}
	}
	var expiresAt time.Time
	if strings.TrimSpace(expiresAtRaw) != "" {
		expiresAt, err = time.Parse(time.RFC3339, strings.TrimSpace(expiresAtRaw))
		if err != nil {
			return gateSecret{}, fmt.Errorf("invalid gateSecret expiresAt: %w", err)
		}
	}
	return gateSecret{
		ID:        id,
		Secret:    secretBytes,
		NotBefore: notBefore,
		ExpiresAt: expiresAt,
	}, nil
}

func normalizeEndpoint(endpoint string) string {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "/"
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return trimmed
}

func resolveResponse(data []byte, responseType string, resolve js.Value) error {
	switch responseType {
	case "text":
		resolve.Invoke(string(data))
		return nil
	case "bytes", "arraybuffer":
		if uint8ArrayCtor.IsUndefined() {
			return errors.New("Uint8Array constructor missing")
		}
		out := uint8ArrayCtor.New(len(data))
		js.CopyBytesToJS(out, data)
		resolve.Invoke(out)
		return nil
	default:
		if jsonGlobal.IsUndefined() {
			return errors.New("JSON global is unavailable")
		}

		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			// Normalize empty responses to null so callers do not get parse errors
			resolve.Invoke(js.Null())
			return nil
		}
		var (
			parsed   js.Value
			parseErr error
		)
		func() {
			defer func() {
				if r := recover(); r != nil {
					parseErr = fmt.Errorf("failed to parse json: %v", r)
				}
			}()
			parsed = jsonGlobal.Call("parse", trimmed)
		}()
		if parseErr != nil {
			return parseErr
		}
		resolve.Invoke(parsed)
		return nil
	}
}

func (s *wasmState) ensureSession(force bool) error {
	s.mu.Lock()
	if s.client == nil {
		s.mu.Unlock()
		return errors.New("secureFetch not initialized")
	}

	needsHandshake := force || s.client.NeedsHandshake()
	if !needsHandshake {
		s.mu.Unlock()
		return nil
	}

	if s.handshakeRunning {
		wait := make(chan error, 1)
		s.waiters = append(s.waiters, wait)
		s.mu.Unlock()
		err := <-wait
		return err
	}

	s.handshakeRunning = true
	s.mu.Unlock()

	err := s.client.Handshake()

	s.mu.Lock()
	waiters := s.waiters
	s.waiters = nil
	s.handshakeRunning = false
	s.mu.Unlock()

	for _, ch := range waiters {
		ch <- err
		close(ch)
	}

	// Stateless mode: no session persistence to localStorage
	// The encrypted channel is ephemeral and tied to the tab lifetime

	return err
}

func newPromise(executor func(resolve, reject js.Value)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go executor(resolve, reject)
		return nil
	})
	promise := promiseCtor.New(handler)
	handler.Release()
	return promise
}

func rejectError(reject js.Value, err error) {
	if err == nil {
		reject.Invoke(js.Undefined())
		return
	}
	if errorCtor.Truthy() {
		reject.Invoke(errorCtor.New(err.Error()))
		return
	}
	reject.Invoke(err.Error())
}

type promiseResult struct {
	value js.Value
	err   error
}

func browserFetch(method, url string, headers map[string]string, body []byte) ([]byte, int, error) {
	if !fetchFuncJS.Truthy() {
		return nil, 0, errors.New("fetch global is unavailable")
	}
	opts := js.Global().Get("Object").New()
	opts.Set("method", method)
	if len(headers) > 0 {
		headerObj := headersCtor.New()
		for key, value := range headers {
			headerObj.Call("set", key, value)
		}
		opts.Set("headers", headerObj)
	}
	if body != nil {
		out := uint8ArrayCtor.New(len(body))
		js.CopyBytesToJS(out, body)
		opts.Set("body", out)
	}
	resp, err := awaitPromise(fetchFuncJS.Invoke(url, opts))
	if err != nil {
		return nil, 0, err
	}
	status := resp.Get("status").Int()
	arrayBuffer, err := awaitPromise(resp.Call("arrayBuffer"))
	if err != nil {
		return nil, status, err
	}
	uint8Array := uint8ArrayCtor.New(arrayBuffer)
	data := make([]byte, uint8Array.Length())
	js.CopyBytesToGo(data, uint8Array)
	return data, status, nil
}

func awaitPromise(promise js.Value) (js.Value, error) {
	ch := make(chan promiseResult, 1)
	thenFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- promiseResult{value: args[0]}
		return nil
	})
	catchFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		ch <- promiseResult{err: jsError(args[0])}
		return nil
	})
	promise.Call("then", thenFunc).Call("catch", catchFunc)
	result := <-ch
	thenFunc.Release()
	catchFunc.Release()
	return result.value, result.err
}

func jsError(val js.Value) error {
	if val.IsUndefined() || val.IsNull() {
		return errors.New("javascript promise rejected")
	}
	if msg := val.Get("message"); msg.Type() == js.TypeString {
		return errors.New(msg.String())
	}
	return errors.New(val.String())
}

// Stateless authentication mode:
// - No session persistence to localStorage
// - Encrypted channel (ECDH session) is ephemeral and tied to tab lifetime
// - JWT tokens (in sessionStorage via app.js) provide authentication across requests
// - On page refresh, client must re-authenticate and re-establish encrypted channel
// - This ensures true stateless operation where server maintains no session state

// ==================== ASSET SERVER FUNCTIONALITY ====================

// AssetServerConfig holds the configuration for the asset server
type AssetServerConfig struct {
	// AllowedDomains is the list of domains that can access the assets
	AllowedDomains []string
	// SecuritySecret is the HMAC secret key for token generation
	SecuritySecret string
	// TokenValidityHours defines how long a token is valid (default: 24)
	TokenValidityHours int
	// KnownIPMappings maps domains to their expected IP addresses (optional, for enhanced security)
	KnownIPMappings map[string][]string
	// SubPath is the subdirectory within the embed.FS to use (e.g., "dist")
	SubPath string
}

// AssetServer manages serving embedded assets with domain restrictions
type AssetServer struct {
	allowedDomains     map[string]bool
	assets             fs.FS
	securitySecret     string
	tokenValidityHours int
	securityToken      string
	currentDomain      string
	isAuthorized       bool
	authError          string
	knownIPMappings    map[string][]string
}

var assetServer *AssetServer

// NewAssetServer creates a new asset server instance with the provided embedded filesystem and config
func NewAssetServer(embedFS fs.FS, config AssetServerConfig) (*AssetServer, error) {
	var assetsSubFS fs.FS
	var err error

	// If SubPath is provided, create a sub filesystem
	if config.SubPath != "" {
		assetsSubFS, err = fs.Sub(embedFS, config.SubPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create sub filesystem: %v", err)
		}
	} else {
		assetsSubFS = embedFS
	}

	allowedMap := make(map[string]bool)
	for _, domain := range config.AllowedDomains {
		allowedMap[strings.ToLower(domain)] = true
	}

	tokenValidityHours := config.TokenValidityHours
	if tokenValidityHours <= 0 {
		tokenValidityHours = 24
	}

	// Get current domain info from browser
	hostname := js.Global().Get("location").Get("hostname").String()
	port := js.Global().Get("location").Get("port").String()
	protocol := js.Global().Get("location").Get("protocol").String()
	currentDomain := hostname
	if port != "" && port != "80" && port != "443" {
		currentDomain = hostname + ":" + port
	}

	server := &AssetServer{
		allowedDomains:     allowedMap,
		assets:             assetsSubFS,
		securitySecret:     config.SecuritySecret,
		tokenValidityHours: tokenValidityHours,
		currentDomain:      currentDomain,
		isAuthorized:       false,
		authError:          "",
		knownIPMappings:    config.KnownIPMappings,
	}

	// Perform comprehensive security validation
	server.validateDomainSecurity(hostname, port, protocol)

	return server, nil
}

// validateDomainSecurity performs multi-layer security checks
func (as *AssetServer) validateDomainSecurity(hostname, port, protocol string) {
	currentDomain := strings.ToLower(as.currentDomain)

	// Layer 1: Check if domain is in allowed list
	if !as.allowedDomains[currentDomain] {
		as.authError = "DOMAIN_NOT_ALLOWED"
		as.isAuthorized = false
		return
	}

	// Layer 2: For production domains, verify it's served over HTTPS
	isLocalhost := hostname == "localhost" || hostname == "127.0.0.1"
	if !isLocalhost && protocol != "https:" {
		as.authError = "HTTPS_REQUIRED"
		as.isAuthorized = false
		return
	}

	// Layer 3: Generate time-based security token using HMAC
	as.securityToken = as.generateSecureToken()
	as.isAuthorized = true
}

// generateSecureToken creates an HMAC-based token that includes domain and time
func (as *AssetServer) generateSecureToken() string {
	// Create token with 1-hour granularity to allow for clock drift
	timeSlot := time.Now().UTC().Truncate(time.Hour).Format("2006-01-02-15")
	message := fmt.Sprintf("%s|%s|wasm-auth", as.currentDomain, timeSlot)

	h := hmac.New(sha256.New, []byte(as.securitySecret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateSecurityToken validates a provided token against current domain
func (as *AssetServer) ValidateSecurityToken(token string) bool {
	if !as.isAuthorized {
		return false
	}

	// Check current hour token
	currentToken := as.generateSecureToken()
	if hmac.Equal([]byte(token), []byte(currentToken)) {
		return true
	}

	// Also check previous hour token (for clock drift tolerance)
	prevTimeSlot := time.Now().UTC().Add(-time.Hour).Truncate(time.Hour).Format("2006-01-02-15")
	prevMessage := fmt.Sprintf("%s|%s|wasm-auth", as.currentDomain, prevTimeSlot)
	h := hmac.New(sha256.New, []byte(as.securitySecret))
	h.Write([]byte(prevMessage))
	prevToken := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(token), []byte(prevToken))
}

// CheckDomain verifies if the current domain is allowed
func (as *AssetServer) CheckDomain() bool {
	return as.isAuthorized
}

// GetAuthError returns the authorization error if any
func (as *AssetServer) GetAuthError() string {
	return as.authError
}

// GetCurrentDomain returns the current domain
func (as *AssetServer) GetCurrentDomain() string {
	return as.currentDomain
}

// GetSecurityToken returns the security token for authorized domains
func (as *AssetServer) GetSecurityToken() string {
	if !as.isAuthorized {
		return ""
	}
	return as.securityToken
}

// resolveHostIP attempts to resolve and validate IP for a hostname
// Note: This is limited in WASM but provides additional validation layer
func resolveHostIP(hostname string) ([]string, error) {
	// In WASM environment, we can't do direct DNS lookups
	// But we can check if the hostname looks suspicious
	if net.ParseIP(hostname) != nil {
		// It's an IP address, not a hostname
		return []string{hostname}, nil
	}
	return nil, fmt.Errorf("dns lookup not available in wasm")
}

// GetAsset retrieves an asset file by path
func (as *AssetServer) GetAsset(path string) ([]byte, error) {
	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")

	// If path is empty, default to index.html
	if path == "" {
		path = "index.html"
	}

	data, err := fs.ReadFile(as.assets, path)
	if err != nil {
		return nil, fmt.Errorf("asset not found: %s", path)
	}

	return data, nil
}

// ListAssets returns all available asset paths
func (as *AssetServer) ListAssets() []string {
	var paths []string
	fs.WalkDir(as.assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

// GetMimeType returns the MIME type based on file extension
func GetMimeType(filename string) string {
	ext := strings.ToLower(filename)

	mimeTypes := map[string]string{
		".html":  "text/html",
		".css":   "text/css",
		".js":    "application/javascript",
		".json":  "application/json",
		".png":   "image/png",
		".jpg":   "image/jpeg",
		".jpeg":  "image/jpeg",
		".gif":   "image/gif",
		".svg":   "image/svg+xml",
		".ico":   "image/x-icon",
		".woff":  "font/woff",
		".woff2": "font/woff2",
		".ttf":   "font/ttf",
		".eot":   "application/vnd.ms-fontobject",
		".webp":  "image/webp",
		".txt":   "text/plain",
		".xml":   "application/xml",
		".wasm":  "application/wasm",
		".map":   "application/json",
	}

	for suffix, mimeType := range mimeTypes {
		if strings.HasSuffix(ext, suffix) {
			return mimeType
		}
	}

	return "application/octet-stream"
}

// ==================== JavaScript API Functions ====================

// jsCheckDomain checks if current domain is allowed and returns security info
func jsCheckDomain(this js.Value, args []js.Value) interface{} {
	if assetServer == nil {
		return map[string]interface{}{
			"allowed": false,
			"error":   "Server not initialized",
		}
	}

	return map[string]interface{}{
		"allowed":   assetServer.CheckDomain(),
		"hostname":  assetServer.GetCurrentDomain(),
		"authError": assetServer.GetAuthError(),
		"token":     assetServer.GetSecurityToken(),
	}
}

// jsValidateToken validates the security token
func jsValidateToken(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"valid": false,
			"error": "Token argument required",
		}
	}

	if assetServer == nil {
		return map[string]interface{}{
			"valid": false,
			"error": "Server not initialized",
		}
	}

	token := args[0].String()
	valid := assetServer.ValidateSecurityToken(token)

	return map[string]interface{}{
		"valid":  valid,
		"domain": assetServer.GetCurrentDomain(),
	}
}

// jsGetAsset retrieves an asset by path (requires valid security token)
func jsGetAsset(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"error": "Path and token arguments required",
		}
	}

	if assetServer == nil {
		return map[string]interface{}{
			"error": "Server not initialized",
		}
	}

	path := args[0].String()
	token := args[1].String()

	// Validate security token
	if !assetServer.ValidateSecurityToken(token) {
		return map[string]interface{}{
			"error": "Security validation failed",
		}
	}

	data, err := assetServer.GetAsset(path)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	// Convert byte slice to Uint8Array for JavaScript
	uint8Array := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(uint8Array, data)

	mimeType := GetMimeType(path)

	return map[string]interface{}{
		"data":     uint8Array,
		"mimeType": mimeType,
		"path":     path,
	}
}

// jsListAssets returns list of all available assets (requires valid security token)
func jsListAssets(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Token argument required",
		}
	}

	if assetServer == nil {
		return map[string]interface{}{
			"error": "Server not initialized",
		}
	}

	token := args[0].String()

	// Validate security token
	if !assetServer.ValidateSecurityToken(token) {
		return map[string]interface{}{
			"error": "Security validation failed",
		}
	}

	paths := assetServer.ListAssets()

	// Convert to JS array
	jsArray := js.Global().Get("Array").New(len(paths))
	for i, path := range paths {
		jsArray.SetIndex(i, path)
	}

	return map[string]interface{}{
		"assets": jsArray,
	}
}

// jsGetAssetAsText retrieves an asset as text (requires valid security token)
func jsGetAssetAsText(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"error": "Path and token arguments required",
		}
	}

	if assetServer == nil {
		return map[string]interface{}{
			"error": "Server not initialized",
		}
	}

	path := args[0].String()
	token := args[1].String()

	// Validate security token
	if !assetServer.ValidateSecurityToken(token) {
		return map[string]interface{}{
			"error": "Security validation failed",
		}
	}

	data, err := assetServer.GetAsset(path)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"text":     string(data),
		"mimeType": GetMimeType(path),
		"path":     path,
	}
}

// jsLoadFrontend loads the entire frontend application (requires valid security token)
func jsLoadFrontend(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error":   "Token argument required",
			"allowed": false,
		}
	}

	if assetServer == nil {
		return map[string]interface{}{
			"error":   "Server not initialized",
			"allowed": false,
		}
	}

	token := args[0].String()

	// Validate security token
	if !assetServer.ValidateSecurityToken(token) {
		return map[string]interface{}{
			"error":     "Security validation failed",
			"allowed":   false,
			"authError": assetServer.GetAuthError(),
		}
	}

	// Get index.html
	indexData, err := assetServer.GetAsset("index.html")
	if err != nil {
		return map[string]interface{}{
			"error": "Failed to load index.html: " + err.Error(),
		}
	}

	// Get all assets for the manifest
	assets := assetServer.ListAssets()

	return map[string]interface{}{
		"success": true,
		"html":    string(indexData),
		"assets":  convertToJSArray(assets),
		"allowed": true,
		"domain":  assetServer.GetCurrentDomain(),
	}
}

// convertToJSArray converts Go string slice to JS array
func convertToJSArray(items []string) js.Value {
	jsArray := js.Global().Get("Array").New(len(items))
	for i, item := range items {
		jsArray.SetIndex(i, item)
	}
	return jsArray
}

// jsGetSecurityInfo returns security information for the current session
func jsGetSecurityInfo(this js.Value, args []js.Value) interface{} {
	if assetServer == nil {
		return map[string]interface{}{
			"error": "Server not initialized",
		}
	}

	return map[string]interface{}{
		"domain":     assetServer.GetCurrentDomain(),
		"authorized": assetServer.CheckDomain(),
		"authError":  assetServer.GetAuthError(),
		"token":      assetServer.GetSecurityToken(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
}

// RegisterAssetServer initializes the asset server with the provided embedded filesystem
// and registers all JavaScript callbacks. Call this from your main function.
func RegisterAssetServer(embedFS fs.FS, config AssetServerConfig) error {
	var err error
	assetServer, err = NewAssetServer(embedFS, config)
	if err != nil {
		return fmt.Errorf("failed to initialize asset server: %v", err)
	}

	// Log security status
	if !assetServer.CheckDomain() {
		fmt.Printf("❌ Domain not authorized: %s\n", assetServer.GetCurrentDomain())
		fmt.Printf("⚠️ Auth error: %s\n", assetServer.GetAuthError())
	}

	// Register JavaScript functions for asset serving
	global := js.Global()
	global.Set("goCheckDomain", js.FuncOf(jsCheckDomain))
	global.Set("goGetAsset", js.FuncOf(jsGetAsset))
	global.Set("goListAssets", js.FuncOf(jsListAssets))
	global.Set("goGetAssetAsText", js.FuncOf(jsGetAssetAsText))
	global.Set("goLoadFrontend", js.FuncOf(jsLoadFrontend))
	global.Set("goValidateToken", js.FuncOf(jsValidateToken))
	global.Set("goGetSecurityInfo", js.FuncOf(jsGetSecurityInfo))

	return nil
}

// RunWithAssets bootstraps the WASM bindings with asset server support and blocks forever.
// This is an alternative to Run() that includes asset server functionality.
func RunWithAssets(embedFS fs.FS, config AssetServerConfig) error {
	// Initialize asset server
	if err := RegisterAssetServer(embedFS, config); err != nil {
		return err
	}

	// Register secure fetch callbacks
	state.registerCallbacks()

	// Block forever
	select {}
}
