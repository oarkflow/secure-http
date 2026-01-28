//go:build js && wasm

package fetch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall/js"
	"time"

	clientpkg "github.com/oarkflow/securehttp/pkg/http/client"
)

type wasmState struct {
	mu               sync.RWMutex
	client           *clientpkg.SecureClient
	handshakeRunning bool
	waiters          []chan error
}

type wasmConfig struct {
	cfg           clientpkg.Config
	autoHandshake bool
	accessToken   string
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
)

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

		secureClient, err := clientpkg.NewSecureClient(cfg.cfg)
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
			if len(payload) == 0 && (req.method == http.MethodPost || req.method == http.MethodPut || req.method == http.MethodPatch) {
				payload = []byte("null")
			}

			// Use appropriate method
			switch req.method {
			case http.MethodGet:
				resp, err = s.client.Get(req.endpoint)
			case http.MethodPost:
				resp, err = s.client.Post(req.endpoint, json.RawMessage(payload))
			case http.MethodPut:
				resp, err = s.client.Put(req.endpoint, json.RawMessage(payload))
			case http.MethodDelete:
				resp, err = s.client.Delete(req.endpoint)
			case http.MethodPatch:
				resp, err = s.client.Patch(req.endpoint, json.RawMessage(payload))
			default:
				rejectError(reject, fmt.Errorf("unsupported method: %s", req.method))
				return
			}
			// Retry with fresh handshake on session error
			if err != nil && strings.Contains(strings.ToLower(err.Error()), "handshake") {
				if handshakeErr := s.ensureSession(true); handshakeErr == nil {
					switch req.method {
					case http.MethodGet:
						resp, err = s.client.Get(req.endpoint)
					case http.MethodPost:
						resp, err = s.client.Post(req.endpoint, json.RawMessage(payload))
					case http.MethodPut:
						resp, err = s.client.Put(req.endpoint, json.RawMessage(payload))
					case http.MethodDelete:
						resp, err = s.client.Delete(req.endpoint)
					case http.MethodPatch:
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

	cfg.cfg.DeviceID = str("deviceID")
	if cfg.cfg.DeviceID == "" {
		return cfg, errors.New("deviceID is required")
	}

	secretVal := val.Get("deviceSecret")
	secret, err := valueToBytes(secretVal)
	if err != nil {
		return cfg, fmt.Errorf("deviceSecret: %w", err)
	}
	cfg.cfg.DeviceSecret = secret

	gateSecrets, err := collectGateSecrets(val)
	if err != nil {
		return cfg, err
	}
	if len(gateSecrets) == 0 {
		return cfg, errors.New("gateSecret is required")
	}
	cfg.cfg.Gate.Secrets = gateSecrets

	capability := str("capabilityToken")
	if capability == "" {
		capability = str("gateCapability")
	}
	if capability == "" {
		return cfg, errors.New("capabilityToken is required")
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

	// Store JWT access token to be set after client creation
	if accessToken := str("accessToken"); accessToken != "" {
		cfg.accessToken = accessToken
	}

	if path := str("handshakePath"); path != "" {
		cfg.cfg.HandshakePath = path
	}

	if timeoutVal := val.Get("timeoutMs"); timeoutVal.Type() == js.TypeNumber {
		ms := timeoutVal.Int()
		if ms > 0 {
			cfg.cfg.HTTPClient = &http.Client{Timeout: time.Duration(ms) * time.Millisecond}
		}
	}

	cfg.autoHandshake = true
	if auto := val.Get("autoHandshake"); auto.Type() == js.TypeBoolean {
		cfg.autoHandshake = auto.Bool()
	}

	return cfg, nil
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
		req.method = http.MethodPost
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

func collectGateSecrets(val js.Value) ([]clientpkg.GateSecret, error) {
	var secrets []clientpkg.GateSecret
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

func parseGateSecretEntry(entry js.Value) (clientpkg.GateSecret, error) {
	id := firstStringProp(entry, "id", "key", "name")
	secretVal := entry.Get("secret")
	if !secretVal.Truthy() {
		secretVal = entry.Get("value")
	}
	if id == "" || !secretVal.Truthy() {
		return clientpkg.GateSecret{}, errors.New("each gateSecret requires id and secret")
	}
	return buildGateSecret(id, secretVal)
}

func parseSingleGateSecret(val js.Value) (clientpkg.GateSecret, error) {
	id := firstStringProp(val, "gateSecretID", "gateSecretId", "gateKeyID", "gateKeyId")
	secretVal := val.Get("gateSecret")
	if id == "" && (!secretVal.Truthy()) {
		return clientpkg.GateSecret{}, nil
	}
	if id == "" {
		return clientpkg.GateSecret{}, errors.New("gateSecretID is required")
	}
	if !secretVal.Truthy() {
		return clientpkg.GateSecret{}, errors.New("gateSecret value is required")
	}
	return buildGateSecret(id, secretVal)
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

func buildGateSecret(id string, secretVal js.Value) (clientpkg.GateSecret, error) {
	secretBytes, err := valueToBytes(secretVal)
	if err != nil {
		return clientpkg.GateSecret{}, err
	}
	if len(secretBytes) == 0 {
		return clientpkg.GateSecret{}, errors.New("gateSecret cannot be empty")
	}
	return clientpkg.GateSecret{ID: id, Secret: secretBytes}, nil
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
