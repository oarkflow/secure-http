//go:build js && wasm

package securefetch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"syscall/js"
	"time"

	clientpkg "github.com/oarkflow/securehttp/pkg/http/client"
)

type wasmState struct {
	mu               sync.Mutex
	client           *clientpkg.SecureClient
	handshakeRunning bool
	waiters          []chan error
}

type wasmConfig struct {
	cfg           clientpkg.Config
	autoHandshake bool
}

type wasmRequest struct {
	endpoint       string
	body           js.Value
	responseType   string
	forceHandshake bool
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

		s.mu.Lock()
		s.client = secureClient
		s.waiters = nil
		s.handshakeRunning = false
		s.mu.Unlock()

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

		payload, err := buildPayload(req.body)
		if err != nil {
			rejectError(reject, err)
			return
		}
		if len(payload) == 0 {
			payload = []byte("null")
		}

		resp, err := s.client.Post(req.endpoint, json.RawMessage(payload))
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "handshake") {
			if handshakeErr := s.ensureSession(true); handshakeErr == nil {
				resp, err = s.client.Post(req.endpoint, json.RawMessage(payload))
			} else {
				err = handshakeErr
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

	if token := str("userToken"); token != "" {
		cfg.cfg.UserToken = token
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

	method := strings.ToUpper(str("method"))
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost {
		return req, fmt.Errorf("unsupported method %s", method)
	}

	req.body = val.Get("body")
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
		return []byte("null"), nil
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
			parsed = jsonGlobal.Call("parse", string(data))
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
