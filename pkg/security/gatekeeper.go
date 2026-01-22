package security

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/securehttp/pkg/crypto"
)

var (
	ErrGateMissingHeader    = errors.New("missing gate header")
	ErrGateClockSkew        = errors.New("gate timestamp outside allowed skew")
	ErrGateNonceReplayed    = errors.New("gate nonce replay detected")
	ErrGateSecretUnknown    = errors.New("gate secret id unknown")
	ErrGateSecretExpired    = errors.New("gate secret expired")
	ErrGateSignatureInvalid = errors.New("gate signature invalid")
	ErrGateCapabilityDenied = errors.New("capability denied")
	ErrGateRateLimited      = errors.New("request rate limited")
)

// GateHeaders encapsulates HTTP header names used by the gate.
type GateHeaders struct {
	SecretID   string
	Timestamp  string
	Nonce      string
	Signature  string
	Capability string
}

// WithDefaults ensures every header has a name.
func (h GateHeaders) WithDefaults() GateHeaders {
	if h.SecretID == "" {
		h.SecretID = "X-Gate-Key"
	}
	if h.Timestamp == "" {
		h.Timestamp = "X-Gate-Timestamp"
	}
	if h.Nonce == "" {
		h.Nonce = "X-Gate-Nonce"
	}
	if h.Signature == "" {
		h.Signature = "X-Gate-Signature"
	}
	if h.Capability == "" {
		h.Capability = "X-Capability-Token"
	}
	return h
}

// RotatingSecret defines an HMAC secret with an activation window.
type RotatingSecret struct {
	ID        string
	Secret    []byte
	NotBefore time.Time
	ExpiresAt time.Time
}

// ActiveAt reports whether the secret is valid at the supplied time.
func (rs RotatingSecret) ActiveAt(now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	if !rs.NotBefore.IsZero() && now.Before(rs.NotBefore) {
		return false
	}
	if !rs.ExpiresAt.IsZero() && now.After(rs.ExpiresAt) {
		return false
	}
	return len(rs.Secret) > 0 && rs.ID != ""
}

// CapabilityStore validates capability tokens.
type CapabilityStore interface {
	Validate(token, method, path string) (*Capability, error)
}

// MemoryCapabilityStore keeps capabilities in RAM.
type MemoryCapabilityStore struct {
	mu           sync.RWMutex
	capabilities map[string]*Capability
}

// NewMemoryCapabilityStore sets up an empty capability store.
func NewMemoryCapabilityStore() *MemoryCapabilityStore {
	return &MemoryCapabilityStore{capabilities: make(map[string]*Capability)}
}

// Register inserts or overwrites a capability.
func (cs *MemoryCapabilityStore) Register(cap Capability) {
	if cap.Token == "" {
		return
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	clone := cap
	if len(cap.Methods) > 0 {
		normalized := make(map[string]struct{}, len(cap.Methods))
		for method := range cap.Methods {
			normalized[strings.ToUpper(method)] = struct{}{}
		}
		clone.Methods = normalized
	}
	if len(cap.Paths) > 0 {
		clone.Paths = append([]string{}, cap.Paths...)
	}
	if len(cap.Metadata) > 0 {
		copied := make(map[string]string, len(cap.Metadata))
		for k, v := range cap.Metadata {
			copied[k] = v
		}
		clone.Metadata = copied
	}
	if len(cap.Rules) > 0 {
		clone.Rules = cloneRules(cap.Rules)
	}
	cs.capabilities[cap.Token] = &clone
}

// Validate ensures token exists and covers the request surface.
func (cs *MemoryCapabilityStore) Validate(token, method, path string) (*Capability, error) {
	if token == "" {
		return nil, ErrGateCapabilityDenied
	}
	cs.mu.RLock()
	cap, ok := cs.capabilities[token]
	cs.mu.RUnlock()
	if !ok || !cap.Allows(method, path) {
		return nil, ErrGateCapabilityDenied
	}
	return cap, nil
}

func cloneRules(rules []CapabilityRule) []CapabilityRule {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([]CapabilityRule, len(rules))
	for i, rule := range rules {
		cloned[i].Path = rule.Path
		if len(rule.Methods) == 0 {
			continue
		}
		methods := make(map[string]struct{}, len(rule.Methods))
		for method := range rule.Methods {
			methods[strings.ToUpper(method)] = struct{}{}
		}
		cloned[i].Methods = methods
	}
	return cloned
}

// NonceStore tracks used nonces to prevent replay.
type NonceStore interface {
	Seen(key, nonce string, ttl time.Duration) bool
}

type memoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryNonceStore returns a nonce store with best-effort cleanup.
func NewMemoryNonceStore() NonceStore {
	store := &memoryNonceStore{seen: make(map[string]time.Time)}
	go store.reaper()
	return store
}

func (s *memoryNonceStore) Seen(key, nonce string, ttl time.Duration) bool {
	if key == "" || nonce == "" {
		return true
	}
	composite := key + "::" + nonce
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.seen[composite]
	if ok && now.Sub(ts) <= ttl {
		return true
	}
	s.seen[composite] = now
	return false
}

func (s *memoryNonceStore) reaper() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-15 * time.Minute)
		s.mu.Lock()
		for key, ts := range s.seen {
			if ts.Before(cutoff) {
				delete(s.seen, key)
			}
		}
		s.mu.Unlock()
	}
}

// RateLimiter throttles repeated requests.
type RateLimiter interface {
	Allow(key string) bool
}

type slidingWindowLimiter struct {
	window  time.Duration
	maxHits int
	mu      sync.Mutex
	hits    map[string][]time.Time
}

// NewSlidingWindowLimiter configures a limiter.
func NewSlidingWindowLimiter(window time.Duration, maxHits int) RateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	if maxHits <= 0 {
		maxHits = 60
	}
	return &slidingWindowLimiter{
		window:  window,
		maxHits: maxHits,
		hits:    make(map[string][]time.Time),
	}
}

func (l *slidingWindowLimiter) Allow(key string) bool {
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-l.window)
	history := l.hits[key]
	filtered := history[:0]
	for _, ts := range history {
		if ts.After(windowStart) {
			filtered = append(filtered, ts)
		}
	}
	if len(filtered) >= l.maxHits {
		l.hits[key] = filtered
		return false
	}
	filtered = append(filtered, now)
	l.hits[key] = filtered
	return true
}

// GatekeeperConfig wires the gate components.
type GatekeeperConfig struct {
	Secrets         []RotatingSecret
	Headers         GateHeaders
	MaxClockSkew    time.Duration
	NonceTTL        time.Duration
	CapabilityStore CapabilityStore
	NonceStore      NonceStore
	RateLimiter     RateLimiter
	Logger          AuditLogger
}

// GateRequest contains the required fields for validation.
type GateRequest struct {
	Method     string
	Path       string
	Headers    map[string]string
	RemoteAddr string
}

// Gatekeeper enforces the pre-routing crypto gate.
type Gatekeeper struct {
	secrets map[string]RotatingSecret
	cfg     GatekeeperConfig
	nonce   NonceStore
	limiter RateLimiter
	logger  AuditLogger
	mu      sync.RWMutex
}

// NewGatekeeper initializes the gatekeeper instance.
func NewGatekeeper(cfg GatekeeperConfig) (*Gatekeeper, error) {
	if cfg.CapabilityStore == nil {
		return nil, errors.New("capability store is required")
	}
	if len(cfg.Secrets) == 0 {
		return nil, errors.New("at least one gate secret is required")
	}
	cfg.Headers = cfg.Headers.WithDefaults()
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = 2 * time.Minute
	}
	if cfg.NonceStore == nil {
		cfg.NonceStore = NewMemoryNonceStore()
	}
	if cfg.RateLimiter == nil {
		cfg.RateLimiter = NewSlidingWindowLimiter(15*time.Second, 20)
	}
	if cfg.Logger == nil {
		cfg.Logger = NoopAuditLogger{}
	}
	secrets := make(map[string]RotatingSecret, len(cfg.Secrets))
	for _, secret := range cfg.Secrets {
		if secret.ID == "" || len(secret.Secret) == 0 {
			continue
		}
		secrets[secret.ID] = secret
	}
	if len(secrets) == 0 {
		return nil, errors.New("no usable gate secrets configured")
	}
	return &Gatekeeper{
		secrets: secrets,
		cfg:     cfg,
		nonce:   cfg.NonceStore,
		limiter: cfg.RateLimiter,
		logger:  cfg.Logger,
	}, nil
}

// Evaluate enforces headers, capability, nonce, signature, and rate limit.
func (g *Gatekeeper) Evaluate(req GateRequest) (*Capability, error) {
	if g == nil {
		return nil, errors.New("gatekeeper unset")
	}
	headers := req.Headers
	header := func(key string) string {
		if headers == nil {
			return ""
		}
		return strings.TrimSpace(headers[key])
	}

	secretID := header(g.cfg.Headers.SecretID)
	nonce := header(g.cfg.Headers.Nonce)
	timestamp := header(g.cfg.Headers.Timestamp)
	signature := header(g.cfg.Headers.Signature)
	capabilityToken := header(g.cfg.Headers.Capability)

	if secretID == "" || nonce == "" || timestamp == "" || signature == "" || capabilityToken == "" {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "missing header", ErrGateMissingHeader)
		return nil, ErrGateMissingHeader
	}

	tsInt, err := parseUnix(timestamp)
	if err != nil {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "invalid timestamp", err)
		return nil, ErrGateClockSkew
	}

	skew := g.cfg.MaxClockSkew
	delta := time.Since(time.Unix(tsInt, 0))
	if delta > skew || delta < -skew {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "timestamp skew", ErrGateClockSkew)
		return nil, ErrGateClockSkew
	}

	cap, err := g.cfg.CapabilityStore.Validate(capabilityToken, req.Method, req.Path)
	if err != nil {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "capability denied", err)
		return nil, ErrGateCapabilityDenied
	}

	if g.nonce.Seen(secretID, nonce, g.cfg.NonceTTL) {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "nonce replay", ErrGateNonceReplayed)
		return nil, ErrGateNonceReplayed
	}

	secret, err := g.secretFor(secretID, time.Unix(tsInt, 0))
	if err != nil {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "secret invalid", err)
		return nil, err
	}

	expected := computeGateMAC(secret.Secret, req.Method, req.Path, timestamp, nonce, capabilityToken)
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "malformed signature", err)
		return nil, ErrGateSignatureInvalid
	}
	if len(sigBytes) == 0 || len(expected) == 0 || !hmacEqual(expected, sigBytes) {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "signature mismatch", ErrGateSignatureInvalid)
		return nil, ErrGateSignatureInvalid
	}

	limiterKey := capabilityToken
	if req.RemoteAddr != "" {
		limiterKey = capabilityToken + "|" + req.RemoteAddr
	}
	if !g.limiter.Allow(limiterKey) {
		g.audit(AuditEventGateDenied, capabilityToken, req.RemoteAddr, nonce, "rate limited", ErrGateRateLimited)
		return nil, ErrGateRateLimited
	}

	g.audit(AuditEventGateAllowed, capabilityToken, req.RemoteAddr, nonce, fmt.Sprintf("%s %s", req.Method, req.Path), nil)
	return cap, nil
}

func (g *Gatekeeper) secretFor(id string, ts time.Time) (RotatingSecret, error) {
	g.mu.RLock()
	secret, ok := g.secrets[id]
	g.mu.RUnlock()
	if !ok {
		return RotatingSecret{}, ErrGateSecretUnknown
	}
	if !secret.ActiveAt(ts) {
		return RotatingSecret{}, ErrGateSecretExpired
	}
	return secret, nil
}

func (g *Gatekeeper) audit(event AuditEventType, capability, remote, nonce, detail string, err error) {
	if g.logger == nil {
		return
	}
	g.logger.Record(AuditEvent{
		Type:       event,
		Detail:     detail,
		Err:        err,
		Timestamp:  time.Now(),
		Capability: capability,
		RemoteAddr: remote,
		Nonce:      nonce,
	})
}

func computeGateMAC(secret []byte, method, path, timestamp, nonce, capability string) []byte {
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
	payload := []byte(builder.String())
	return crypto.ComputeHMAC(secret, payload)
}

func hmacEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return hmac.Equal(a, b)
}

func parseUnix(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty timestamp")
	}
	var ts int64
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid timestamp")
		}
		ts = ts*10 + int64(ch-'0')
	}
	return ts, nil
}
