package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/securehttp/pkg/crypto"
)

const (
	MetadataDeviceID           = "device_id"
	metadataUserID             = "user_id"
	metadataUserRoles          = "user_roles"
	metadataUserPrefix         = "user_meta_"
	metadataSessionFingerprint = "session_fp"
)

// HeaderNames defines transport headers used for session coordination.
type HeaderNames struct {
	SessionID string
	UserToken string
}

// WithDefaults ensures no header value is empty.
func (h HeaderNames) WithDefaults() HeaderNames {
	if h.SessionID == "" {
		h.SessionID = "X-Session-ID"
	}
	if h.UserToken == "" {
		h.UserToken = "X-User-Token"
	}
	return h
}

// DefaultHeaderNames returns the standard header layout.
func DefaultHeaderNames() HeaderNames {
	return HeaderNames{
		SessionID: "X-Session-ID",
		UserToken: "X-User-Token",
	}
}

var (
	ErrUnknownDevice        = errors.New("unknown device")
	ErrInvalidDeviceSecret  = errors.New("invalid device secret")
	ErrInvalidDevicePayload = errors.New("invalid device payload")
	ErrInvalidUserToken     = errors.New("invalid user token")
	ErrMissingUserToken     = errors.New("user token required")
)

// AuditEventType represents a security lifecycle hook.
type AuditEventType string

const (
	AuditEventHandshakeSuccess AuditEventType = "handshake_success"
	AuditEventHandshakeFailure AuditEventType = "handshake_failure"
	AuditEventDecryptSuccess   AuditEventType = "decrypt_success"
	AuditEventDecryptFailure   AuditEventType = "decrypt_failure"
	AuditEventGateAllowed      AuditEventType = "gate_allowed"
	AuditEventGateDenied       AuditEventType = "gate_denied"
	AuditEventPentestProbe     AuditEventType = "pentest_probe"
	AuditEventLogout           AuditEventType = "logout"
)

// AuditEvent captures notable security events for logging/metrics.
type AuditEvent struct {
	Type       AuditEventType
	SessionID  string
	DeviceID   string
	UserID     string
	Capability string
	RemoteAddr string
	Nonce      string
	Detail     string
	Err        error
	Timestamp  time.Time
}

// Capability describes an allowed method/path tuple granted by a token.
type Capability struct {
	Token    string
	Methods  map[string]struct{}
	Paths    []string
	Rules    []CapabilityRule
	Metadata map[string]string
}

// CapabilityRule restricts a token to a specific path+method surface.
type CapabilityRule struct {
	Path    string
	Methods map[string]struct{}
}

// Allows returns true when the capability covers the method/path.
func (c *Capability) Allows(method, path string) bool {
	if c == nil {
		return false
	}
	if len(c.Rules) > 0 {
		for _, rule := range c.Rules {
			if rule.allows(method, path) {
				return true
			}
		}
		return false
	}
	if len(c.Methods) > 0 {
		if _, ok := c.Methods[strings.ToUpper(method)]; !ok {
			return false
		}
	}
	if len(c.Paths) == 0 {
		return true
	}
	for _, allowed := range c.Paths {
		if pathMatches(allowed, path) {
			return true
		}
	}
	return false
}

func (r CapabilityRule) allows(method, path string) bool {
	if r.Path == "" {
		return false
	}
	if !pathMatches(r.Path, path) {
		return false
	}
	if len(r.Methods) == 0 {
		return true
	}
	_, ok := r.Methods[strings.ToUpper(method)]
	return ok
}

func pathMatches(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return pattern == path
}

// AuditLogger receives security events.
type AuditLogger interface {
	Record(AuditEvent)
}

// AuditLoggerFunc adapts a function to AuditLogger.
type AuditLoggerFunc func(AuditEvent)

// Record implements AuditLogger.
func (f AuditLoggerFunc) Record(evt AuditEvent) {
	if f == nil {
		return
	}
	f(evt)
}

// NoopAuditLogger ignores all events.
type NoopAuditLogger struct{}

// Record implements AuditLogger.
func (NoopAuditLogger) Record(AuditEvent) {}

// MultiAuditLogger fans out audit events to multiple loggers.
type MultiAuditLogger []AuditLogger

// Record implements AuditLogger.
func (ml MultiAuditLogger) Record(evt AuditEvent) {
	for _, logger := range ml {
		if logger == nil {
			continue
		}
		logger.Record(evt)
	}
}

// DeviceRegistry validates device signatures during the handshake.
type DeviceRegistry interface {
	Validate(deviceID string, signature []byte, payload []byte) error
}

// UserAuthenticator validates user tokens and produces contextual claims.
type UserAuthenticator interface {
	Validate(token string) (*UserContext, error)
}

// SecurityPolicy drives device and user level protections applied by the middleware.
type SecurityPolicy struct {
	RequireDevice     bool
	RequireUser       bool
	DeviceRegistry    DeviceRegistry
	UserAuthenticator UserAuthenticator
	MaxClockSkew      time.Duration
	SessionTTL        time.Duration
	MessageTTL        time.Duration
	Logger            AuditLogger
}

// DefaultSecurityPolicy returns a policy with no device/user requirements.
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{
		MaxClockSkew: time.Minute,
		SessionTTL:   crypto.SessionTimeout,
		MessageTTL:   crypto.DefaultMessageTTL,
	}
}

// ValidateReady ensures mandatory dependencies are set before runtime use.
func (p *SecurityPolicy) ValidateReady() error {
	if p == nil {
		return nil
	}
	if p.RequireDevice && p.DeviceRegistry == nil {
		return errors.New("device registry required but missing")
	}
	if p.RequireUser && p.UserAuthenticator == nil {
		return errors.New("user authenticator required but missing")
	}
	if p.MaxClockSkew <= 0 {
		p.MaxClockSkew = time.Minute
	}
	if p.SessionTTL <= 0 {
		p.SessionTTL = crypto.SessionTimeout
	}
	if p.MessageTTL <= 0 {
		p.MessageTTL = crypto.DefaultMessageTTL
	}
	if p.Logger == nil {
		p.Logger = NoopAuditLogger{}
	}
	return nil
}

// UserContext captures authenticated user metadata propagated through the secure layer.
type UserContext struct {
	ID       string            `json:"id"`
	Roles    []string          `json:"roles,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Summary returns a compact string useful for logging/auditing flows.
func (ctx *UserContext) Summary() string {
	if ctx == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("user_id=%s", ctx.ID)}
	if len(ctx.Roles) > 0 {
		parts = append(parts, fmt.Sprintf("roles=%v", ctx.Roles))
	}
	if len(ctx.Metadata) > 0 {
		parts = append(parts, fmt.Sprintf("metadata_keys=%d", len(ctx.Metadata)))
	}
	return strings.Join(parts, ";")
}

// InMemoryDeviceRegistry is a helper registry for demos/tests; production systems can plug their own.
type InMemoryDeviceRegistry struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

// NewInMemoryDeviceRegistry constructs an empty registry.
func NewInMemoryDeviceRegistry() *InMemoryDeviceRegistry {
	return &InMemoryDeviceRegistry{
		secrets: make(map[string][]byte),
	}
}

// Register stores a device secret used to validate handshake signatures.
func (r *InMemoryDeviceRegistry) Register(deviceID string, secret []byte) {
	if deviceID == "" || len(secret) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	secretCopy := make([]byte, len(secret))
	copy(secretCopy, secret)
	r.secrets[deviceID] = secretCopy
}

// Validate ensures the provided signature matches the registry secret for the device.
func (r *InMemoryDeviceRegistry) Validate(deviceID string, signature []byte, payload []byte) error {
	if len(payload) == 0 {
		return ErrInvalidDevicePayload
	}

	r.mu.RLock()
	secret, ok := r.secrets[deviceID]
	r.mu.RUnlock()
	if !ok {
		return ErrUnknownDevice
	}

	expected := crypto.ComputeHMAC(secret, payload)
	if !hmac.Equal(expected, signature) {
		return ErrInvalidDeviceSecret
	}

	return nil
}

// DeviceAuthenticationPayload ensures the client and server sign/verify the same byte layout.
func DeviceAuthenticationPayload(clientPublicKey []byte, timestamp int64) []byte {
	payload := make([]byte, 0, len(clientPublicKey)+8)
	payload = append(payload, clientPublicKey...)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	payload = append(payload, ts...)
	return payload
}

// StaticUserAuthenticator is a deterministic authenticator for demos/tests.
type StaticUserAuthenticator struct {
	mu    sync.RWMutex
	users map[string]*UserContext
}

// NewStaticUserAuthenticator bootstraps the authenticator instance.
func NewStaticUserAuthenticator() *StaticUserAuthenticator {
	return &StaticUserAuthenticator{
		users: make(map[string]*UserContext),
	}
}

// Register stores a token->context mapping.
func (a *StaticUserAuthenticator) Register(token string, ctx *UserContext) {
	if token == "" || ctx == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[token] = copyUserContext(ctx)
}

// Validate returns a cloned context for the supplied token.
func (a *StaticUserAuthenticator) Validate(token string) (*UserContext, error) {
	if token == "" {
		return nil, ErrMissingUserToken
	}
	a.mu.RLock()
	ctx, ok := a.users[token]
	a.mu.RUnlock()
	if !ok {
		return nil, ErrInvalidUserToken
	}
	return copyUserContext(ctx), nil
}

func copyUserContext(ctx *UserContext) *UserContext {
	if ctx == nil {
		return nil
	}
	clone := &UserContext{ID: ctx.ID}
	if len(ctx.Roles) > 0 {
		clone.Roles = append([]string{}, ctx.Roles...)
	}
	if len(ctx.Metadata) > 0 {
		clone.Metadata = make(map[string]string, len(ctx.Metadata))
		for k, v := range ctx.Metadata {
			clone.Metadata[k] = v
		}
	}
	return clone
}

// AttachUserContext flattens a user context into metadata stored on the crypto session.
func AttachUserContext(metadata map[string]string, ctx *UserContext) {
	if metadata == nil || ctx == nil {
		return
	}
	metadata[metadataUserID] = ctx.ID
	if len(ctx.Roles) > 0 {
		metadata[metadataUserRoles] = strings.Join(ctx.Roles, ",")
	}
	for k, v := range ctx.Metadata {
		metadata[metadataUserPrefix+k] = v
	}
}

// ExtractUserContext hydrates a user context from session metadata.
func ExtractUserContext(metadata map[string]string) *UserContext {
	if len(metadata) == 0 {
		return nil
	}
	id := metadata[metadataUserID]
	if id == "" {
		return nil
	}
	ctx := &UserContext{ID: id}
	if rawRoles := metadata[metadataUserRoles]; rawRoles != "" {
		ctx.Roles = strings.Split(rawRoles, ",")
	}
	for k, v := range metadata {
		if strings.HasPrefix(k, metadataUserPrefix) {
			if ctx.Metadata == nil {
				ctx.Metadata = make(map[string]string)
			}
			ctx.Metadata[strings.TrimPrefix(k, metadataUserPrefix)] = v
		}
	}
	return ctx
}

// StoreSessionFingerprint binds a session to a hashed client fingerprint.
func StoreSessionFingerprint(metadata map[string]string, fingerprint string) {
	if metadata == nil || fingerprint == "" {
		return
	}
	metadata[metadataSessionFingerprint] = fingerprint
}

// VerifySessionFingerprint ensures the inbound request matches the stored fingerprint.
func VerifySessionFingerprint(metadata map[string]string, fingerprint string) bool {
	if fingerprint == "" || len(metadata) == 0 {
		return false
	}
	stored := metadata[metadataSessionFingerprint]
	if stored == "" {
		return false
	}
	return hmac.Equal([]byte(stored), []byte(fingerprint))
}

// ComputeSessionFingerprint hashes identifying request traits to guard against hijacking.
func ComputeSessionFingerprint(ip, userAgent string) string {
	if strings.TrimSpace(ip) == "" && strings.TrimSpace(userAgent) == "" {
		return ""
	}
	composite := strings.TrimSpace(ip) + "|" + strings.TrimSpace(userAgent)
	sum := sha256.Sum256([]byte(composite))
	return hex.EncodeToString(sum[:])
}
