package security

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/oarkflow/securehttp/pkg/crypto"
)

const (
	MetadataDeviceID   = "device_id"
	metadataUserID     = "user_id"
	metadataUserRoles  = "user_roles"
	metadataUserPrefix = "user_meta_"
)

var (
	ErrUnknownDevice        = errors.New("unknown device")
	ErrInvalidDeviceSecret  = errors.New("invalid device secret")
	ErrInvalidDevicePayload = errors.New("invalid device payload")
	ErrInvalidUserToken     = errors.New("invalid user token")
	ErrMissingUserToken     = errors.New("user token required")
)

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
}

// DefaultSecurityPolicy returns a policy with no device/user requirements.
func DefaultSecurityPolicy() *SecurityPolicy {
	return &SecurityPolicy{}
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
