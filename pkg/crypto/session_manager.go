package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// SessionManagerConfig controls lifecycle behavior.
type SessionManagerConfig struct {
	SessionTimeout  time.Duration
	CleanupInterval time.Duration
	MessageTTL      time.Duration
}

// SessionManager manages encryption sessions
type SessionManager struct {
	sessions   map[string]*Session
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	config     SessionManagerConfig
	mu         sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() (*SessionManager, error) {
	return NewSessionManagerWithConfig(SessionManagerConfig{})
}

// NewSessionManagerWithConfig allows customizing lifecycle parameters.
func NewSessionManagerWithConfig(cfg SessionManagerConfig) (*SessionManager, error) {
	if cfg.SessionTimeout <= 0 {
		cfg.SessionTimeout = SessionTimeout
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.MessageTTL <= 0 {
		cfg.MessageTTL = DefaultMessageTTL
	}

	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	sm := &SessionManager{
		sessions:   make(map[string]*Session),
		privateKey: privKey,
		publicKey:  pubKey,
		config:     cfg,
	}

	go sm.cleanupExpiredSessions()
	return sm, nil
}

// GetPublicKey returns the server's public key
func (sm *SessionManager) GetPublicKey() []byte {
	return sm.publicKey.Bytes()
}

// CreateSession creates a new session from client public key
func (sm *SessionManager) CreateSession(clientPublicKey []byte, metadata map[string]string) (string, error) {
	// Perform ECDH
	sharedSecret, err := PerformECDH(sm.privateKey, clientPublicKey)
	if err != nil {
		return "", err
	}

	// Derive session keys
	encKey, macKey, err := DeriveKeys(sharedSecret)
	if err != nil {
		return "", err
	}

	// Create session
	session := &Session{
		SharedSecret: sharedSecret,
		EncKey:       encKey,
		MacKey:       macKey,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		Nonce:        0,
		Metadata:     cloneMetadata(metadata),
		SessionTTL:   sm.config.SessionTimeout,
		MessageTTL:   sm.config.MessageTTL,
	}

	// Generate session ID
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return "", err
	}

	sessionIDStr := base64.StdEncoding.EncodeToString(sessionID)

	sm.mu.Lock()
	sm.sessions[sessionIDStr] = session
	sm.mu.Unlock()

	return sessionIDStr, nil
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	copyMap := make(map[string]string, len(src))
	for k, v := range src {
		copyMap[k] = v
	}
	return copyMap
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists || session.IsExpired() {
		return nil, false
	}

	return session, true
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

// cleanupExpiredSessions periodically removes expired sessions
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		for id, session := range sm.sessions {
			if session.IsExpired() {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

// SessionCount returns the number of active sessions
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}
