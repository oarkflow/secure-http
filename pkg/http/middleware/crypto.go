package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
)

const (
	MaxMessageSize = 10 * 1024 * 1024 // 10MB
)

// Config defines how the crypto middleware behaves.
type Config struct {
	Policy               *security.SecurityPolicy
	Headers              security.HeaderNames
	SessionManagerConfig crypto.SessionManagerConfig
}

// CryptoMiddleware handles encryption/decryption for Fiber
type CryptoMiddleware struct {
	sessionManager *crypto.SessionManager
	policy         *security.SecurityPolicy
	headers        security.HeaderNames
}

// NewCryptoMiddleware creates a new crypto middleware
func NewCryptoMiddleware(policy *security.SecurityPolicy) (*CryptoMiddleware, error) {
	return NewCryptoMiddlewareWithConfig(Config{Policy: policy})
}

// NewCryptoMiddlewareWithConfig builds the middleware with advanced options.
func NewCryptoMiddlewareWithConfig(cfg Config) (*CryptoMiddleware, error) {
	policy := cfg.Policy
	if policy == nil {
		policy = security.DefaultSecurityPolicy()
	}
	if err := policy.ValidateReady(); err != nil {
		return nil, err
	}
	headers := cfg.Headers.WithDefaults()
	sessionCfg := cfg.SessionManagerConfig
	if sessionCfg.SessionTimeout <= 0 {
		sessionCfg.SessionTimeout = policy.SessionTTL
	}
	if sessionCfg.MessageTTL <= 0 {
		sessionCfg.MessageTTL = policy.MessageTTL
	}
	if sessionCfg.CleanupInterval <= 0 {
		sessionCfg.CleanupInterval = 5 * time.Minute
	}
	sm, err := crypto.NewSessionManagerWithConfig(sessionCfg)
	if err != nil {
		return nil, err
	}

	return &CryptoMiddleware{
		sessionManager: sm,
		policy:         policy,
		headers:        headers,
	}, nil
}

// GetSessionManager returns the session manager (for handshake endpoint)
func (cm *CryptoMiddleware) GetSessionManager() *crypto.SessionManager {
	return cm.sessionManager
}

// Decrypt middleware decrypts incoming requests
func (cm *CryptoMiddleware) Decrypt() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sessionID := c.Get(cm.headers.SessionID)
		if sessionID == "" {
			cm.logEvent(security.AuditEventDecryptFailure, "", "", nil, "missing session header", fmt.Errorf("missing session"))
			return respondNotFound(c)
		}

		session, exists := cm.sessionManager.GetSession(sessionID)
		if !exists {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, "", nil, "session not found", fmt.Errorf("session invalid"))
			return respondNotFound(c)
		}

		fingerprint := clientFingerprint(c)
		if !security.VerifySessionFingerprint(session.Metadata, fingerprint) {
			cm.sessionManager.DeleteSession(sessionID)
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "fingerprint mismatch", fmt.Errorf("session fingerprint mismatch"))
			return respondNotFound(c)
		}

		var userCtx *security.UserContext
		if cm.policy != nil && cm.policy.UserAuthenticator != nil {
			token := c.Get(cm.headers.UserToken)
			if token != "" {
				ctx, err := cm.policy.UserAuthenticator.Validate(token)
				if err != nil {
					cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "user token invalid", err)
					return respondNotFound(c)
				}
				userCtx = ctx
			} else if cm.policy.RequireUser {
				userCtx = security.ExtractUserContext(session.Metadata)
				if userCtx == nil {
					cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "missing user token", fmt.Errorf("user token missing"))
					return respondNotFound(c)
				}
			}
		} else if cm.policy != nil && cm.policy.RequireUser {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], nil, "user verification disabled", fmt.Errorf("user verification disabled"))
			return respondNotFound(c)
		} else {
			userCtx = security.ExtractUserContext(session.Metadata)
		}

		body := c.Body()
		if len(body) == 0 {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "empty body", fmt.Errorf("empty body"))
			return respondNotFound(c)
		}
		if len(body) > MaxMessageSize {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "payload too large", fmt.Errorf("payload too large"))
			return respondNotFound(c)
		}

		var encMsg crypto.EncryptedMessage
		if err := json.Unmarshal(body, &encMsg); err != nil {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "invalid envelope", err)
			return respondNotFound(c)
		}

		plaintext, err := session.Decrypt(&encMsg)
		if err != nil {
			cm.logEvent(security.AuditEventDecryptFailure, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "decrypt failure", err)
			return respondNotFound(c)
		}

		c.Locals("decrypted_body", plaintext)
		c.Locals("session", session)
		c.Locals("session_id", sessionID)
		if session.Metadata != nil {
			if deviceID := session.Metadata[security.MetadataDeviceID]; deviceID != "" {
				c.Locals("device_id", deviceID)
			}
		}
		if userCtx == nil {
			userCtx = security.ExtractUserContext(session.Metadata)
		}
		if userCtx != nil {
			c.Locals("user_context", userCtx)
		}
		cm.logEvent(security.AuditEventDecryptSuccess, sessionID, session.Metadata[security.MetadataDeviceID], userCtx, "payload decrypted", nil)

		return c.Next()
	}
}

// Encrypt middleware encrypts outgoing responses
func (cm *CryptoMiddleware) Encrypt() fiber.Handler {
	return func(c *fiber.Ctx) error {
		buf := &bytes.Buffer{}

		// Replace the body writer temporarily
		c.Context().Response.SetBodyStream(buf, -1)

		// Call next handler
		err := c.Next()
		if err != nil {
			return err
		}

		// Get session from context
		session, ok := c.Locals("session").(*crypto.Session)
		if !ok {
			return respondNotFound(c)
		}

		// Get the response body that was written
		responseBody := c.Response().Body()

		// Don't encrypt if response is empty or an error status
		if len(responseBody) == 0 || c.Response().StatusCode() >= 400 {
			return nil
		}

		// Encrypt response
		encMsg, err := session.Encrypt(responseBody)
		if err != nil {
			c.Response().Reset()
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Encryption failed",
			})
		}

		// Marshal encrypted message
		encryptedBody, err := json.Marshal(encMsg)
		if err != nil {
			c.Response().Reset()
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to marshal encrypted response",
			})
		}

		// Replace response body with encrypted version
		c.Response().Reset()
		c.Set(fiber.HeaderContentType, "application/octet-stream")
		return c.Send(encryptedBody)
	}
}

// Handshake handles the key exchange
func (cm *CryptoMiddleware) Handshake() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req crypto.HandshakeRequest
		if err := c.BodyParser(&req); err != nil {
			cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "invalid payload", err)
			return respondNotFound(c)
		}

		if cm.policy != nil {
			skew := cm.policy.MaxClockSkew
			if skew <= 0 {
				skew = time.Minute
			}
			ts := time.Unix(req.Timestamp, 0)
			delta := time.Since(ts)
			if delta > skew || delta < -skew {
				cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "timestamp out of range", fmt.Errorf("timestamp skew"))
				return respondNotFound(c)
			}
		}

		if cm.policy != nil && cm.policy.RequireDevice {
			if req.DeviceID == "" || len(req.DeviceSignature) == 0 {
				cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "missing device identity", fmt.Errorf("missing device"))
				return respondNotFound(c)
			}
			payload := security.DeviceAuthenticationPayload(req.ClientPublicKey, req.Timestamp)
			if err := cm.policy.DeviceRegistry.Validate(req.DeviceID, req.DeviceSignature, payload); err != nil {
				cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "device validation failed", err)
				return respondNotFound(c)
			}
		}

		var userCtx *security.UserContext
		if cm.policy != nil && cm.policy.UserAuthenticator != nil {
			if req.UserToken == "" {
				if cm.policy.RequireUser {
					cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "missing user token", fmt.Errorf("missing user token"))
					return respondNotFound(c)
				}
			} else {
				ctx, err := cm.policy.UserAuthenticator.Validate(req.UserToken)
				if err != nil {
					cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "user token invalid", err)
					return respondNotFound(c)
				}
				userCtx = ctx
			}
		} else if cm.policy != nil && cm.policy.RequireUser {
			cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, nil, "user verification disabled", fmt.Errorf("user verification disabled"))
			return respondNotFound(c)
		}

		metadata := make(map[string]string)
		if req.DeviceID != "" {
			metadata[security.MetadataDeviceID] = req.DeviceID
		}
		if userCtx != nil {
			security.AttachUserContext(metadata, userCtx)
		}
		fingerprint := clientFingerprint(c)
		if fingerprint != "" {
			security.StoreSessionFingerprint(metadata, fingerprint)
		}
		if len(metadata) == 0 {
			metadata = nil
		}

		sessionID, err := cm.sessionManager.CreateSession(req.ClientPublicKey, metadata)
		if err != nil {
			cm.logEvent(security.AuditEventHandshakeFailure, "", req.DeviceID, userCtx, "session creation failed", err)
			return respondNotFound(c)
		}

		nowTime := time.Now()
		resp := crypto.HandshakeResponse{
			ServerPublicKey: cm.sessionManager.GetPublicKey(),
			SessionID:       []byte(sessionID),
			DeviceID:        req.DeviceID,
			ExpiresAt:       nowTime.Add(cm.policy.SessionTTL).Unix(),
			Timestamp:       nowTime.Unix(),
		}

		cm.logEvent(security.AuditEventHandshakeSuccess, sessionID, req.DeviceID, userCtx, "session established", nil)
		return c.JSON(resp)
	}
}

// logEvent forwards structured events to the configured audit logger.
func (cm *CryptoMiddleware) logEvent(eventType security.AuditEventType, sessionID, deviceID string, userCtx *security.UserContext, detail string, err error) {
	if cm == nil || cm.policy == nil || cm.policy.Logger == nil {
		return
	}
	evt := security.AuditEvent{
		Type:      eventType,
		SessionID: sessionID,
		DeviceID:  deviceID,
		Detail:    detail,
		Err:       err,
		Timestamp: time.Now(),
	}
	if userCtx != nil {
		evt.UserID = userCtx.ID
	}
	cm.policy.Logger.Record(evt)
}

func clientFingerprint(c *fiber.Ctx) string {
	if c == nil {
		return ""
	}
	return security.ComputeSessionFingerprint(c.IP(), string(c.Context().UserAgent()))
}
