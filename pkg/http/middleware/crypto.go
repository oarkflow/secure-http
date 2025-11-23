package middleware

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/crypto"
	"github.com/oarkflow/securehttp/pkg/security"
)

const (
	MaxMessageSize  = 10 * 1024 * 1024 // 10MB
	headerSessionID = "X-Session-ID"
	headerUserToken = "X-User-Token"
)

// CryptoMiddleware handles encryption/decryption for Fiber
type CryptoMiddleware struct {
	sessionManager *crypto.SessionManager
	policy         *security.SecurityPolicy
}

// NewCryptoMiddleware creates a new crypto middleware
func NewCryptoMiddleware(policy *security.SecurityPolicy) (*CryptoMiddleware, error) {
	if policy == nil {
		policy = security.DefaultSecurityPolicy()
	}
	if err := policy.ValidateReady(); err != nil {
		return nil, err
	}
	sm, err := crypto.NewSessionManager()
	if err != nil {
		return nil, err
	}

	return &CryptoMiddleware{
		sessionManager: sm,
		policy:         policy,
	}, nil
}

// GetSessionManager returns the session manager (for handshake endpoint)
func (cm *CryptoMiddleware) GetSessionManager() *crypto.SessionManager {
	return cm.sessionManager
}

// Decrypt middleware decrypts incoming requests
func (cm *CryptoMiddleware) Decrypt() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get session ID from header
		sessionID := c.Get(headerSessionID)
		if sessionID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing session ID",
			})
		}

		// Get session
		session, exists := cm.sessionManager.GetSession(sessionID)
		if !exists {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired session",
			})
		}

		var userCtx *security.UserContext
		if cm.policy != nil && cm.policy.UserAuthenticator != nil {
			token := c.Get(headerUserToken)
			if token != "" {
				ctx, err := cm.policy.UserAuthenticator.Validate(token)
				if err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "Invalid user token",
					})
				}
				userCtx = ctx
			} else if cm.policy.RequireUser {
				userCtx = security.ExtractUserContext(session.Metadata)
				if userCtx == nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "Missing user token",
					})
				}
			}
		} else if cm.policy != nil && cm.policy.RequireUser {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User verification disabled",
			})
		} else {
			userCtx = security.ExtractUserContext(session.Metadata)
		}

		// Read encrypted body
		body := c.Body()
		if len(body) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Empty request body",
			})
		}

		if len(body) > MaxMessageSize {
			return c.Status(fiber.StatusRequestEntityTooLarge).JSON(fiber.Map{
				"error": "Request too large",
			})
		}

		// Parse encrypted message
		var encMsg crypto.EncryptedMessage
		if err := json.Unmarshal(body, &encMsg); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid encrypted message format",
			})
		}

		// Decrypt
		plaintext, err := session.Decrypt(&encMsg)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Decryption failed: " + err.Error(),
			})
		}

		// Store decrypted data in context
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
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Session not found in context",
			})
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
		// Parse handshake request
		var req crypto.HandshakeRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid request format",
			})
		}

		// Verify timestamp (60 second window)
		now := time.Now().Unix()
		if abs(now-req.Timestamp) > 60 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid timestamp",
			})
		}

		// Optional device binding
		if cm.policy != nil && cm.policy.RequireDevice {
			if req.DeviceID == "" || len(req.DeviceSignature) == 0 {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Missing device identity",
				})
			}
			payload := security.DeviceAuthenticationPayload(req.ClientPublicKey, req.Timestamp)
			if err := cm.policy.DeviceRegistry.Validate(req.DeviceID, req.DeviceSignature, payload); err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "Device validation failed",
				})
			}
		}

		var userCtx *security.UserContext
		if cm.policy != nil && cm.policy.UserAuthenticator != nil {
			if req.UserToken == "" {
				if cm.policy.RequireUser {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "Missing user token",
					})
				}
			} else {
				ctx, err := cm.policy.UserAuthenticator.Validate(req.UserToken)
				if err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "Invalid user token",
					})
				}
				userCtx = ctx
			}
		} else if cm.policy != nil && cm.policy.RequireUser {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "User verification disabled",
			})
		}

		metadata := make(map[string]string)
		if req.DeviceID != "" {
			metadata[security.MetadataDeviceID] = req.DeviceID
		}
		if userCtx != nil {
			security.AttachUserContext(metadata, userCtx)
		}
		if len(metadata) == 0 {
			metadata = nil
		}

		// Create session
		sessionID, err := cm.sessionManager.CreateSession(req.ClientPublicKey, metadata)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to create session",
			})
		}

		// Prepare response
		nowTime := time.Now()
		resp := crypto.HandshakeResponse{
			ServerPublicKey: cm.sessionManager.GetPublicKey(),
			SessionID:       []byte(sessionID),
			DeviceID:        req.DeviceID,
			ExpiresAt:       nowTime.Add(crypto.SessionTimeout).Unix(),
			Timestamp:       nowTime.Unix(),
		}

		return c.JSON(resp)
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
