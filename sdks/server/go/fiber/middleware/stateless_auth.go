package middleware

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/security"
)

// StatelessAuthMiddleware provides stateless JWT authentication
type StatelessAuthMiddleware struct {
	auth       *security.StatelessAuthenticator
	cookieName string
}

type StatelessAuthConfig struct {
	CookieName string
}

// NewStatelessAuthMiddleware creates a new stateless auth middleware
func NewStatelessAuthMiddleware(auth *security.StatelessAuthenticator) *StatelessAuthMiddleware {
	return NewStatelessAuthMiddlewareWithConfig(auth, StatelessAuthConfig{})
}

func NewStatelessAuthMiddlewareWithConfig(auth *security.StatelessAuthenticator, cfg StatelessAuthConfig) *StatelessAuthMiddleware {
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		cookieName = "securehttp_access"
	}
	return &StatelessAuthMiddleware{
		auth:       auth,
		cookieName: cookieName,
	}
}

// Verify validates the JWT token and injects claims into context
func (sam *StatelessAuthMiddleware) Verify() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token, source, err := sam.resolveToken(c)
		if err != nil {
			return respondOpaqueAuthFailure(c)
		}

		// Compute current fingerprint
		fingerprint := security.ComputeSessionFingerprint(
			c.IP(),
			string(c.Context().UserAgent()),
		)

		// Validate token
		claims, err := sam.auth.ValidateToken(token, "access", fingerprint)
		if err != nil {
			return respondOpaqueAuthFailure(c)
		}

		// Inject claims into context
		c.Locals("token_claims", claims)
		c.Locals("user_id", claims.UserID)
		c.Locals("device_id", claims.DeviceID)
		c.Locals("user_roles", claims.Roles)
		c.Locals("token_id", claims.TokenID)
		c.Locals("auth_source", source)

		// Create user context for compatibility with existing middleware
		userCtx := &security.UserContext{
			ID:       claims.UserID,
			Roles:    claims.Roles,
			Metadata: claims.Metadata,
		}
		c.Locals("user_context", userCtx)

		return c.Next()
	}
}

func (sam *StatelessAuthMiddleware) resolveToken(c *fiber.Ctx) (string, string, error) {
	if sam == nil || c == nil {
		return "", "", fiber.ErrUnauthorized
	}
	authHeader := strings.TrimSpace(c.Get("Authorization"))
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return "", "", errors.New("invalid authorization format")
		}
		token := strings.TrimSpace(parts[1])
		if token == "" {
			return "", "", errors.New("missing bearer token")
		}
		return token, "header", nil
	}
	cookieName := strings.TrimSpace(sam.cookieName)
	if cookieName != "" {
		if token := strings.TrimSpace(c.Cookies(cookieName)); token != "" {
			return token, "cookie", nil
		}
	}
	return "", "", errors.New("missing authorization token")
}

// RequireRole middleware checks if user has required role
func (sam *StatelessAuthMiddleware) RequireRole(requiredRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("token_claims").(*security.StatelessTokenClaims)
		if !ok || claims == nil {
			return respondOpaqueAuthFailure(c)
		}

		// Check if user has any of the required roles
		userRoles := make(map[string]bool)
		for _, role := range claims.Roles {
			userRoles[role] = true
		}

		for _, required := range requiredRoles {
			if userRoles[required] {
				return c.Next()
			}
		}

		return respondOpaqueAuthFailure(c)
	}
}

// RequirePermission middleware checks if user has required permission
func (sam *StatelessAuthMiddleware) RequirePermission(requiredPerms ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("token_claims").(*security.StatelessTokenClaims)
		if !ok || claims == nil {
			return respondOpaqueAuthFailure(c)
		}

		// Check if user has any of the required permissions
		userPerms := make(map[string]bool)
		for _, perm := range claims.Permissions {
			userPerms[perm] = true
		}

		for _, required := range requiredPerms {
			if userPerms[required] {
				return c.Next()
			}
		}

		return respondOpaqueAuthFailure(c)
	}
}
