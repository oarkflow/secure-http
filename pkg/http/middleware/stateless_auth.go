package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/security"
)

// StatelessAuthMiddleware provides stateless JWT authentication
type StatelessAuthMiddleware struct {
	auth *security.StatelessAuthenticator
}

// NewStatelessAuthMiddleware creates a new stateless auth middleware
func NewStatelessAuthMiddleware(auth *security.StatelessAuthenticator) *StatelessAuthMiddleware {
	return &StatelessAuthMiddleware{
		auth: auth,
	}
}

// Verify validates the JWT token and injects claims into context
func (sam *StatelessAuthMiddleware) Verify() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract token from Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		// Extract Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization format",
			})
		}

		token := parts[1]

		// Compute current fingerprint
		fingerprint := security.ComputeSessionFingerprint(
			c.IP(),
			string(c.Context().UserAgent()),
		)

		// Validate token
		claims, err := sam.auth.ValidateToken(token, "access", fingerprint)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}

		// Inject claims into context
		c.Locals("token_claims", claims)
		c.Locals("user_id", claims.UserID)
		c.Locals("device_id", claims.DeviceID)
		c.Locals("user_roles", claims.Roles)
		c.Locals("token_id", claims.TokenID)

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

// RequireRole middleware checks if user has required role
func (sam *StatelessAuthMiddleware) RequireRole(requiredRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("token_claims").(*security.StatelessTokenClaims)
		if !ok || claims == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
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

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "insufficient permissions",
		})
	}
}

// RequirePermission middleware checks if user has required permission
func (sam *StatelessAuthMiddleware) RequirePermission(requiredPerms ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims, ok := c.Locals("token_claims").(*security.StatelessTokenClaims)
		if !ok || claims == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
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

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "insufficient permissions",
		})
	}
}
