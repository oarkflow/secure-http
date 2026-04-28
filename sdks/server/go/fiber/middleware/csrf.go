package middleware

import (
	"crypto/subtle"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/securehttp/pkg/security"
)

type CSRFConfig struct {
	Enabled    bool
	CookieName string
	HeaderName string
}

type CSRFMiddleware struct {
	enabled    bool
	cookieName string
	headerName string
}

func NewCSRFMiddleware(cfg CSRFConfig) *CSRFMiddleware {
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		cookieName = "securehttp_csrf"
	}
	headerName := strings.TrimSpace(cfg.HeaderName)
	if headerName == "" {
		headerName = "X-CSRF-Token"
	}
	return &CSRFMiddleware{
		enabled:    cfg.Enabled,
		cookieName: cookieName,
		headerName: headerName,
	}
}

func (cm *CSRFMiddleware) Verify() fiber.Handler {
	return func(c fiber.Ctx) error {
		if cm == nil || !cm.enabled || isSafeMethod(c.Method()) {
			return c.Next()
		}
		source, _ := c.Locals("auth_source").(string)
		if source != "cookie" {
			return c.Next()
		}

		claims, _ := c.Locals("token_claims").(*security.StatelessTokenClaims)
		if claims == nil || len(claims.Metadata) == 0 {
			return respondOpaqueAuthFailure(c)
		}
		expected := strings.TrimSpace(claims.Metadata["csrf_token"])
		if expected == "" {
			return respondOpaqueAuthFailure(c)
		}
		headerValue := strings.TrimSpace(c.Get(cm.headerName))
		if headerValue == "" || subtle.ConstantTimeCompare([]byte(headerValue), []byte(expected)) != 1 {
			return respondOpaqueAuthFailure(c)
		}
		cookieValue := strings.TrimSpace(c.Cookies(cm.cookieName))
		if cookieValue == "" || subtle.ConstantTimeCompare([]byte(cookieValue), []byte(expected)) != 1 {
			return respondOpaqueAuthFailure(c)
		}
		return c.Next()
	}
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return true
	default:
		return false
	}
}
