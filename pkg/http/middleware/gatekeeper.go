package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/security"
)

// GateMiddleware enforces the pre-routing crypto gate.
type GateMiddleware struct {
	gate *security.Gatekeeper
}

// NewGateMiddleware wires a gatekeeper instance into Fiber.
func NewGateMiddleware(gate *security.Gatekeeper) *GateMiddleware {
	return &GateMiddleware{gate: gate}
}

// Handle validates gate headers and short-circuits on failure.
func (gm *GateMiddleware) Handle() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if gm == nil || gm.gate == nil {
			return respondNotFound(c)
		}
		headers := normalizeHeaders(c.GetReqHeaders())
		capability, err := gm.gate.Evaluate(security.GateRequest{
			Method:     c.Method(),
			Path:       string(c.Request().URI().Path()),
			Headers:    headers,
			RemoteAddr: c.IP(),
		})
		if err != nil {
			return respondNotFound(c)
		}
		if capability != nil {
			c.Locals("capability_token", capability.Token)
			c.Locals("capability_meta", capability.Metadata)
		}
		return c.Next()
	}
}

func normalizeHeaders(source map[string][]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	flattened := make(map[string]string, len(source))
	for key, values := range source {
		if len(values) == 0 {
			continue
		}
		flattened[key] = values[0]
	}
	return flattened
}
