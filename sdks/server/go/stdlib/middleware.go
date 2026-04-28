package stdlib

import (
	"context"
	"net/http"

	securecrypto "github.com/oarkflow/securehttp/pkg/crypto"
	corehttp "github.com/oarkflow/securehttp/pkg/http/server"
	"github.com/oarkflow/securehttp/pkg/security"
)

const MaxMessageSize = corehttp.MaxMessageSize

type Config = corehttp.TransportConfig
type Middleware = corehttp.Middleware

func New(policy *security.SecurityPolicy) (*Middleware, error) {
	return corehttp.NewTransport(policy)
}

func NewWithConfig(cfg Config) (*Middleware, error) {
	return corehttp.NewTransportWithConfig(cfg)
}

func GateMiddleware(gate *security.Gatekeeper) func(http.Handler) http.Handler {
	return corehttp.GateMiddleware(gate)
}

func PlaintextBodyFromContext(ctx context.Context) []byte {
	return corehttp.PlaintextBodyFromContext(ctx)
}

func SessionFromContext(ctx context.Context) *securecrypto.Session {
	return corehttp.SessionFromContext(ctx)
}

func SessionIDFromContext(ctx context.Context) string {
	return corehttp.SessionIDFromContext(ctx)
}

func DeviceIDFromContext(ctx context.Context) string {
	return corehttp.DeviceIDFromContext(ctx)
}

func UserContextFromContext(ctx context.Context) *security.UserContext {
	return corehttp.UserContextFromContext(ctx)
}

func CapabilityTokenFromContext(ctx context.Context) string {
	return corehttp.CapabilityTokenFromContext(ctx)
}

func CapabilityMetadataFromContext(ctx context.Context) map[string]string {
	return corehttp.CapabilityMetadataFromContext(ctx)
}

func DecodeJSON(r *http.Request, out any) error {
	return corehttp.DecodeJSON(r, out)
}
