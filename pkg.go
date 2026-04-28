package securehttp

import (
	"github.com/gofiber/fiber/v3"
	"github.com/oarkflow/securehttp/pkg/browser"
	"github.com/oarkflow/securehttp/pkg/config"
	httpclient "github.com/oarkflow/securehttp/pkg/http/client"
	"github.com/oarkflow/securehttp/pkg/security"
	httpserver "github.com/oarkflow/securehttp/sdks/server/go/fiber/server"
	serversdk "github.com/oarkflow/securehttp/sdks/server/go/manifest"
	httpstdlib "github.com/oarkflow/securehttp/sdks/server/go/stdlib"
)

type SecureClient = httpclient.SecureClient
type ClientConfig = httpclient.Config
type GateClientConfig = httpclient.GateClientConfig
type GateSecret = httpclient.GateSecret

type Server = httpserver.Server
type ServerOptions = httpserver.Options
type ServerDependencies = httpserver.Dependencies
type ServerRuntime = httpserver.Runtime
type ServerRuntimeOptions = httpserver.RuntimeOptions
type FiberServerMountOptions = httpserver.MountOptions
type FiberMountedRoutes = httpserver.MountedRoutes
type AuthSession = httpserver.AuthSession
type BrowserGateSecret = browser.GateSecret
type BrowserLoginResponse = browser.LoginResponse
type BrowserBootstrapConfig = browser.BootstrapConfig
type BrowserLoginResponseOptions = browser.LoginResponseOptions
type BrowserBootstrapOptions = browser.BootstrapOptions
type FiberBrowserLoginResponseOptions = httpserver.BrowserLoginResponseOptions
type FiberBrowserBootstrapOptions = httpserver.BrowserBootstrapOptions
type StdHTTPMiddleware = httpstdlib.Middleware
type StdHTTPMiddlewareConfig = httpstdlib.Config
type ServerSDKManifest = serversdk.Manifest
type ServerSDKManifestOptions = serversdk.ManifestOptions

func NewClient(cfg ClientConfig) (*SecureClient, error) {
	return httpclient.NewSecureClient(cfg)
}

func NewClientFromFile(path string) (*SecureClient, error) {
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		return nil, err
	}
	return httpclient.NewSecureClient(*cfg)
}

func ConnectClient(cfg ClientConfig) (*SecureClient, error) {
	client, err := httpclient.NewSecureClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := client.Handshake(); err != nil {
		return nil, err
	}
	return client, nil
}

func ConnectClientFromFile(path string) (*SecureClient, error) {
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		return nil, err
	}
	return ConnectClient(*cfg)
}

func NewServer(opts ServerOptions) (*Server, error) {
	return httpserver.New(opts)
}

func NewServerRuntime(opts ServerRuntimeOptions) (*ServerRuntime, error) {
	return httpserver.NewRuntime(opts)
}

func NewServerRuntimeFromFile(path string, opts ...ServerRuntimeOptions) (*ServerRuntime, error) {
	var resolved ServerRuntimeOptions
	if len(opts) > 0 {
		resolved = opts[0]
	}
	return httpserver.NewRuntimeFromFile(path, resolved)
}

func NewServerFromFile(path string, opts ...ServerOptions) (*Server, error) {
	var resolved ServerOptions
	if len(opts) > 0 {
		resolved = opts[0]
	}
	return httpserver.NewFromFile(path, resolved)
}

func DefaultFiberServerConfig() fiber.Config {
	return httpserver.DefaultFiberConfig()
}

func BuildBrowserLoginResponse(opts BrowserLoginResponseOptions) BrowserLoginResponse {
	return browser.BuildLoginResponse(opts)
}

func BuildBrowserBootstrapConfig(opts BrowserBootstrapOptions) (*BrowserBootstrapConfig, error) {
	return browser.BuildBootstrapConfig(opts)
}

func BuildFiberBrowserLoginResponse(cfg *config.ServerConfig, session *AuthSession, userID string, opts FiberBrowserLoginResponseOptions) BrowserLoginResponse {
	return httpserver.BuildBrowserLoginResponse(cfg, session, userID, opts)
}

func BuildFiberBrowserBootstrap(c fiber.Ctx, deps ServerDependencies, opts FiberBrowserBootstrapOptions) (*BrowserBootstrapConfig, error) {
	return httpserver.BuildBrowserBootstrap(c, deps, opts)
}

func NewStdHTTPMiddleware(policy *security.SecurityPolicy) (*StdHTTPMiddleware, error) {
	return httpstdlib.New(policy)
}

func NewStdHTTPMiddlewareWithConfig(cfg StdHTTPMiddlewareConfig) (*StdHTTPMiddleware, error) {
	return httpstdlib.NewWithConfig(cfg)
}

func BuildServerSDKManifest(cfg *config.ServerConfig, opts ServerSDKManifestOptions) *ServerSDKManifest {
	return serversdk.BuildManifest(cfg, opts)
}
