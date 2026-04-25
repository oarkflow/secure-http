package securehttp

import (
	"github.com/oarkflow/securehttp/pkg/config"
	httpclient "github.com/oarkflow/securehttp/pkg/http/client"
	httpserver "github.com/oarkflow/securehttp/pkg/http/server"
)

type SecureClient = httpclient.SecureClient
type ClientConfig = httpclient.Config
type GateClientConfig = httpclient.GateClientConfig
type GateSecret = httpclient.GateSecret

type Server = httpserver.Server
type ServerOptions = httpserver.Options
type ServerDependencies = httpserver.Dependencies

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

func NewServerFromFile(path string, opts ...ServerOptions) (*Server, error) {
	var resolved ServerOptions
	if len(opts) > 0 {
		resolved = opts[0]
	}
	return httpserver.NewFromFile(path, resolved)
}
