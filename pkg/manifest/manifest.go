package manifest

import (
	"strings"

	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/security"
)

const CurrentManifestVersion = "v1"

// Manifest exposes the canonical server protocol contract in a language-neutral shape.
type Manifest struct {
	Version       string               `json:"version"`
	BaseURL       string               `json:"baseURL,omitempty"`
	RuntimeMode   string               `json:"runtimeMode,omitempty"`
	HandshakePath string               `json:"handshakePath"`
	BootstrapPath string               `json:"bootstrapPath,omitempty"`
	Headers       HeaderManifest       `json:"headers"`
	Auth          AuthManifest         `json:"auth"`
	Gate          GateManifest         `json:"gate"`
	Capabilities  []CapabilityManifest `json:"capabilities,omitempty"`
}

type HeaderManifest struct {
	SessionID string               `json:"sessionID"`
	UserToken string               `json:"userToken"`
	Gate      security.GateHeaders `json:"gate"`
}

type AuthManifest struct {
	RequireDevice bool         `json:"requireDevice"`
	RequireUser   bool         `json:"requireUser"`
	SessionCookie CookieConfig `json:"sessionCookie"`
	CSRF          CSRFConfig   `json:"csrf"`
}

type CookieConfig struct {
	Enabled  bool   `json:"enabled"`
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"sameSite,omitempty"`
}

type CSRFConfig struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookieName"`
	HeaderName string `json:"headerName"`
	Path       string `json:"path,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Secure     bool   `json:"secure"`
	SameSite   string `json:"sameSite,omitempty"`
}

type GateManifest struct {
	AllowedOrigins []string             `json:"allowedOrigins,omitempty"`
	StrictOrigin   bool                 `json:"strictOrigin"`
	MaxClockSkew   string               `json:"maxClockSkew,omitempty"`
	NonceTTL       string               `json:"nonceTTL,omitempty"`
	Secrets        []GateSecretManifest `json:"secrets,omitempty"`
}

type GateSecretManifest struct {
	ID        string `json:"id"`
	Secret    string `json:"secret,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

type CapabilityManifest struct {
	Token    string            `json:"token"`
	Methods  []string          `json:"methods,omitempty"`
	Paths    []string          `json:"paths,omitempty"`
	Routes   []CapabilityRoute `json:"routes,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type CapabilityRoute struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods,omitempty"`
}

type ManifestOptions struct {
	BaseURL        string
	HandshakePath  string
	BootstrapPath  string
	IncludeSecrets bool
}

// BuildManifest exports the portable server contract for other SDKs and runtimes.
func BuildManifest(cfg *config.ServerConfig, opts ManifestOptions) *Manifest {
	if cfg == nil {
		return nil
	}
	cfgCopy := *cfg
	cfgCopy.Auth = cfg.Auth
	cfgCopy.Gate = cfg.Gate
	normalizeConfigDefaults(&cfgCopy)

	handshakePath := strings.TrimSpace(opts.HandshakePath)
	if handshakePath == "" {
		handshakePath = "/handshake"
	}

	manifest := &Manifest{
		Version:       CurrentManifestVersion,
		BaseURL:       strings.TrimSpace(opts.BaseURL),
		RuntimeMode:   cfgCopy.Runtime.Mode,
		HandshakePath: handshakePath,
		BootstrapPath: strings.TrimSpace(opts.BootstrapPath),
		Headers: HeaderManifest{
			SessionID: security.DefaultHeaderNames().SessionID,
			UserToken: security.DefaultHeaderNames().UserToken,
			Gate:      cfgCopy.Gate.Headers.WithDefaults(),
		},
		Auth: AuthManifest{
			RequireDevice: cfgCopy.Auth.RequireDevice,
			RequireUser:   cfgCopy.Auth.RequireUser,
			SessionCookie: CookieConfig{
				Enabled:  cfgCopy.Auth.SessionCookie.Enabled,
				Name:     cfgCopy.Auth.SessionCookie.Name,
				Path:     cfgCopy.Auth.SessionCookie.Path,
				Domain:   cfgCopy.Auth.SessionCookie.Domain,
				HTTPOnly: cfgCopy.Auth.SessionCookie.HTTPOnly,
				Secure:   cfgCopy.Auth.SessionCookie.Secure,
				SameSite: cfgCopy.Auth.SessionCookie.SameSite,
			},
			CSRF: CSRFConfig{
				Enabled:    cfgCopy.Auth.CSRF.Enabled,
				CookieName: cfgCopy.Auth.CSRF.CookieName,
				HeaderName: cfgCopy.Auth.CSRF.HeaderName,
				Path:       cfgCopy.Auth.CSRF.Path,
				Domain:     cfgCopy.Auth.CSRF.Domain,
				Secure:     cfgCopy.Auth.CSRF.Secure,
				SameSite:   cfgCopy.Auth.CSRF.SameSite,
			},
		},
		Gate: GateManifest{
			AllowedOrigins: append([]string{}, cfgCopy.Gate.AllowedOrigins...),
			StrictOrigin:   cfgCopy.Gate.StrictOrigin || cfgCopy.IsStrictMode(),
			MaxClockSkew:   cfgCopy.Gate.MaxClockSkew,
			NonceTTL:       cfgCopy.Gate.NonceTTL,
		},
	}

	if opts.IncludeSecrets {
		manifest.Gate.Secrets = make([]GateSecretManifest, 0, len(cfgCopy.Gate.Secrets))
		for _, secret := range cfgCopy.Gate.Secrets {
			manifest.Gate.Secrets = append(manifest.Gate.Secrets, GateSecretManifest{
				ID:        secret.ID,
				Secret:    secret.Material,
				NotBefore: secret.NotBefore,
				ExpiresAt: secret.ExpiresAt,
			})
		}
	}

	if len(cfgCopy.Capabilities) > 0 {
		manifest.Capabilities = make([]CapabilityManifest, 0, len(cfgCopy.Capabilities))
		for _, capability := range cfgCopy.Capabilities {
			item := CapabilityManifest{
				Token:    capability.Token,
				Methods:  append([]string{}, capability.Methods...),
				Paths:    append([]string{}, capability.Paths...),
				Metadata: copyStringMap(capability.Metadata),
			}
			if len(capability.Routes) > 0 {
				item.Routes = make([]CapabilityRoute, 0, len(capability.Routes))
				for _, route := range capability.Routes {
					item.Routes = append(item.Routes, CapabilityRoute{
						Path:    route.Path,
						Methods: append([]string{}, route.Methods...),
					})
				}
			}
			manifest.Capabilities = append(manifest.Capabilities, item)
		}
	}

	return manifest
}

func copyStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func normalizeConfigDefaults(cfg *config.ServerConfig) {
	if cfg == nil {
		return
	}
	cfg.Runtime.Mode = strings.ToLower(strings.TrimSpace(cfg.Runtime.Mode))
	if cfg.Runtime.Mode == "" {
		cfg.Runtime.Mode = "strict"
	}
	if !cfg.Auth.SessionCookie.Enabled {
		cfg.Auth.SessionCookie.Enabled = true
	}
	if strings.TrimSpace(cfg.Auth.SessionCookie.Name) == "" {
		cfg.Auth.SessionCookie.Name = "securehttp_access"
	}
	if strings.TrimSpace(cfg.Auth.SessionCookie.Path) == "" {
		cfg.Auth.SessionCookie.Path = "/"
	}
	if !cfg.Auth.SessionCookie.HTTPOnly {
		cfg.Auth.SessionCookie.HTTPOnly = true
	}
	cfg.Auth.SessionCookie.SameSite = strings.ToLower(strings.TrimSpace(cfg.Auth.SessionCookie.SameSite))
	if cfg.Auth.SessionCookie.SameSite == "" {
		cfg.Auth.SessionCookie.SameSite = "lax"
	}
	if !cfg.Auth.CSRF.Enabled {
		cfg.Auth.CSRF.Enabled = true
	}
	if strings.TrimSpace(cfg.Auth.CSRF.CookieName) == "" {
		cfg.Auth.CSRF.CookieName = "securehttp_csrf"
	}
	if strings.TrimSpace(cfg.Auth.CSRF.HeaderName) == "" {
		cfg.Auth.CSRF.HeaderName = "X-CSRF-Token"
	}
	if strings.TrimSpace(cfg.Auth.CSRF.Path) == "" {
		cfg.Auth.CSRF.Path = "/"
	}
	cfg.Auth.CSRF.SameSite = strings.ToLower(strings.TrimSpace(cfg.Auth.CSRF.SameSite))
	if cfg.Auth.CSRF.SameSite == "" {
		cfg.Auth.CSRF.SameSite = "lax"
	}
}
