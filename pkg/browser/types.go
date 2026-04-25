package browser

import "fmt"

// GateSecret is the browser-visible representation of one active gate secret.
type GateSecret struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	NotBefore string `json:"notBefore,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// LoginResponse is returned by an app-specific login route before the browser
// calls the bootstrap endpoint to recover device and gate material.
type LoginResponse struct {
	Status         int    `json:"status,omitempty"`
	Success        bool   `json:"success"`
	UserID         string `json:"userID,omitempty"`
	UserIDLegacy   string `json:"user_id,omitempty"`
	BootstrapPath  string `json:"bootstrapPath,omitempty"`
	HandshakePath  string `json:"handshakePath,omitempty"`
	BaseURL        string `json:"baseURL,omitempty"`
	CookieAuth     bool   `json:"cookieAuth,omitempty"`
	CSRFCookieName string `json:"csrfCookieName,omitempty"`
	CSRFHeaderName string `json:"csrfHeaderName,omitempty"`
	AccessToken    string `json:"accessToken,omitempty"`
	RefreshToken   string `json:"refreshToken,omitempty"`
	CSRFToken      string `json:"csrfToken,omitempty"`
}

// BootstrapConfig is the canonical JSON shape consumed by the WASM/browser
// secure transport initialization flow.
type BootstrapConfig struct {
	BaseURL         string       `json:"baseURL,omitempty"`
	DeviceID        string       `json:"deviceID"`
	DeviceSecret    string       `json:"deviceSecret"`
	UserToken       string       `json:"userToken,omitempty"`
	HandshakePath   string       `json:"handshakePath,omitempty"`
	CapabilityToken string       `json:"capabilityToken"`
	GateSecrets     []GateSecret `json:"gateSecrets"`
}

// LoginResponseOptions lets any Go server build the canonical browser login
// payload without depending on a specific web framework.
type LoginResponseOptions struct {
	UserID         string
	BootstrapPath  string
	HandshakePath  string
	BaseURL        string
	CookieAuth     bool
	CSRFCookieName string
	CSRFHeaderName string
	AccessToken    string
	RefreshToken   string
	CSRFToken      string
}

// BootstrapOptions lets any Go server build the canonical bootstrap payload.
type BootstrapOptions struct {
	BaseURL         string
	DeviceID        string
	DeviceSecret    string
	UserToken       string
	HandshakePath   string
	CapabilityToken string
	GateSecrets     []GateSecret
}

func BuildLoginResponse(opts LoginResponseOptions) LoginResponse {
	resp := LoginResponse{
		Status:         200,
		Success:        true,
		UserID:         opts.UserID,
		UserIDLegacy:   opts.UserID,
		BootstrapPath:  opts.BootstrapPath,
		HandshakePath:  opts.HandshakePath,
		BaseURL:        opts.BaseURL,
		CookieAuth:     opts.CookieAuth,
		CSRFCookieName: opts.CSRFCookieName,
		CSRFHeaderName: opts.CSRFHeaderName,
	}
	if !opts.CookieAuth {
		resp.AccessToken = opts.AccessToken
		resp.RefreshToken = opts.RefreshToken
		resp.CSRFToken = opts.CSRFToken
	}
	return resp
}

func BuildBootstrapConfig(opts BootstrapOptions) (*BootstrapConfig, error) {
	if opts.DeviceID == "" {
		return nil, fmt.Errorf("deviceID is required")
	}
	if opts.DeviceSecret == "" {
		return nil, fmt.Errorf("deviceSecret is required")
	}
	if opts.CapabilityToken == "" {
		return nil, fmt.Errorf("capabilityToken is required")
	}
	if len(opts.GateSecrets) == 0 {
		return nil, fmt.Errorf("gateSecrets are required")
	}
	return &BootstrapConfig{
		BaseURL:         opts.BaseURL,
		DeviceID:        opts.DeviceID,
		DeviceSecret:    opts.DeviceSecret,
		UserToken:       opts.UserToken,
		HandshakePath:   opts.HandshakePath,
		CapabilityToken: opts.CapabilityToken,
		GateSecrets:     append([]GateSecret(nil), opts.GateSecrets...),
	}, nil
}
