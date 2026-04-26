package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/securehttp/pkg/browser"
	"github.com/oarkflow/securehttp/pkg/config"
	"github.com/oarkflow/securehttp/pkg/security"
)

type BrowserLoginResponseOptions struct {
	BaseURL       string
	BootstrapPath string
	HandshakePath string
}

type BrowserBootstrapOptions struct {
	BaseURL             string
	HandshakePath       string
	CapabilityToken     string
	ResolveUserToken    func(*fiber.Ctx) string
	RestoreDevice       func(*fiber.Ctx, Dependencies, string) error
	ResolveDeviceSecret func(*fiber.Ctx, Dependencies, string) (string, error)
}

func BuildBrowserLoginResponse(cfg *config.ServerConfig, session *AuthSession, userID string, opts BrowserLoginResponseOptions) browser.LoginResponse {
	bootstrapPath := strings.TrimSpace(opts.BootstrapPath)
	if bootstrapPath == "" {
		bootstrapPath = "/bootstrap"
	}
	handshakePath := strings.TrimSpace(opts.HandshakePath)
	if handshakePath == "" {
		handshakePath = "/handshake"
	}
	loginOpts := browser.LoginResponseOptions{
		UserID:         userID,
		BaseURL:        strings.TrimSpace(opts.BaseURL),
		BootstrapPath:  bootstrapPath,
		HandshakePath:  handshakePath,
		CookieAuth:     cfg != nil && cfg.Auth.SessionCookie.Enabled,
		CSRFCookieName: csrfCookieName(cfg),
		CSRFHeaderName: csrfHeaderName(cfg),
	}
	if session != nil {
		loginOpts.AccessToken = session.AccessToken
		loginOpts.RefreshToken = session.RefreshToken
		loginOpts.CSRFToken = session.CSRFToken
	}
	return browser.BuildLoginResponse(loginOpts)
}

func BuildBrowserBootstrap(c *fiber.Ctx, deps Dependencies, opts BrowserBootstrapOptions) (*browser.BootstrapConfig, error) {
	deviceID, _ := c.Locals("device_id").(string)
	if strings.TrimSpace(deviceID) == "" {
		return nil, fmt.Errorf("device not found")
	}
	if opts.RestoreDevice != nil {
		if err := opts.RestoreDevice(c, deps, deviceID); err != nil {
			return nil, err
		}
	}
	resolveDeviceSecret := opts.ResolveDeviceSecret
	if resolveDeviceSecret == nil {
		resolveDeviceSecret = resolveBootstrapDeviceSecret
	}
	deviceSecret, err := resolveDeviceSecret(c, deps, deviceID)
	if err != nil {
		return nil, err
	}
	handshakePath := strings.TrimSpace(opts.HandshakePath)
	if handshakePath == "" {
		handshakePath = "/handshake"
	}
	capabilityToken := strings.TrimSpace(opts.CapabilityToken)
	if capabilityToken == "" && deps.Config != nil && len(deps.Config.Capabilities) > 0 {
		capabilityToken = deps.Config.Capabilities[0].Token
	}
	return browser.BuildBootstrapConfig(browser.BootstrapOptions{
		BaseURL:         strings.TrimSpace(opts.BaseURL),
		DeviceID:        deviceID,
		DeviceSecret:    deviceSecret,
		UserToken:       resolveBootstrapUserToken(c, opts.ResolveUserToken),
		HandshakePath:   handshakePath,
		CapabilityToken: capabilityToken,
		GateSecrets:     browserGateSecrets(deps.Config),
	})
}

func browserGateSecrets(cfg *config.ServerConfig) []browser.GateSecret {
	if cfg == nil || len(cfg.Gate.Secrets) == 0 {
		return nil
	}
	out := make([]browser.GateSecret, 0, len(cfg.Gate.Secrets))
	for _, s := range cfg.Gate.Secrets {
		out = append(out, browser.GateSecret{
			ID:        s.ID,
			Secret:    s.Material,
			NotBefore: s.NotBefore,
			ExpiresAt: s.ExpiresAt,
		})
	}
	return out
}

func resolveBootstrapUserToken(c *fiber.Ctx, resolve func(*fiber.Ctx) string) string {
	if resolve != nil {
		return strings.TrimSpace(resolve(c))
	}
	claims, _ := c.Locals("token_claims").(*security.StatelessTokenClaims)
	if claims == nil || len(claims.Metadata) == 0 {
		return ""
	}
	return strings.TrimSpace(claims.Metadata["user_token"])
}

func resolveBootstrapDeviceSecret(_ *fiber.Ctx, deps Dependencies, deviceID string) (string, error) {
	if deps.Config != nil {
		for i := range deps.Config.Devices {
			if deps.Config.Devices[i].ID == deviceID && strings.TrimSpace(deps.Config.Devices[i].Secret) != "" {
				return deps.Config.Devices[i].Secret, nil
			}
		}
	}
	if deps.DeviceRegistry != nil {
		secret, err := deps.DeviceRegistry.GetSecret(deviceID)
		if err == nil && len(secret) > 0 {
			return "base64:" + base64.StdEncoding.EncodeToString(secret), nil
		}
	}
	return "", fmt.Errorf("device secret not found for %s", deviceID)
}

func csrfCookieName(cfg *config.ServerConfig) string {
	if cfg == nil || strings.TrimSpace(cfg.Auth.CSRF.CookieName) == "" {
		return "securehttp_csrf"
	}
	return cfg.Auth.CSRF.CookieName
}

func csrfHeaderName(cfg *config.ServerConfig) string {
	if cfg == nil || strings.TrimSpace(cfg.Auth.CSRF.HeaderName) == "" {
		return "X-CSRF-Token"
	}
	return cfg.Auth.CSRF.HeaderName
}

func deriveDemoDeviceSecret(deviceID string) []byte {
	h := hmac.New(sha256.New, []byte("demo-device-derivation-key"))
	h.Write([]byte(deviceID))
	return h.Sum(nil)
}
