package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/securehttp/pkg/security"
)

// ServerConfig represents the persisted runtime configuration.
type ServerConfig struct {
	ListenAddr   string                 `json:"listen_addr"`
	Gate         GateConfig             `json:"gate"`
	Capabilities []CapabilityDefinition `json:"capabilities"`
	Devices      []DeviceDefinition     `json:"devices"`
	Users        []UserDefinition       `json:"users"`
	Alerts       AlertingConfig         `json:"alerts"`
	Auth         AuthConfig             `json:"auth"`
}

// AuthConfig toggles user/device requirements.
type AuthConfig struct {
	RequireDevice  bool   `json:"require_device"`
	RequireUser    bool   `json:"require_user"`
	JWTSigningKey  string `json:"jwt_signing_key"`
}

// GateConfig declares the pre-routing gate settings.
type GateConfig struct {
	Headers        security.GateHeaders `json:"headers"`
	Secrets        []SecretDefinition   `json:"secrets"`
	MaxClockSkew   string               `json:"max_clock_skew"`
	NonceTTL       string               `json:"nonce_ttl"`
	AllowedOrigins []string             `json:"allowed_origins"`
	StrictOrigin   bool                 `json:"strict_origin"`
	RateLimit      RateLimitConfig      `json:"rate_limit"`
}

// RateLimitConfig maps onto the sliding window limiter.
type RateLimitConfig struct {
	Window  string `json:"window"`
	MaxHits int    `json:"max_hits"`
}

// SecretDefinition stores rotating secret metadata.
type SecretDefinition struct {
	ID        string `json:"id"`
	Material  string `json:"secret"`
	NotBefore string `json:"not_before"`
	ExpiresAt string `json:"expires_at"`
}

// CapabilityDefinition binds a token to one or more routes.
type CapabilityDefinition struct {
	Token    string                      `json:"token"`
	Routes   []CapabilityRouteDefinition `json:"routes"`
	Paths    []string                    `json:"paths"`
	Methods  []string                    `json:"methods"`
	Metadata map[string]string           `json:"metadata"`
}

// CapabilityRouteDefinition maps one route to allowed methods.
type CapabilityRouteDefinition struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
}

// DeviceDefinition stores the HMAC secret used during handshakes.
type DeviceDefinition struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// UserDefinition maps a bearer token to a context.
type UserDefinition struct {
	Token    string            `json:"token"`
	ID       string            `json:"id"`
	Roles    []string          `json:"roles"`
	Metadata map[string]string `json:"metadata"`
}

// AlertingConfig configures webhook dispatch.
type AlertingConfig struct {
	WebhookURL    string                    `json:"webhook_url"`
	IncludeEvents []security.AuditEventType `json:"include_events"`
	MinInterval   string                    `json:"min_interval"`
	LogFile       string                    `json:"log_file"`
}

// LoadServerConfig loads and validates the server configuration file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if !cfg.Auth.RequireDevice && !cfg.Auth.RequireUser {
		cfg.Auth.RequireDevice = true
		cfg.Auth.RequireUser = true
	}
	return &cfg, nil
}

// BuildCapabilityStore hydrates a memory-backed store from config.
func (cfg *ServerConfig) BuildCapabilityStore() (*security.MemoryCapabilityStore, error) {
	store := security.NewMemoryCapabilityStore()
	for _, def := range cfg.Capabilities {
		cap, err := def.toCapability()
		if err != nil {
			return nil, err
		}
		store.Register(*cap)
	}
	if len(cfg.Capabilities) == 0 {
		return nil, fmt.Errorf("at least one capability token must be configured")
	}
	return store, nil
}

// BuildDeviceRegistry loads devices into the in-memory registry.
func (cfg *ServerConfig) BuildDeviceRegistry() (*security.InMemoryDeviceRegistry, error) {
	reg := security.NewInMemoryDeviceRegistry()
	if len(cfg.Devices) == 0 {
		return nil, fmt.Errorf("device registry cannot be empty")
	}
	for _, device := range cfg.Devices {
		if err := device.register(reg); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// BuildUserAuthenticator loads static tokens.
func (cfg *ServerConfig) BuildUserAuthenticator() (*security.StaticUserAuthenticator, error) {
	auth := security.NewStaticUserAuthenticator()
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("user authenticator cannot be empty")
	}
	for _, user := range cfg.Users {
		if err := user.register(auth); err != nil {
			return nil, err
		}
	}
	return auth, nil
}

// GatekeeperConfig converts GateConfig to the runtime structure.
func (cfg *ServerConfig) GatekeeperConfig(store security.CapabilityStore, logger security.AuditLogger) (security.GatekeeperConfig, error) {
	secrets, err := cfg.Gate.buildRotatingSecrets()
	if err != nil {
		return security.GatekeeperConfig{}, err
	}
	maxSkew, err := parseDuration(cfg.Gate.MaxClockSkew, time.Minute)
	if err != nil {
		return security.GatekeeperConfig{}, err
	}
	nonceTTL, err := parseDuration(cfg.Gate.NonceTTL, 2*time.Minute)
	if err != nil {
		return security.GatekeeperConfig{}, err
	}
	rlWindow, err := parseDuration(cfg.Gate.RateLimit.Window, 15*time.Second)
	if err != nil {
		return security.GatekeeperConfig{}, err
	}
	limiter := security.NewSlidingWindowLimiter(rlWindow, cfg.Gate.RateLimit.MaxHits)
	return security.GatekeeperConfig{
		Secrets:         secrets,
		Headers:         cfg.Gate.Headers,
		MaxClockSkew:    maxSkew,
		NonceTTL:        nonceTTL,
		CapabilityStore: store,
		RateLimiter:     limiter,
		Logger:          logger,
	}, nil
}

func (gc GateConfig) buildRotatingSecrets() ([]security.RotatingSecret, error) {
	if len(gc.Secrets) == 0 {
		return nil, fmt.Errorf("at least one gate secret must be defined")
	}
	secrets := make([]security.RotatingSecret, 0, len(gc.Secrets))
	for _, def := range gc.Secrets {
		secret, err := def.toRotatingSecret()
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (def SecretDefinition) toRotatingSecret() (security.RotatingSecret, error) {
	if def.ID == "" {
		return security.RotatingSecret{}, fmt.Errorf("gate secret id is required")
	}
	material, err := decodeKeyMaterial(def.Material)
	if err != nil {
		return security.RotatingSecret{}, fmt.Errorf("gate secret %s: %w", def.ID, err)
	}
	notBefore, err := parseOptionalTime(def.NotBefore)
	if err != nil {
		return security.RotatingSecret{}, err
	}
	expiresAt, err := parseOptionalTime(def.ExpiresAt)
	if err != nil {
		return security.RotatingSecret{}, err
	}
	return security.RotatingSecret{
		ID:        def.ID,
		Secret:    material,
		NotBefore: notBefore,
		ExpiresAt: expiresAt,
	}, nil
}

func (def CapabilityDefinition) toCapability() (*security.Capability, error) {
	if strings.TrimSpace(def.Token) == "" {
		return nil, fmt.Errorf("capability token is required")
	}
	cap := &security.Capability{
		Token:    def.Token,
		Metadata: copyStringMap(def.Metadata),
	}
	if len(def.Routes) > 0 {
		rules := make([]security.CapabilityRule, 0, len(def.Routes))
		for _, route := range def.Routes {
			if strings.TrimSpace(route.Path) == "" {
				return nil, fmt.Errorf("capability %s has a route with empty path", def.Token)
			}
			rules = append(rules, security.CapabilityRule{
				Path:    route.Path,
				Methods: normalizeMethodSet(route.Methods),
			})
		}
		cap.Rules = rules
		return cap, nil
	}
	cap.Methods = normalizeMethodSet(def.Methods)
	if len(def.Paths) > 0 {
		cap.Paths = append([]string{}, def.Paths...)
	}
	return cap, nil
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

func (device DeviceDefinition) register(reg *security.InMemoryDeviceRegistry) error {
	if device.ID == "" {
		return fmt.Errorf("device id is required")
	}
	secret, err := decodeKeyMaterial(device.Secret)
	if err != nil {
		return fmt.Errorf("device %s: %w", device.ID, err)
	}
	reg.Register(device.ID, secret)
	return nil
}

func (user UserDefinition) register(auth *security.StaticUserAuthenticator) error {
	if user.Token == "" {
		return fmt.Errorf("user token is required")
	}
	if user.ID == "" {
		return fmt.Errorf("user id is required for token %s", user.Token)
	}
	auth.Register(user.Token, &security.UserContext{
		ID:       user.ID,
		Roles:    append([]string{}, user.Roles...),
		Metadata: copyStringMap(user.Metadata),
	})
	return nil
}

// ParseAlertSettings normalizes alert configuration options.
func (cfg *ServerConfig) ParseAlertSettings() (string, []security.AuditEventType, time.Duration, error) {
	url := strings.TrimSpace(cfg.Alerts.WebhookURL)
	if url == "" {
		return "", nil, 0, nil
	}
	interval, err := parseDuration(cfg.Alerts.MinInterval, 5*time.Second)
	if err != nil {
		return "", nil, 0, err
	}
	include := cfg.Alerts.IncludeEvents
	if len(include) == 0 {
		include = []security.AuditEventType{security.AuditEventGateDenied, security.AuditEventDecryptFailure, security.AuditEventHandshakeFailure}
	}
	return url, include, interval, nil
}

// BuildAuditLogger wires console/file/webhook loggers.
func (cfg *ServerConfig) BuildAuditLogger() (security.AuditLogger, func(), error) {
	console := security.NewConsoleAuditLogger()
	logPath := strings.TrimSpace(cfg.Alerts.LogFile)
	if logPath == "" {
		logPath = "logs/audit.log"
	}
	fileLogger, err := security.NewAsyncFileAuditLogger(logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("file audit logger: %w", err)
	}
	cleanup := func() {
		fileLogger.Close()
	}
	loggers := security.MultiAuditLogger{console, fileLogger}
	url, include, interval, err := cfg.ParseAlertSettings()
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if url != "" {
		if webhook := security.NewWebhookAuditLogger(url, include, interval); webhook != nil {
			loggers = append(loggers, webhook)
		}
	}
	return loggers, cleanup, nil
}
