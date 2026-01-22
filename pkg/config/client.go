package config

import (
	"encoding/json"
	"fmt"
	"os"

	pkgclient "github.com/oarkflow/securehttp/pkg/http/client"
	"github.com/oarkflow/securehttp/pkg/security"
)

// ClientConfigFile maps the JSON structure for the demo client.
type ClientConfigFile struct {
	BaseURL       string          `json:"base_url"`
	HandshakePath string          `json:"handshake_path"`
	Device        ClientDevice    `json:"device"`
	UserToken     string          `json:"user_token"`
	Gate          ClientGateBlock `json:"gate"`
}

// ClientDevice captures client identity material.
type ClientDevice struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// ClientGateBlock mirrors the server gate requirements.
type ClientGateBlock struct {
	CapabilityToken string               `json:"capability_token"`
	Secrets         []SecretDefinition   `json:"secrets"`
	Headers         security.GateHeaders `json:"headers"`
	NonceSize       int                  `json:"nonce_size"`
}

// LoadClientConfig reads and converts the JSON file into the runtime client config.
func LoadClientConfig(path string) (*pkgclient.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	var cfgFile ClientConfigFile
	if err := json.Unmarshal(data, &cfgFile); err != nil {
		return nil, fmt.Errorf("parse client config: %w", err)
	}
	if cfgFile.BaseURL == "" {
		return nil, fmt.Errorf("client base_url is required")
	}
	if cfgFile.Device.ID == "" {
		return nil, fmt.Errorf("device id is required")
	}
	deviceSecret, err := decodeKeyMaterial(cfgFile.Device.Secret)
	if err != nil {
		return nil, fmt.Errorf("device secret: %w", err)
	}
	gateSecrets, err := cfgFile.Gate.buildGateSecrets()
	if err != nil {
		return nil, err
	}
	if cfgFile.UserToken == "" {
		return nil, fmt.Errorf("user token is required")
	}
	return &pkgclient.Config{
		BaseURL:       cfgFile.BaseURL,
		DeviceID:      cfgFile.Device.ID,
		DeviceSecret:  deviceSecret,
		UserToken:     cfgFile.UserToken,
		HandshakePath: cfgFile.HandshakePath,
		Gate: pkgclient.GateClientConfig{
			Secrets:         gateSecrets,
			CapabilityToken: cfgFile.Gate.CapabilityToken,
			Headers:         cfgFile.Gate.Headers,
			NonceSize:       cfgFile.Gate.NonceSize,
		},
	}, nil
}

func (gate ClientGateBlock) buildGateSecrets() ([]pkgclient.GateSecret, error) {
	if len(gate.Secrets) == 0 {
		return nil, fmt.Errorf("client gate requires at least one secret")
	}
	secrets := make([]pkgclient.GateSecret, 0, len(gate.Secrets))
	for _, def := range gate.Secrets {
		material, err := decodeKeyMaterial(def.Material)
		if err != nil {
			return nil, fmt.Errorf("gate secret %s: %w", def.ID, err)
		}
		secrets = append(secrets, pkgclient.GateSecret{ID: def.ID, Secret: material})
	}
	return secrets, nil
}
