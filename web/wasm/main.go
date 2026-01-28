//go:build js && wasm
// +build js,wasm

package main

import (
	"embed"
	"fmt"

	"github.com/oarkflow/securehttp/pkg/wasm/fetch"
)

//go:embed dist/*
var assetsFS embed.FS

// Security configuration - CHANGE THESE FOR YOUR DEPLOYMENT
const (
	// SecuritySecret is the HMAC secret key for token generation
	SecuritySecret = "YOUR-SECRET-KEY-CHANGE-THIS-IN-PRODUCTION-32CHARS"
)

// AllowedDomains - Configure your allowed domains here
// These are the ONLY domains that can load the WASM assets
var AllowedDomains = []string{
	"nepali.romanized.io",
	"romanized.io",
	"localhost:3000",
	"localhost:8081",
	"localhost:8443",
	"127.0.0.1:3000",
	"127.0.0.1:8081",
	"127.0.0.1:8443",
}

// KnownIPMappings maps domains to their expected IP addresses
// This prevents hosts file bypass attacks
var KnownIPMappings = map[string][]string{
	"nepali.romanized.io": {"YOUR_SERVER_IP_1", "YOUR_SERVER_IP_2"},
	"romanized.io":        {"YOUR_SERVER_IP_1", "YOUR_SERVER_IP_2"},
}

func main() {
	fmt.Println("Go WebAssembly Asset Server Initialized (Using fetch package)")

	config := fetch.AssetServerConfig{
		AllowedDomains:     AllowedDomains,
		SecuritySecret:     SecuritySecret,
		TokenValidityHours: 24,
		SubPath:            "dist",
		KnownIPMappings:    KnownIPMappings,
	}

	// This runs both secure fetch and asset server, then blocks forever
	if err := fetch.RunWithAssets(assetsFS, config); err != nil {
		fmt.Printf("Failed to start: %v\n", err)
		return
	}
}
