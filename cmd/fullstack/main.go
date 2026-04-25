package main

import (
	"flag"
	"log"
	"os"

	"github.com/oarkflow/securehttp/pkg/http/server"
)

func main() {
	var (
		configPath   = flag.String("config", defaultConfigPath(), "Path to server configuration JSON")
		webRoot      = flag.String("web", "web/demo", "Static asset directory (includes index.html + fetch.wasm)")
		staticPrefix = flag.String("static-prefix", "/demo", "URL prefix that serves the WASM + static bundle")
		addrOverride = flag.String("addr", "", "Override listen address (defaults to listen_addr in config)")
	)
	flag.Parse()

	srv, err := server.NewFromFile(*configPath, server.Options{
		ListenAddr:         *addrOverride,
		WebRoot:            *webRoot,
		StaticPrefix:       *staticPrefix,
		EnableStatic:       true,
		EnableDemoRoutes:   true,
		RequireAccessToken: true,
	})
	if err != nil {
		log.Fatalf("build server: %v", err)
	}
	defer srv.Close()

	log.Printf("Starting full-stack secure demo")
	log.Fatal(srv.Listen(""))
}

func defaultConfigPath() string {
	if val := os.Getenv("SECURE_HTTP_CONFIG"); val != "" {
		return val
	}
	return "config/server.json"
}
