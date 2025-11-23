package main

import (
	"flag"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var (
		addr      = flag.String("addr", ":8082", "address to listen on")
		rootDir   = flag.String("dir", "web/securefetch-demo", "directory containing the demo assets")
		allowCORS = flag.Bool("cors", true, "allow all origins (useful for local development)")
	)
	flag.Parse()

	if err := validateAssets(*rootDir); err != nil {
		log.Fatalf("unable to serve assets: %v", err)
	}

	// Ensure browsers treat wasm files with the correct MIME type.
	mime.AddExtensionType(".wasm", "application/wasm")

	fileHandler := staticHandler(http.Dir(*rootDir), *allowCORS)
	logged := loggingMiddleware(fileHandler)

	log.Printf("🌐 Serving %s on http://localhost%s", *rootDir, *addr)
	log.Printf("📦 Expecting securefetch.wasm + wasm_exec.js inside that directory")
	log.Fatal(http.ListenAndServe(*addr, logged))
}

func validateAssets(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}

	warnMissing(filepath.Join(root, "securefetch.wasm"), "build via GOOS=js GOARCH=wasm go build -o web/securefetch-demo/securefetch.wasm ./cmd/securefetchwasm")
	warnMissing(filepath.Join(root, "wasm_exec.js"), "cp '$(go env GOROOT)/misc/wasm/wasm_exec.js' web/securefetch-demo/")
	return nil
}

func warnMissing(path string, hint string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	log.Printf("⚠️  %s not found. Hint: %s", path, hint)
}

func staticHandler(fs http.FileSystem, allowCORS bool) http.Handler {
	fileServer := http.FileServer(fs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowCORS {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Cache-Control", "no-store")
		}
		fileServer.ServeHTTP(w, r)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, lrw.status, duration)
	})
}
