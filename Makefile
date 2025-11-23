.PHONY: build-wasm run-server run-web test clean

# Build the secureFetch WASM module and copy runtime shim
build-wasm:
	@echo "Building securefetch.wasm..."
	GOOS=js GOARCH=wasm go build -o web/securefetch-demo/securefetch.wasm ./cmd/securefetchwasm
	@echo "Copying wasm_exec.js..."
	@if [ -f "$$(go env GOROOT)/misc/wasm/wasm_exec.js" ]; then \
		cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" web/securefetch-demo/; \
	else \
		echo "Warning: wasm_exec.js not found at $$(go env GOROOT)/misc/wasm/wasm_exec.js."; \
		echo "Please copy it manually from your Go installation's misc/wasm/ directory."; \
	fi
	@echo "WASM build complete. Files in web/securefetch-demo/"

# Run the secure HTTP server (handles encrypted requests)
run-server:
	@echo "Starting secure server on :8443..."
	go run ./cmd/server/main.go

# Run the web server to serve the demo UI and WASM
run-web:
	@echo "Starting web server on :8082..."
	go run ./cmd/securefetchweb -addr :8082 -dir web/securefetch-demo

# Build WASM and run both servers in background for testing
test: build-wasm
	@echo "Starting servers for testing..."
	@echo "Secure server: http://localhost:8443"
	@echo "Web demo: http://localhost:8082"
	@echo "Press Ctrl+C to stop"
	@trap 'kill 0' INT; \
		go run ./cmd/server/main.go & \
		go run ./cmd/securefetchweb -addr :8082 -dir web/securefetch-demo & \
		wait

# Clean built artifacts
clean:
	rm -f web/securefetch-demo/securefetch.wasm web/securefetch-demo/wasm_exec.js
