.PHONY: wasm run-server

# Known wasm_exec.js locations (ordered by priority)
WASM_EXEC_PATHS := \
	$(shell go env GOROOT)/lib/wasm/wasm_exec.js \
	$(shell go env GOROOT)/misc/wasm/wasm_exec.js \
	/usr/lib/go/lib/wasm/wasm_exec.js \
	/usr/lib/go/misc/wasm/wasm_exec.js \
	/usr/share/go/lib/wasm/wasm_exec.js \
	/usr/share/go/misc/wasm/wasm_exec.js

# Find first existing wasm_exec.js
WASM_EXEC := $(firstword $(wildcard $(WASM_EXEC_PATHS)))

run: wasm run-server

# Build the fetch WASM module and copy runtime shim
wasm:
	@echo "Building fetch.wasm..."
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o web/demo/fetch.wasm ./cmd/wasm

	@echo "Searching for wasm_exec.js..."
	@if [ -z "$(WASM_EXEC)" ]; then \
		echo "ERROR: wasm_exec.js not found in any known Go locations."; \
		echo "Searched:"; \
		for p in $(WASM_EXEC_PATHS); do echo "  - $$p"; done; \
		echo ""; \
		echo "Fix:"; \
		echo "  • Ensure Go is properly installed"; \
		echo "  • Or manually copy wasm_exec.js into web/demo/"; \
		exit 1; \
	fi

	@echo "Found wasm_exec.js at: $(WASM_EXEC)"
	cp "$(WASM_EXEC)" web/demo/

	@echo "WASM build complete. Files in web/demo/"

# Run the secure HTTP server
run-server:
	@echo "Starting secure server on :8443..."
	go run ./cmd/fullstack  -config config/server.json -web web/demo -static-prefix /lab -addr :8443
