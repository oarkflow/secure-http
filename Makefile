.PHONY: wasm wasm-go wasm-tinygo prepare-todo-web run-server run-todo-sample

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
TINYGOROOT := $(shell tinygo env TINYGOROOT 2>/dev/null)
TINYGOWASM_EXEC := $(TINYGOROOT)/targets/wasm_exec.js

run: wasm run-server

# Build the fetch WASM module and copy runtime shim.
# Prefers TinyGo with aggressive size optimization, falls back to the Go compiler
# when the local TinyGo/Go pairing is incompatible.
wasm:
	@$(MAKE) wasm-tinygo || $(MAKE) wasm-go

wasm-tinygo:
	@echo "Building fetch.wasm..."
	@if ! command -v tinygo >/dev/null 2>&1; then \
		echo "ERROR: tinygo is not installed."; \
		exit 1; \
	fi
	@if tinygo build -target wasm -opt=z -no-debug -scheduler=none -panic=trap -gc=leaking -o cmd/fullstack/client/fetch.wasm ./cmd/wasm; then \
		if [ ! -f "$(TINYGOWASM_EXEC)" ]; then \
			echo "ERROR: TinyGo wasm_exec.js not found at $(TINYGOWASM_EXEC)"; \
			exit 1; \
		fi; \
		cp "$(TINYGOWASM_EXEC)" cmd/fullstack/client/wasm_exec.js; \
		echo "TinyGo WASM build complete:"; \
		ls -lh cmd/fullstack/client/fetch.wasm; \
	else \
		echo "TinyGo build failed; falling back to Go's wasm compiler."; \
		$(MAKE) wasm-go; \
	fi

wasm-go:
	@echo "TinyGo build unavailable; falling back to Go's wasm compiler."
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o cmd/fullstack/client/fetch.wasm ./cmd/wasm

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
	cp "$(WASM_EXEC)" cmd/fullstack/client/

	@echo "WASM build complete. Files in cmd/fullstack/client/"
	@ls -lh cmd/fullstack/client/fetch.wasm

prepare-todo-web: wasm
	@echo "Staging todo sample frontend assets..."
	mkdir -p examples/todo_password_server/web
	cp cmd/fullstack/client/fetch.wasm examples/todo_password_server/web/fetch.wasm
	cp cmd/fullstack/client/wasm_exec.js examples/todo_password_server/web/wasm_exec.js
	cp cmd/fullstack/client/secure_http.js examples/todo_password_server/web/secure_http.js

# Run the secure HTTP server
run-server:
	@echo "Starting secure server on :8443..."
	go run ./cmd/fullstack  -config config/server.json -web ./cmd/fullstack/client -static-prefix /lab -addr :8443

run-todo-sample: prepare-todo-web
	@echo "Starting username/password todo sample on :9443..."
	go run ./examples/todo_password_server -config config/todo-server.json -web ./examples/todo_password_server/web -static-prefix /todo -addr :9443
