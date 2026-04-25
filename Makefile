.PHONY: run run-server wasm wasm-go wasm-tinygo wasm-optimize patch-tinygo-wasm-exec

REACT_APP_DIR := examples/react-app
REACT_APP_WASM_DIR := $(REACT_APP_DIR)/src/lib/client
REACT_APP_WASM_ENTRY := ./$(REACT_APP_DIR)/wasm
REACT_APP_SERVER_ENTRY := ./$(REACT_APP_DIR)
TODO_SERVER_CONFIG := config.json

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
WASM_OPT := $(shell command -v wasm-opt 2>/dev/null)
WASM_OPT_FLAGS := -Oz --enable-bulk-memory --enable-nontrapping-float-to-int

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
	@if tinygo build -target wasm -opt=z -no-debug -scheduler=asyncify -panic=trap -gc=leaking -o $(REACT_APP_WASM_DIR)/fetch.wasm $(REACT_APP_WASM_ENTRY); then \
		$(MAKE) wasm-optimize; \
		if [ ! -f "$(TINYGOWASM_EXEC)" ]; then \
			echo "ERROR: TinyGo wasm_exec.js not found at $(TINYGOWASM_EXEC)"; \
			exit 1; \
		fi; \
		cp "$(TINYGOWASM_EXEC)" $(REACT_APP_WASM_DIR)/wasm_exec.js; \
		$(MAKE) patch-tinygo-wasm-exec; \
		echo "TinyGo WASM build complete:"; \
		ls -lh $(REACT_APP_WASM_DIR)/fetch.wasm; \
	else \
		echo "TinyGo build failed; falling back to Go's wasm compiler."; \
		$(MAKE) wasm-go; \
	fi

wasm-go:
	@echo "TinyGo build unavailable; falling back to Go's wasm compiler."
	GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w" -o $(REACT_APP_WASM_DIR)/fetch.wasm $(REACT_APP_WASM_ENTRY)
	@$(MAKE) wasm-optimize

	@echo "Searching for wasm_exec.js..."
	@if [ -z "$(WASM_EXEC)" ]; then \
		echo "ERROR: wasm_exec.js not found in any known Go locations."; \
		echo "Searched:"; \
		for p in $(WASM_EXEC_PATHS); do echo "  - $$p"; done; \
		echo ""; \
		echo "Fix:"; \
		echo "  • Ensure Go is properly installed"; \
		echo "  • Or manually copy wasm_exec.js into $(REACT_APP_WASM_DIR)/"; \
		exit 1; \
	fi

	@echo "Found wasm_exec.js at: $(WASM_EXEC)"
	cp "$(WASM_EXEC)" $(REACT_APP_WASM_DIR)/

	@echo "WASM build complete. Files in $(REACT_APP_WASM_DIR)/"
	@ls -lh $(REACT_APP_WASM_DIR)/fetch.wasm

wasm-optimize:
	@if [ -n "$(WASM_OPT)" ]; then \
		echo "Optimizing fetch.wasm with wasm-opt..."; \
		"$(WASM_OPT)" $(WASM_OPT_FLAGS) $(REACT_APP_WASM_DIR)/fetch.wasm -o $(REACT_APP_WASM_DIR)/fetch.wasm.tmp; \
		mv $(REACT_APP_WASM_DIR)/fetch.wasm.tmp $(REACT_APP_WASM_DIR)/fetch.wasm; \
	else \
		echo "wasm-opt not found; skipping post-link optimization."; \
	fi

patch-tinygo-wasm-exec:
	@if ! grep -q '"runtime.getRandomData"' $(REACT_APP_WASM_DIR)/wasm_exec.js; then \
		perl -0pi -e 's/(gojs: \{\n)/$$1\t\t\t\t\t"runtime.getRandomData": (bufPtr, bufLen) => {\n\t\t\t\t\t\tcrypto.getRandomValues(loadSlice(bufPtr, bufLen));\n\t\t\t\t\t},\n/' $(REACT_APP_WASM_DIR)/wasm_exec.js; \
	fi

run-server:
	@echo "Starting React demo backend on :9443..."
	go run $(REACT_APP_SERVER_ENTRY) -config $(TODO_SERVER_CONFIG) -addr :9443
