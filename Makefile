.PHONY: test test-go test-node build vuln ci

test: test-go test-node

test-go:
	go test ./...

test-node:
	npm run test:node

build:
	go build ./...

vuln:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	elif [ -x "$$HOME/go/bin/govulncheck" ]; then \
		"$$HOME/go/bin/govulncheck" ./...; \
	else \
		echo "govulncheck not installed; run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

ci: test build vuln
