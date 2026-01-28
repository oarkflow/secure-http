#!/bin/bash
# Quick start script for the Secure WASM Demo

set -e

echo "🔐 Secure WASM Demo - Quick Start"
echo "=================================="
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "✅ Go found: $(go version)"
echo ""

# Build WASM binary
echo "📦 Building WASM binary..."
cd "$(dirname "$0")"
GOOS=js GOARCH=wasm go build -o web/wasm/main.wasm web/wasm/main.go

if [ -f "web/wasm/main.wasm" ]; then
    echo "✅ WASM binary built successfully"
    echo "   Size: $(du -h web/wasm/main.wasm | cut -f1)"
else
    echo "❌ Failed to build WASM binary"
    exit 1
fi

echo ""
echo "🚀 Starting server..."
echo ""
echo "Demo will be available at:"
echo "  📱 Login Page:  http://localhost:8443/wasm/login.html"
echo ""
echo "Demo Credentials:"
echo "  👤 User:  user-123"
echo "  🔑 Token: user-token-123"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""
echo "-----------------------------------"
echo ""

# Start the server
go run cmd/fullstack/main.go
