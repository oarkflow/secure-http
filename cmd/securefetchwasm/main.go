//go:build js && wasm

package main

import "github.com/oarkflow/securehttp/pkg/wasm/securefetch"

func main() {
	securefetch.Run()
}
