//go:build js && wasm

package main

import "github.com/oarkflow/securehttp/pkg/wasm/fetch"

func main() {
	fetch.Run()
}
