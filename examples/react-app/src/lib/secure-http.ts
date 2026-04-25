import fetchWasmUrl from '../../../../cmd/fullstack/client/fetch.wasm?url'
import { createSecureHttpClient } from '../../../../cmd/fullstack/client/index.js'

export const secureHttpClient = createSecureHttpClient({
  wasmUrl: fetchWasmUrl,
})
