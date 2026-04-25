import fetchWasmUrl from './client/fetch.wasm?url'
import { createSecureHttpClient } from './client/index.js'

export const secureHttpClient = createSecureHttpClient({
  wasmUrl: fetchWasmUrl,
})
