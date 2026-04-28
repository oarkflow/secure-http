import { createSecureHttpClient } from './client'

const fetchWasmUrl = `${import.meta.env.BASE_URL}fetch.wasm`

export const secureHttpClient = createSecureHttpClient({
	wasmUrl: fetchWasmUrl,
})
