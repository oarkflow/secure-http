import { createSecureHttpClient } from './secure-fetch'

const fetchWasmUrl = `${import.meta.env.BASE_URL}fetch.wasm`

export const secureHttpClient = createSecureHttpClient({
	wasmUrl: fetchWasmUrl,
})
