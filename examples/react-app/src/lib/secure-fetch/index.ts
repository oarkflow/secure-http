import { createSecureHttpClient } from './client'

export * from './client'
export * from './react'
export * from './session'
export * from './types'


const fetchWasmUrl = `${import.meta.env.BASE_URL ?? ''}fetch.wasm`

export const client = createSecureHttpClient({
	wasmUrl: fetchWasmUrl,
})
