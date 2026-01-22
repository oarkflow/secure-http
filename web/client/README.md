# SecureFetch JS Client

A JavaScript/WASM client for SecureFetch, designed to be used with modern frontend frameworks (React, Vue, etc.) via ESM.

## Installation

```bash
npm install @secure-http/client
```

(Or link locally for development)

## Usage

You need to serve the `securefetch.wasm` file from your public directory.

```javascript
import { SecureClient } from "@secure-http/client";

const client = new SecureClient({
    wasmUrl: "/securefetch.wasm",
    labConfig: {
        baseURL: "https://api.example.com",
        deviceID: "device-123",
        // ... other config
    }
});

async function main() {
    try {
        await client.init();
        const data = await client.fetch("/api/secure-data");
        console.log(data);
    } catch (err) {
        console.error("Secure fetch failed:", err);
    }
}
```

## React Example

```jsx
import React, { useEffect, useState } from 'react';
import { SecureClient } from '@secure-http/client';

const client = new SecureClient({
    wasmUrl: "/securefetch.wasm",
    labConfig: { /* ... */ }
});

export function SecureComponent() {
    const [data, setData] = useState(null);

    useEffect(() => {
        client.fetch("/api/profile").then(setData);
    }, []);

    if (!data) return <div>Loading...</div>;
    return <div>{JSON.stringify(data)}</div>;
}
```
