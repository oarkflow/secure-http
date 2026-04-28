import { defineConfig } from "@playwright/test";

export default defineConfig({
    testDir: "./tests/e2e",
    timeout: 30_000,
    webServer: [
        {
            command: "go run ./examples/react-app -config config.dev.json -addr :8443",
            port: 8443,
            reuseExistingServer: true,
        },
        {
            command: "npm run dev -- --host 127.0.0.1 --port 5173",
            cwd: "./examples/react-app",
            port: 5173,
            reuseExistingServer: true,
        },
    ],
    use: {
        baseURL: "http://127.0.0.1:5173",
        headless: true,
    },
});
