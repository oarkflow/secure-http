# React Secure HTTP Demo

This example pairs a React frontend with the Fiber todo backend in the same `examples/react-app` directory.
It includes its own local secure HTTP browser client under `src/lib/client`,
restores cookie-backed auth sessions, and sends todo API requests through the WASM bridge.

## Ports

- Frontend dev server: `http://localhost:5173`
- Backend Fiber server: `http://localhost:9443`

The frontend talks to the backend directly. There is no Vite proxy.

## Environment

Create `examples/react-app/.env.local`:

```bash
cp .env.example .env.local
```

Default value:

```env
VITE_SECURE_HTTP_BACKEND_URL=http://localhost:9443
```

Use the same hostname for frontend and backend.
For local development, stick to `localhost` for both instead of mixing `localhost`
and `127.0.0.1`, otherwise cookie-based auth and CSRF reads can break.

## Run the Backend

From the repo root:

```bash
make run-server
```

That target starts the Fiber backend on port `9443`.
If you need to refresh the bundled WASM bridge first, run:

```bash
make wasm
```

If you prefer the raw command, this is what it runs:

```bash
go run ./examples/react-app \
  -config config.dev.json \
  -addr :9443
```

To serve the production React build from the same Go process:

```bash
go run ./examples/react-app \
  -config config.production.json \
  -web ./examples/react-app/dist \
  -static-prefix / \
  -addr :9443
```

Use `config.dev.json` for local HTTP development and `config.production.json` as the strict HTTPS deployment template.

## Run the PHP Backend

There is also a Composer-based PHP demo server in `examples/php-server`.

From `examples/php-server`:

```bash
composer install
composer run serve
```

That server listens on `http://127.0.0.1:9080` and exposes the same login, bootstrap, handshake, and todo routes as the Go demo.

## Run the Frontend

From `examples/react-app`:

```bash
npm install
npm run dev -- --host localhost --port 5173
```

To point the React app at the PHP demo server instead:

```bash
VITE_SECURE_HTTP_BACKEND_URL=http://127.0.0.1:9080 npm run dev -- --host 127.0.0.1 --port 5173
```

Then open:

```text
http://localhost:5173/
```

## Sample Credentials

- `alice` / `alice-password`
- `bob` / `bob-password`

## Production Build

From `examples/react-app`:

```bash
npm run build
```

## Notes

- The frontend depends on the backend being up first.
- Auth uses backend cookies plus CSRF protection.
- If the backend restarts and invalidates the session, the frontend clears its saved
  session state and sends the user back through login.
- Encrypted API traffic starts after login/bootstrap completes successfully.
