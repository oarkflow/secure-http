# React Secure HTTP Demo

This app is a React frontend for the `examples/todo_password_server` Fiber backend.
It uses the shared secure HTTP browser client from `cmd/fullstack/client`, restores
cookie-backed auth sessions, and sends todo API requests through the WASM bridge.

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
make run-todo-sample
```

That target:

- builds `fetch.wasm`
- stages the browser assets for the sample backend
- starts the Fiber server on port `9443`

If you prefer the raw command, this is what it runs:

```bash
go run ./examples/todo_password_server \
  -config config/todo-server.json \
  -web ./examples/todo_password_server/web \
  -static-prefix /todo \
  -addr :9443
```

## Run the Frontend

From `examples/react-app`:

```bash
npm install
npm run dev -- --host localhost --port 5173
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
