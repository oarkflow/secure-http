# PHP Secure HTTP Demo

This example runs the Secure HTTP todo demo on plain PHP using the Composer SDK in `sdks/server/php`.

It exposes the same routes the React app already expects:

- `POST /auth/login`
- `POST /auth/bootstrap`
- `POST /auth/logout`
- `POST /handshake`
- `GET/POST /api/todos`
- `PUT/DELETE /api/todos/{id}`

## Run the PHP server

From `examples/php-server`:

```bash
composer install
composer run serve
```

The demo server listens on:

```text
http://127.0.0.1:9080
```

## Run the React app against PHP

From `examples/react-app`:

```bash
npm install
VITE_SECURE_HTTP_BACKEND_URL=http://127.0.0.1:9080 npm run dev -- --host 127.0.0.1 --port 5173
```

## Sample credentials

- `alice` / `alice-password`
- `bob` / `bob-password`

## Production-style same-origin demo

Build the React app:

```bash
cd ../react-app
VITE_SECURE_HTTP_BACKEND_URL=http://127.0.0.1:9080 npm run build
```

Then start the PHP server again. If `examples/react-app/dist` exists, the PHP demo server will serve that build for non-API routes.
