# rustunnel demo server

Zero-dependency Node.js web app for demoing the rustunnel client.

## Usage

```bash
# Start on port 3000 (default)
node server.js

# Start on a custom port
node server.js 8080
# or
PORT=8080 node server.js
```

Then in another terminal:

```bash
rustunnel http 3000 --subdomain demo
```

## Pages

| Route | Description |
|-------|-------------|
| `/` | Home page |
| `/about` | How the tunnel works |
| `/live` | Live request counter (auto-refreshes every 2 s) |
| `/api-demo` | Interactive JSON API explorer |

## JSON API

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Uptime, request count, Node version, timestamp |
| `GET /api/requests` | Last 10 requests seen by the server |
| `GET /api/echo?msg=hello` | Echo headers + query param back as JSON |
