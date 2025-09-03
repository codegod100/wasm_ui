# Odin WASM UI Chat Example

An Odin + WebAssembly UI example with a minimal virtual DOM, a small static server powered by `odin-http`, and JWT-backed endpoints. The UI runs in the browser (WASM), while the native server serves static files and a tiny JSON API.

## Features

- Chat UI rendered from Odin to the DOM via JS bridges
- Fixed-height, scrollable message list with auto-scroll and focus preservation
- Send messages from the UI; server stores them in memory (max 200)
- JWT (HS256) demo endpoints with constant-time signature verification
- “Who Am I” button to validate the JWT from the browser

## Prerequisites

- Odin toolchain (tested with `odin version dev-2025-08`)
- just (optional but recommended): `just --version`

## Quick Start

- Build and run everything:
  - `just serve`
  - Open `http://localhost:8080/`

The `serve` recipe will:
- Fetch `vendor/odin-http` if missing (`just vendor`)
- Build the WASM UI (`just build` → `ui.wasm`)
- Build the native server (`just build-server` → `./server_bin`)
- Launch the server on port 8080

## Useful Commands

- Build WASM only: `just build`
- Build server only: `just build-server`
- Fetch/update vendor:
  - `just vendor` (clone odin-http)
  - `just vendor-update` (pull latest)

Without just:
- WASM: `odin build . -target:js_wasm32 -out:./ui.wasm`
- Server: `odin build ./server -collection:local=./vendor -out:./server_bin && ./server_bin`

## Endpoints

- `GET /api/messages` → `[{ user, text, at }]`
- `POST /api/messages` → body `{ user, text }`
- `GET /api/auth/token?sub=NAME` → `{ token }` (HS256 JWT)
- `GET /api/auth/whoami` (requires `Authorization: Bearer <token>`) → `{ payload }`
- `GET /api/health` → `{ ok: true }`
- `GET /api/time` → `{ now: "YYYY-MM-DD HH:MM:SS" }`

## File Overview

- `index.html` — Boots the WASM, provides DOM/JS bridge and loading spinner
- `odin.js` — Odin’s JS runtime/loader required by `index.html` (not tracked; copied at build if missing)
- `main.odin` — UI state + components; fetch handlers, JWT wiring
- `vdom.odin` — Minimal virtual DOM node definitions
- `renderer.odin` — DOM builder + JS foreign imports (events, fetch, focus)
- `events.odin` — Event dispatch from JS → Odin and rerender
- `server/main.odin` — Static server, JSON API, rate limiting, logging
- `server/jwt.odin` — HS256 sign/verify and base64url helpers
- `justfile` — Build/serve tasks; vendor management

## Notes

- Messages are stored in-memory. Restarting the server clears history.
- JWT secret defaults to `dev-secret-change-me` (see `server/main.odin`). Swap for production.
- The app shows a spinner until the first render; on failure, it replaces the spinner with a friendly error.

## Troubleshooting

- If the server can’t find `odin-http`, run `just vendor`.
- If the browser fetches fail, check DevTools Network and the terminal logs. The UI logs status and up to 200 chars of body on parse failures.
- If you see a 404 for `odin.js`, run `just build` (it will attempt to copy it). You can set `ODIN_JS_PATH` to point to your local Odin `odin.js`.

---
This is an educational example; harden and review before production use.
