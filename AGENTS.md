# Repository Guidelines

This repository hosts a minimal Odin + WASM UI and an Odin HTTP server. Follow these guidelines to contribute safely and efficiently.

## Project Structure & Module Organization

- Root UI (WASM): `main.odin`, `renderer.odin`, `vdom.odin`, `events.odin`, `index.html`, `odin.js`.
- Server: `server/` (HTTP API, JWT, storage). Key files: `server/main.odin`, `server/jwt.odin`, `server/storage.odin`.
- Vendor deps: `vendor/odin-http/` (external). Do not modify vendored code.
- Build outputs: `ui.wasm`, `server_bin`.

## Build, Test, and Development Commands

- `just build`: Build the WASM module to `ui.wasm`.
- `just build-server`: Build the native server to `./server_bin`.
- `just serve`: Build both and run the server on `http://127.0.0.1:8080`.
- Without Just:
  - UI: `odin build . -target:js_wasm32 -out:./ui.wasm`
  - Server: `odin build ./server -collection:local=./vendor -out:./server_bin && ./server_bin`

## Coding Style & Naming Conventions

- Language: Odin. Follow existing patterns: snake_case procs/vars, `PascalCase` types, concise functions.
- Indentation: match surrounding files; keep diffs minimal.
- Imports: prefer `core:*` and `local:odin-http` collections already used.
- Do not patch files in `vendor/`.

## Testing Guidelines

- No formal test suite yet. Verify manually:
  - Load UI at `http://localhost:8080` and send messages.
  - Exercise API: `GET/POST /api/messages`, `GET /api/auth/token`, `GET /api/auth/whoami`.
  - Check server logs for warnings/errors.
- If adding tests, keep them small and colocated near new code.

## Commit & Pull Request Guidelines

- Scope: small, focused changes; include rationale in the description.
- Messages: imperative mood, concise summary, and context (e.g., "server: persist messages via Turso").
- PRs: describe changes, steps to validate, and any new env vars. Include screenshots or curl examples for UI/API changes.
- Do not change vendored code; bump or vendor-update instead.

## Security & Configuration Tips

- Persistence: set `TURSO_DATABASE_URL`/`TURSO_AUTH_TOKEN` (or `LIBSQL_URL`/`LIBSQL_AUTH_TOKEN`). Just loads `.env` (`set dotenv-load := true`).
- JWT: default dev secret in `server/main.odin`; replace for production.
- Rate limits and logging are enabled by default; keep them in place for demos.

## Strict Behavior (No Fallbacks)

- No fallbacks: storage is Turso-only. Do not reintroduce in-memory or mock stores.
- No “simplified” code paths: avoid hidden retries, silent error swallowing, or behavior divergence between Just and raw runs.
- Do not patch vendored code (`vendor/`); update via `just vendor-update` if needed.
- On storage errors, return 500 and log precise context (HTTP status, SQL, message). Keep startup non-blocking but do not degrade functionality.
