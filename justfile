# Simple build recipe for the WASM UI example

# Configuration
target := "js_wasm32"
out := "ui.wasm"

# Default task
default: build

# Ensure `odin.js` is present (copy if needed)
ensure-odin-js:
	@if [ -f odin.js ]; then \
		echo "odin.js present"; \
	elif [ -n "${ODIN_JS_PATH:-}" ] && [ -f "$ODIN_JS_PATH" ]; then \
		cp "$ODIN_JS_PATH" ./odin.js; \
		echo "Copied odin.js from ODIN_JS_PATH"; \
	elif [ -f ../wasm_hello/odin.js ]; then \
		cp ../wasm_hello/odin.js ./odin.js; \
		echo "Copied odin.js from ../wasm_hello"; \
	else \
		echo "Missing odin.js. Set ODIN_JS_PATH to the path of Odin's odin.js or copy it here." >&2; \
		exit 1; \
	fi

# Build the WASM module
build: ensure-odin-js
	odin build . -target:{{target}} -out:./{{out}}

# Build the native server (requires odin-http in vendor/)
build-server: vendor
	odin build ./server -collection:local=./vendor -out:./server_bin

# Build both wasm and server
build-all: build build-server

# Run the server (builds first)
serve: build-all
	./server_bin

# Fetch vendored dependencies (odin-http)
vendor:
	mkdir -p vendor
	@if [ -d vendor/odin-http/.git ]; then \
		echo "vendor/odin-http already present"; \
	else \
		git clone https://github.com/laytan/odin-http vendor/odin-http; \
	fi

# Update vendored dependencies
vendor-update:
	@if [ -d vendor/odin-http/.git ]; then \
		git -C vendor/odin-http pull --ff-only; \
	else \
		echo "vendor/odin-http missing; run: just vendor"; \
	fi
