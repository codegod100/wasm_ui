# Simple build recipe for the WASM UI example

# Configuration
target := "js_wasm32"
out := "ui.wasm"

# Default task
default: build

# Build the WASM module
build:
	odin build . -target:{{target}} -out:./{{out}}

# Build the native server (requires odin-http in vendor/)
build-server:
	odin build ./server -collection:local=./vendor -out:./server_bin

# Build both wasm and server
build-all: build build-server

# Run the server (builds first)
serve: build-all
	./server_bin
