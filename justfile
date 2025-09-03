# Simple build recipe for the WASM UI example

# Configuration
target := "js_wasm32"
out := "ui.wasm"

# Default task
default: build

# Build the WASM module
build:
	odin build . -target:{{target}} -out:./{{out}}

