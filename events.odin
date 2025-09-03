package main

import "core:runtime"

handlers: map[u32]proc()

register_handler :: proc(id: u32, f: proc()) {
    if handlers == nil { handlers = make(map[u32]proc()) }
    handlers[id] = f;
}

@(export) on_event :: proc "contextless" (id: u32) {
    // Provide a default context for calls from JS
    context = runtime.default_context()
    if handlers == nil { return }
    if f, ok := handlers[id]; ok { f() }
    rerender();
}
