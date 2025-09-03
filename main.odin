package main

import "core:fmt"

// Simple global state for the demo
count: i32

on_click :: proc() {
    count += 1
}

App :: proc() -> Node {
    props := make(map[string]string)
    label := fmt.tprintf("Count: %v", count)

    btn_props := make(map[string]string)
    btn_props["on:click"] = "1"

    return Div(props,
        Text(label),
        Button(btn_props, Text(" Increment ")),
    )
}

main :: proc() {
    register_handler(1, on_click)
    mount("#app", App)
}

