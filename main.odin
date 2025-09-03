package main

import "core:fmt"

// Simple global state for the demo
count: i32

on_increment :: proc() {
    count += 1
}

on_decrement :: proc() {
    count -= 1
}

App :: proc() -> Node {
    props := make(map[string]string)
    label := fmt.tprintf("Count: %v", count)

    inc_btn := make(map[string]string)
    inc_btn["on:click"] = "1"

    dec_btn := make(map[string]string)
    dec_btn["on:click"] = "2"

    return Div(props,
        Text(label),
        Button(inc_btn, Text(" Increment ")),
        Button(dec_btn, Text(" Decrement ")),
    )
}

main :: proc() {
    register_handler(1, on_increment)
    register_handler(2, on_decrement)
    mount("#app", App)
}
