package main

import "core:fmt"

// Simple global state for the demo
// Chat state
messages: [dynamic]string

append_message :: proc(msg: string) {
    if messages == nil { messages, _ = make([dynamic]string) }
    _, _ = append(&messages, msg)
}

on_send_hello :: proc() {
    append_message("You: Hello")
}

on_bot_reply :: proc() {
    append_message("Bot: Hi there!")
}

on_clear :: proc() {
    messages = nil
}

App :: proc() -> Node {
    root_props := make(map[string]string)

    // Build message list nodes
    msg_nodes, _ := make([dynamic]Node)
    if messages != nil {
        for msg in messages {
            row_props := make(map[string]string)
            row := Div(row_props, Text(msg))
            _, _ = append(&msg_nodes, row)
        }
    }

    // Buttons
    send_btn := make(map[string]string)
    send_btn["on:click"] = "1"

    bot_btn := make(map[string]string)
    bot_btn["on:click"] = "2"

    clear_btn := make(map[string]string)
    clear_btn["on:click"] = "3"

    // Chat header and actions
    header_props := make(map[string]string)
    header := Div(header_props,
        Text("Simple Chat"),
    )

    list_container_props := make(map[string]string)
    list_container := Div(list_container_props, ..msg_nodes[:])

    actions_props := make(map[string]string)
    actions := Div(actions_props,
        Button(send_btn, Text(" Send Hello ")),
        Button(bot_btn, Text(" Bot Reply ")),
        Button(clear_btn, Text(" Clear ")),
    )

    return Div(root_props,
        header,
        list_container,
        actions,
    )
}

main :: proc() {
    register_handler(1, on_send_hello)
    register_handler(2, on_bot_reply)
    register_handler(3, on_clear)
    mount("#app", App)
}
