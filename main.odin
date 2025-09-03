package main

import "core:fmt"
import "core:strings"

// Simple global state for the demo
// Chat state
messages: [dynamic]string
draft_buf: [1024]u8

get_input_text :: proc() -> string {
    // Fetch value of the input with id="chat-input" from JS into draft_buf
    n := js_get_value_by_id("chat-input", &draft_buf[0], i32(len(draft_buf)))
    if n < 0 { n = 0 }
    s := string(draft_buf[:int(n)])
    // Copy to a fresh string so it survives future overwrites
    return fmt.tprintf("%s", s)
}

append_message :: proc(msg: string) {
    if messages == nil { messages, _ = make([dynamic]string) }
    _, _ = append(&messages, msg)
}

on_send :: proc() {
    text := strings.trim_space(get_input_text())
    if len(text) == 0 { return }
    append_message(fmt.tprintf("You: %s", text))
    // simple bot echo
    reply := fmt.tprintf("Bot: You said '%s'", text)
    append_message(reply)
    // clear the input field in the DOM
    js_set_value_by_id("chat-input", "")
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

    // Input + Buttons
    input_props := make(map[string]string)
    input_props["id"] = "chat-input"
    input_props["type"] = "text"
    input_props["placeholder"] = "Type a message..."
    // Enter to send
    input_props["on:enter"] = "1"

    send_btn := make(map[string]string)
    send_btn["on:click"] = "1"

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
        Input(input_props),
        Button(send_btn, Text(" Send ")),
        Button(clear_btn, Text(" Clear ")),
    )

    return Div(root_props,
        header,
        list_container,
        actions,
    )
}

main :: proc() {
    register_handler(1, on_send)
    register_handler(3, on_clear)
    mount("#app", App)
}
