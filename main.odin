package main

import "core:fmt"
import "core:strings"
import json "core:encoding/json"

// Simple global state for the demo
// Chat state
messages: [dynamic]string
draft_buf: [1024]u8
fetch_buf: [16384]u8
current_username: string

Server_Message :: struct { user: string, text: string, at: string }
Token_Response :: struct { token: string }
WhoAmI_Response :: struct { payload: string }

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
    // Require login (auth token + resolved username)
    if !js_has_auth_token() || len(strings.trim_space(current_username)) == 0 {
        append_message("Please sign in with a passkey to send messages.")
        return
    }
    // clear input
    js_set_value_by_id("chat-input", "")
    // POST to backend; on completion event 11 will fire
    body := struct{ text: string }{ text }
    data, merr := json.marshal(body)
    if merr != nil {
        append_message("Error: could not encode message")
        return
    }
    js_fetch_post_json("/api/messages", string(data), 11)
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
    // Disable browser autocomplete and helpers
    input_props["autocomplete"] = "off"
    input_props["autocorrect"] = "off"
    input_props["autocapitalize"] = "off"
    input_props["spellcheck"] = "false"
    input_props["enterkeyhint"] = "send"
    // Enter to send
    input_props["on:enter"] = "1"

    send_btn := make(map[string]string)
    send_btn["on:click"] = "1"

    clear_btn := make(map[string]string)
    clear_btn["on:click"] = "3"

    whoami_btn := make(map[string]string)
    whoami_btn["on:click"] = "12"

    // Chat header and actions
    header_props := make(map[string]string)
    header_props["class"] = "chat-header"
    header := Div(header_props,
        Text(fmt.tprintf("Simple Chat — %s", (current_username if len(current_username) > 0 else "You"))),
    )

    list_container_props := make(map[string]string)
    list_container_props["id"] = "chat-list"
    list_container_props["class"] = "chat-list"
    list_container_props["style"] = "height:260px; overflow-y:auto; border:1px solid #ddd; border-radius:8px; padding:8px;"
    list_container := Div(list_container_props, ..msg_nodes[:])

    actions_props := make(map[string]string)
    actions_props["class"] = "chat-actions"
    actions := Div(actions_props,
        Input(input_props),
        Button(send_btn, Text(" Send ")),
        Button(whoami_btn, Text(" Who Am I ")),
        Button(clear_btn, Text(" Clear ")),
    )

    return Div(root_props,
        header,
        list_container,
        actions,
    )
}

// Fetch handlers
on_messages_fetched :: proc() {
    status := js_get_fetch_status()
    n := js_get_fetch_body(&fetch_buf[0], i32(len(fetch_buf)))
    total := int(n)
    if total < 0 { total = 0 }
    if total > len(fetch_buf) { total = len(fetch_buf) }
    s := string(fetch_buf[:total])

    if status != 200 || total <= 0 {
        // Log status and a small body preview to help debugging
        prev_len := total
        if prev_len > 200 { prev_len = 200 }
        preview := s[:prev_len]
        append_message(fmt.tprintf("Fetch /api/messages failed (status %v): %s", status, preview))
        return
    }

    // Parse JSON array of Server_Message
    arr: []Server_Message
    if uerr := json.unmarshal_string(s, &arr); uerr != nil {
        prev_len := len(s)
        if prev_len > 200 { prev_len = 200 }
        preview := s[:prev_len]
        append_message(fmt.tprintf("Error: bad JSON from /api/messages (%v). Body preview: %s", uerr, preview))
        return
    }
    // Rebuild messages from server
    messages = nil
    for m in arr {
        append_message(fmt.tprintf("%s: %s", m.user, m.text))
    }
}

on_post_done :: proc() {
    // After posting, refresh messages
    js_fetch_get("/api/messages", 10)
}

on_token_fetched :: proc() {
    n := js_get_fetch_body(&fetch_buf[0], i32(len(fetch_buf)))
    total := int(n)
    if total <= 0 { return }
    s := string(fetch_buf[:total])
    tr: Token_Response
    if err := json.unmarshal_string(s, &tr); err != nil || len(tr.token) == 0 {
        append_message(fmt.tprintf("Auth token error: %v, body: %s", err, s[:min(total, 120)]))
        return
    }
    js_set_auth_token(tr.token)
    // now fetch messages with auth
    js_fetch_get("/api/messages", 10)
}

on_whoami_click :: proc() {
    js_fetch_get("/api/auth/whoami", 30)
}

on_whoami_fetched :: proc() {
    status := js_get_fetch_status()
    n := js_get_fetch_body(&fetch_buf[0], i32(len(fetch_buf)))
    total := int(n)
    if total < 0 { total = 0 }
    s := string(fetch_buf[:total])
    if status != 200 {
        prev := total; if prev > 120 { prev = 120 }
        append_message(fmt.tprintf("WhoAmI failed (status %v): %s", status, s[:prev]))
        return
    }
    resp: WhoAmI_Response
    if err := json.unmarshal_string(s, &resp); err != nil {
        prev := total; if prev > 120 { prev = 120 }
        append_message(fmt.tprintf("WhoAmI bad JSON (%v): %s", err, s[:prev]))
        return
    }
    msg := strings.concatenate([]string{"WhoAmI: ", resp.payload}, context.allocator)
    append_message(msg)
}

// Handler to pull username from JS and rerender
on_current_user_updated :: proc() {
    // Reuse draft_buf as scratch to fetch name from JS
    n := js_get_current_user(&draft_buf[0], i32(len(draft_buf)))
    if n < 0 { n = 0 }
    name := string(draft_buf[:int(n)])
    current_username = fmt.tprintf("%s", name)
    rerender()
}

main :: proc() {
    register_handler(1, on_send)
    register_handler(3, on_clear)
    register_handler(10, on_messages_fetched)
    register_handler(11, on_post_done)
    register_handler(20, on_token_fetched)
    register_handler(12, on_whoami_click)
    register_handler(30, on_whoami_fetched)
    register_handler(60, on_current_user_updated)
    mount("#app", App)
    // Load messages (public)
    js_fetch_get("/api/messages", 10)
}
