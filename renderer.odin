package main

import "core:strconv"

// JS imports provided by index.html via `globalThis.js = { ... }`
foreign import "js"
@(default_calling_convention="contextless")
foreign js {
    js_query_selector   :: proc(sel: string) -> u32 ---
    js_create_element   :: proc(tag: string) -> u32 ---
    js_create_text_node :: proc(text: string) -> u32 ---
    js_set_attr         :: proc(el: u32, name, value: string) ---
    js_append_child     :: proc(parent, child: u32) ---
    js_remove_children  :: proc(el: u32) ---
    js_add_event        :: proc(el: u32, ev: string, id: u32) ---
}

root_el: u32
builder_proc: proc() -> Node

build_dom :: proc(n: Node) -> u32 {
    if n.kind == .Text {
        return js_create_text_node(n.text);
    }
    if n.kind == .Elem {
        el := js_create_element(n.tag);
        // set attributes and events
        for k, v in n.props {
            if k == "on:click" {
                id_u64, _ := strconv.parse_u64(v);
                js_add_event(el, "click", u32(id_u64));
            } else {
                js_set_attr(el, k, v);
            }
        }
        for child in n.children {
            ch := build_dom(child);
            js_append_child(el, ch);
        }
        return el;
    }
    // Fragment or unknown -> collapse children into a DocumentFragment-like div
    el := js_create_element("div");
    for child in n.children { js_append_child(el, build_dom(child)) }
    return el;
}

mount :: proc(root_selector: string, app: proc() -> Node) {
    builder_proc = app;
    root_el = js_query_selector(root_selector);
    rerender();
}

rerender :: proc() {
    if root_el == 0 { return }
    js_remove_children(root_el);
    vnode := builder_proc();
    dom := build_dom(vnode);
    js_append_child(root_el, dom);
}
