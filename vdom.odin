package main

// Minimal VDOM structures and helpers

Node_Kind :: enum { Text, Elem, Fragment }

Node :: struct {
    kind: Node_Kind,
    tag: string,                    // for Elem
    text: string,                   // for Text
    props: map[string]string,
    children: [dynamic]Node,
}

Text :: proc(s: string) -> Node {
    return Node{ kind = .Text, text = s };
}

Elem :: proc(tag: string, props: map[string]string, children: ..Node) -> Node {
    kids, _ := make([dynamic]Node);
    for c in children { _, _ = append(&kids, c) }
    return Node{ kind = .Elem, tag = tag, props = props, children = kids };
}

// Convenience helpers for common tags
Div :: proc(props: map[string]string, children: ..Node) -> Node {
    return Elem("div", props, ..children);
}

Button :: proc(props: map[string]string, children: ..Node) -> Node {
    return Elem("button", props, ..children);
}

