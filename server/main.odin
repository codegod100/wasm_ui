package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:sync"
import "core:time"
import "core:encoding/json"

import http "local:odin-http"

// In-memory message store (demo-only)
Message :: struct { user: string, text: string, at: string }
PostBody :: struct { user: string, text: string }
messages: [dynamic]Message
messages_mu: sync.Mutex
max_messages := 200

add_message :: proc(m: Message) {
    sync.lock(&messages_mu)
    defer sync.unlock(&messages_mu)
    if messages == nil { messages, _ = make([dynamic]Message) }
    _, _ = append(&messages, m)
    if len(messages) > max_messages {
        // Drop oldest to keep memory bounded
        start := len(messages) - max_messages
        trimmed, _ := make([dynamic]Message, 0, max_messages)
        for x in messages[start:] { _, _ = append(&trimmed, x) }
        messages = trimmed
    }
}

get_messages :: proc() -> []Message {
    sync.lock(&messages_mu)
    defer sync.unlock(&messages_mu)
    if messages != nil {
        return messages[:]
    }
    empty: []Message
    return empty
}

main :: proc() {
    context.logger = log.create_console_logger(.Info)

    s: http.Server
    http.server_shutdown_on_interrupt(&s)

    router: http.Router
    http.router_init(&router)
    defer http.router_destroy(&router)

    // API routes
    http.route_get(&router, "/api/health", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_json(res, struct{ ok: bool }{true})
    }))

    http.route_get(&router, "/api/time", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        now := time.now()
        dbuf: [time.MIN_YYYY_DATE_LEN]u8
        tbuf: [time.MIN_HMS_LEN]u8
        ts := fmt.tprintf("%s %s", time.to_string_yyyy_mm_dd(now, dbuf[:]), time.to_string_hms(now, tbuf[:]))
        body := struct{ now: string }{ ts }
        http.respond_json(res, body)
    }))

    // Messages
    http.route_get(&router, "/api/messages", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_json(res, get_messages())
    }))

    http.route_post(&router, "/api/messages", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        http.body(req, 8<<20, res, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            res := cast(^http.Response)rp
            if berr != nil {
                http.respond(res, http.body_error_status(berr))
                return
            }
            // Parse JSON
            pb: PostBody
            if jerr := json.unmarshal_string(body, &pb); jerr != nil || len(pb.text) == 0 {
                http.respond(res, http.Status.Bad_Request)
                return
            }
            n := time.now()
            dbuf: [time.MIN_YYYY_DATE_LEN]u8
            tbuf: [time.MIN_HMS_LEN]u8
            at := fmt.tprintf("%s %s", time.to_string_yyyy_mm_dd(n, dbuf[:]), time.to_string_hms(n, tbuf[:]))
            add_message(Message{ user = pb.user, text = pb.text, at = at })
            http.respond_json(res, struct{ status: string }{"ok"}, .Created)
        })
    }))

    // Static files
    http.route_get(&router, "/", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_file(res, "index.html")
    }))
    http.route_get(&router, "(.*)", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        http.respond_dir(res, "/", ".", req.url_params[0])
    }))

    routed := http.router_handler(&router)

    // Rate limit: 60 requests/60s per IP
    rl_data: http.Rate_Limit_Data
    rl_opts := http.Rate_Limit_Opts{ window = time.Second * 60, max = 60 }
    limited := http.rate_limit(&rl_data, &routed, &rl_opts)

    // Basic request logger middleware
    logger := http.middleware_proc(&limited, proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
        start := time.now()
        next := h.next.(^http.Handler)
        next.handle(next, req, res)
        dur_ms := int(time.diff(time.now(), start) / time.Millisecond)
        // Method and path
        method := "?"; path := req.url.path
        if rl, ok := req.line.(http.Requestline); ok {
            method = http.method_string(rl.method)
        }
        log.infof("%s %s -> %v (%dms)", method, path, res.status, dur_ms)
    })

    addr := net.Endpoint{ address = net.IP4_Loopback, port = 8080 }
    log.infof("Serving on http://%v:%v", addr.address, addr.port)
    if err := http.listen_and_serve(&s, logger, addr); err != nil {
        fmt.printf("server stopped: %v\n", err)
    }
}
