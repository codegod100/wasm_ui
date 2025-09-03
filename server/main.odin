package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:time"
import "core:encoding/json"
import "core:strconv"
import "core:strings"

import http "local:odin-http"

PostBody :: struct { user: string, text: string }
JWT_Payload :: struct { sub: string, iat: string }
jwt_secret: string

main :: proc() {
    context.logger = log.create_console_logger(.Info)

    // Initialize storage (Turso or memory)
    storage_init()

    s: http.Server
    http.server_shutdown_on_interrupt(&s)

    router: http.Router
    http.router_init(&router)
    defer http.router_destroy(&router)

    // API routes
    // JWT demo: issue and verify
    jwt_secret = strings.clone("dev-secret-change-me", context.allocator)
    http.route_get(&router, "/api/auth/token", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        sub := http.query_get(req.url, "sub") or_else "demo"
        now := time.now()
        sbuf: [32]u8
        iat := strconv.itoa(sbuf[:], int(time.to_unix_seconds(now)))
        // Minimal payload; in a real app include exp, iss, aud, etc.
        p := JWT_Payload{sub = sub, iat = iat}
        pdata, perr := json.marshal(p)
        if perr != nil {
            http.respond(res, http.Status.Internal_Server_Error)
            return
        }
        payload := string(pdata)
        token := jwt_sign_hs256(payload, transmute([]byte) jwt_secret, context.temp_allocator)
        http.respond_json(res, struct{ token: string }{ token })
    }))

    http.route_get(&router, "/api/auth/whoami", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        auth, ok := http.headers_get_unsafe(req.headers, "authorization")
        if !ok || !strings.has_prefix(auth, "Bearer ") {
            http.respond(res, http.Status.Unauthorized)
            return
        }
        tok := strings.trim_prefix(auth, "Bearer ")
        okv, payload := jwt_verify_hs256(tok, transmute([]byte) jwt_secret, context.temp_allocator)
        if !okv {
            http.respond(res, http.Status.Unauthorized)
            return
        }
        // Return the raw payload JSON back
        http.respond_json(res, struct{ payload: string }{ payload })
    }))
    http.route_get(&router, "/api/health", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_json(res, struct{ ok: bool }{true})
    }))
    http.route_get(&router, "/api/storage", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_json(res, storage_status())
    }))

    http.route_get(&router, "/api/time", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        now := time.now()
        dbuf: [time.MIN_YYYY_DATE_LEN]u8
        tbuf: [time.MIN_HMS_LEN]u8
        ts := fmt.tprintf("%s %s", time.to_string_yyyy_mm_dd(now, dbuf[:]), time.to_string_hms(now, tbuf[:]))
        body := struct{ now: string }{ ts }
        http.respond_json(res, body)
    }))

    // Turso is configured via environment variables in storage_init()

    // Messages
    http.route_get(&router, "/api/messages", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        msgs, ok := get_messages()
        if !ok { http.respond(res, http.Status.Internal_Server_Error); return }
        http.respond_json(res, msgs)
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
            // Use unix seconds as ASCII and clone into long-lived allocator
            sec := time.to_unix_seconds(n)
            sbuf: [32]u8
            sec_str := strconv.itoa(sbuf[:], int(sec))
            at := strings.clone(sec_str, context.allocator)
            if ok := add_message(Message{ user = pb.user, text = pb.text, at = at }); !ok {
                http.respond(res, http.Status.Internal_Server_Error)
                return
            }
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
