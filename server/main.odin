package main

import "core:fmt"
import "core:log"
import "core:net"

import http "local:odin-http"

main :: proc() {
    context.logger = log.create_console_logger(.Info)

    s: http.Server
    http.server_shutdown_on_interrupt(&s)

    router: http.Router
    http.router_init(&router)
    defer http.router_destroy(&router)

    // Serve index at root
    http.route_get(&router, "/", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        http.respond_file(res, "index.html")
    }))

    // Serve everything else from current directory
    http.route_get(&router, "(.*)", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        http.respond_dir(res, "/", ".", req.url_params[0])
    }))

    routed := http.router_handler(&router)

    addr := net.Endpoint{ address = net.IP4_Loopback, port = 8080 }
    log.infof("Serving on http://%v:%v", addr.address, addr.port)
    if err := http.listen_and_serve(&s, routed, addr); err != nil {
        fmt.printf("server stopped: %v\n", err)
    }
}
