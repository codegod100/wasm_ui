package main

import "core:fmt"
import "core:log"
import "core:os"
import "core:net"
import "core:bytes"
import "core:c"
import "core:sync"
import "core:encoding/json"
import "core:strconv"
import "core:strings"

// Minimal HTTPS via OpenSSL (vendored)
import openssl "local:odin-http/openssl"
import runtime "base:runtime"

// Message model shared by server
Message :: struct { user: string, text: string, at: string }

// Result window for queries
max_messages := 200

// -----------------------
// Turso (libSQL over HTTP)
// -----------------------
turso_enabled: bool
turso_url:   string
turso_token: string
// Lazily ensure schema to avoid blocking startup when env vars are present.
turso_schema_attempted: bool
turso_schema_ready: bool
storage_last_error: string
storage_last_status: int
storage_last_sql: string
storage_last_rows: int
storage_last_body_preview: string

// -----------------------
// Passkey (WebAuthn) models
// -----------------------
User :: struct { id: string, username: string }
Credential :: struct { id: string, user_id: string, public_key: string, alg: int, sign_count: int, transports: string, created_at: int }

// Helper: random bytes -> base64url string
rand_b64url :: proc(n: int, allocator := context.temp_allocator) -> (out: string, ok: bool) {
    if n <= 0 { return "", false }
    buf := make([]byte, n, allocator)
    // Fill with pseudo-random bytes (sufficient for demo; replace with OS entropy for production)
    rg := runtime.default_random_generator()
    if !runtime.random_generator_read_bytes(rg, buf) { return "", false }
    return base64url_encode(buf, allocator), true
}

// Minimal request/response structs for Turso API
Turso_Result :: struct {
    columns:          []string,
    rows:             [][]string,
    lastInsertRowid:  i64,
    rowsAffected:     i64,
}

// Pipeline (requests-based) request/response
Turso_Pipeline_Stmt :: struct { sql: string, args: []string }
Turso_Pipeline_Request :: struct { type: string, stmt: Turso_Pipeline_Stmt }
Turso_Pipeline_Req :: struct { requests: []Turso_Pipeline_Request }
// Flexible pipeline response shapes seen across deployments
Turso_Pipeline_Result_Direct :: struct { columns: []string, rows: [][]string, lastInsertRowid: i64, rowsAffected: i64 }
Turso_Pipeline_Result_Wrapped1 :: struct { result: Turso_Pipeline_Result_Direct }
Turso_Pipeline_Result_Wrapped2 :: struct { response: Turso_Pipeline_Result_Direct }
Turso_Pipeline_Response_Ok :: struct { type: string, result: Turso_Pipeline_Result_Direct }
Turso_Pipeline_Result_Wrapped3 :: struct { response: Turso_Pipeline_Response_Ok }
Turso_Pipeline_Resp_Direct :: struct { results: []Turso_Pipeline_Result_Direct }
Turso_Pipeline_Resp_Wrapped1 :: struct { results: []Turso_Pipeline_Result_Wrapped1 }
Turso_Pipeline_Resp_Wrapped2 :: struct { results: []Turso_Pipeline_Result_Wrapped2 }
Turso_Pipeline_Resp_Wrapped3 :: struct { results: []Turso_Pipeline_Result_Wrapped3 }

// Variant where result.rows are arrays of typed cells: { type, value }
Turso_Cell :: struct { type: string, value: string }
Turso_ColMeta :: struct { name: string, decltype: Maybe(string) }
Turso_Result_Cells :: struct { cols: []Turso_ColMeta, rows: [][]Turso_Cell }
Turso_Pipeline_Response_Ok_Cells :: struct { type: string, response: struct { type: string, result: Turso_Result_Cells } }
Turso_Pipeline_Resp_Wrapped_Cells :: struct { results: []Turso_Pipeline_Response_Ok_Cells }

// Error decoding helpers (common response shapes)
Turso_ErrA :: struct { message: string }
Turso_ErrB :: struct { error: string, message: string, code: string, details: string, errorMessage: string }
Turso_ErrC_Inner :: struct { message: string, code: string }
Turso_ErrC :: struct { error: Turso_ErrC_Inner }

// Internal helper to POST a pipeline request
// Very small HTTPS client to avoid pulling the vendor http client (to prevent package duplication issues).
// Supports only HTTPS, basic headers, and reads full response until EOF.
// Returns full body and numeric status.
https_post_json :: proc(target_url: string, bearer_token: string, json_body: string, allocator := context.temp_allocator) -> (status: int, body: string, ok: bool) {
    // Parse URL: expect https://host[:port]/path
    if !strings.has_prefix(target_url, "https://") {
        log.warnf("turso only supports https URLs, got: %s", target_url)
        return 0, "", false
    }
    rest := target_url[8:]
    slash := strings.index_byte(rest, '/')
    hostport := rest
    path := "/"
    if slash >= 0 { hostport = rest[:slash]; path = rest[slash:] }
    colon := strings.index_byte(hostport, ':')
    host := hostport
    port := 443
    if colon >= 0 {
        host = hostport[:colon]
        if p, okp := strconv.parse_int(hostport[colon+1:], 10); okp { port = p }
    }

    // Resolve host
    ep4, ep6, rerr := net.resolve(host)
    if rerr != nil { return 0, "", false }
    endpoint := ep4 if ep4.address != nil else ep6
    endpoint.port = port

    // TCP connect
    sock, derr := net.dial_tcp(endpoint)
    if derr != nil { return 0, "", false }

    // TLS handshake
    ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
    ssl := openssl.SSL_new(ctx)
    openssl.SSL_set_fd(ssl, c.int(sock))
    chost := strings.clone_to_cstring(host, allocator)
    defer delete(chost, allocator)
    _ = openssl.SSL_set_tlsext_host_name(ssl, chost)
    switch openssl.SSL_connect(ssl) {
    case 1: // ok
    case 2: log.warn("openssl controlled shutdown"); return 0, "", false
    case:   log.warn("openssl fatal shutdown");     return 0, "", false
    }

    // Build request
    req := strings.builder_make(0, 256 + len(json_body), allocator)
    strings.write_string(&req, "POST ")
    strings.write_string(&req, path)
    strings.write_string(&req, " HTTP/1.1\r\n")
    strings.write_string(&req, "host: ")
    strings.write_string(&req, host)
    if port != 443 { strings.write_string(&req, fmt.tprintf(":%d", port)) }
    strings.write_string(&req, "\r\n")
    strings.write_string(&req, "accept: */*\r\n")
    strings.write_string(&req, "user-agent: wasm-ui-server\r\n")
    strings.write_string(&req, "connection: close\r\n")
    strings.write_string(&req, "authorization: Bearer ")
    strings.write_string(&req, bearer_token)
    strings.write_string(&req, "\r\n")
    // Prefer strong read-after-write consistency to avoid replica lag on immediate reads
    // Headers are ignored by servers that don't recognize them
    strings.write_string(&req, "x-turso-consistency: strong\r\n")
    strings.write_string(&req, "x-libsql-consistency: strong\r\n")
    strings.write_string(&req, "content-type: application/json\r\n")
    strings.write_string(&req, "content-length: ")
    lbuf: [32]u8
    strings.write_string(&req, strconv.itoa(lbuf[:], len(json_body)))
    strings.write_string(&req, "\r\n\r\n")
    strings.write_string(&req, json_body)
    req_str := strings.to_string(req)

    // Send
    data := transmute([]byte)req_str
    to_write := len(data)
    for to_write > 0 {
        n := openssl.SSL_write(ssl, raw_data(data), c.int(to_write))
        if n <= 0 { log.warn("ssl write failed"); return 0, "", false }
        data = data[n:]
        to_write -= int(n)
    }

    // Read response until headers parsed and expected body length is fully read.
    buff: [4096]byte
    out: bytes.Buffer
    bytes.buffer_init_allocator(&out, 0, 0, allocator)
    defer bytes.buffer_destroy(&out)

    have_headers := false
    header_end := -1
    content_len := -1
    for {
        r := openssl.SSL_read(ssl, &buff[0], c.int(len(buff)))
        if r <= 0 { break }
        bytes.buffer_write(&out, buff[:r])

        if !have_headers {
            resp_so_far := string(bytes.buffer_to_bytes(&out))
            idx := strings.index(resp_so_far, "\r\n\r\n")
            if idx >= 0 {
                have_headers = true
                header_end = idx + 4
                // Try to parse Content-Length
                hdrs := resp_so_far[:idx]
                lower, alloc := strings.replace_all(hdrs, "Content-Length:", "content-length:", allocator)
                if alloc { defer delete(lower, allocator) } else { lower = hdrs }
                // Find line starting with content-length:
                pos := strings.index(lower, "content-length:")
                if pos >= 0 {
                    // Slice to end-of-line and parse digits
                    line := lower[pos:]
                    eol := strings.index(line, "\r\n")
                    if eol > -1 { line = line[:eol] }
                    // after colon, skip spaces
                    after := line[16:]
                    // trim spaces
                    after = strings.trim_space(after)
                    if n, okn := strconv.parse_int(after, 10); okn { content_len = n }
                }
            }
        }

        if have_headers && content_len >= 0 {
            if bytes.buffer_length(&out) - header_end >= content_len { break }
        }
    }

    // Convert body to a stable string before destroying buffers
    tmp_bytes := bytes.buffer_to_bytes(&out)
    resp_stable := strings.clone(string(tmp_bytes), context.allocator)

    // Cleanup TLS
    openssl.SSL_free(ssl)
    openssl.SSL_CTX_free(ctx)
    net.close(sock)
    // Parse status line
    line_end := strings.index(resp_stable, "\r\n")
    if line_end <= 0 { return 0, "", false }
    status_part := resp_stable[:line_end]
    sp1 := strings.index_byte(status_part, ' ') ; if sp1 < 0 { return 0, "", false }
    sp2 := strings.index_byte(status_part[sp1+1:], ' '); if sp2 < 0 { return 0, "", false }
    code_str := status_part[sp1+1: sp1+1+sp2]
    code, okc := strconv.parse_int(code_str, 10); if !okc { return 0, "", false }

    // Split headers/body
    sep := strings.index(resp_stable, "\r\n\r\n")
    body_str := ""
    if sep >= 0 {
        if content_len >= 0 && sep+4+content_len <= len(resp_stable) {
            body_str = resp_stable[sep+4: sep+4+content_len]
        } else {
            body_str = resp_stable[sep+4:]
        }
    }
    return code, body_str, true
}

// Helper: basic SQL single-quote escaping for text literals
sql_quote :: proc(s: string, allocator := context.temp_allocator) -> string {
    // Replace ' with '' per SQL standard
    b := strings.builder_make(0, len(s)+4, allocator)
    strings.write_byte(&b, '\'')
    for ch in s {
        if ch == '\'' { strings.write_string(&b, "''") }
        else { strings.write_rune(&b, ch) }
    }
    strings.write_byte(&b, '\'')
    return strings.to_string(b)
}

// Execute a single SQL statement via /v2/pipeline with no parameter binding (values embedded in SQL)
turso_execute :: proc(sql: string, allocator := context.temp_allocator) -> (Turso_Result, bool) {
    resp: Turso_Result
    if !turso_enabled || len(turso_url) == 0 || len(turso_token) == 0 {
        return resp, false
    }

    storage_last_sql = strings.clone(sql, context.allocator)
    // Build pipeline body: { requests: [{ type: "execute", stmt: { sql, args: [] } }] }
    preq := Turso_Pipeline_Req{ requests = []Turso_Pipeline_Request{ { type = "execute", stmt = Turso_Pipeline_Stmt{ sql = sql, args = make([]string, 0) } } } }
    url := strings.concatenate([]string{turso_url, "/v2/pipeline"}, allocator)
    body_json, jerr := json.marshal(preq)
    if jerr != nil { log.warnf("turso marshal error: %v", jerr); return resp, false }

    status, body_str, ok := https_post_json(url, turso_token, string(body_json), allocator)
    storage_last_status = status
    // Save a short preview of the last response body for debugging
    storage_last_body_preview = body_str[:min(400, len(body_str))]
    if !ok || status < 200 || status >= 300 {
        preview := body_str
        if len(preview) > 400 { preview = preview[:400] }
        msg := ""
        // { message }
        ea: Turso_ErrA
        if json.unmarshal_string(body_str, &ea) == nil && len(ea.message) > 0 { msg = ea.message }
        // { error, message, code } or { errorMessage }
        if len(msg) == 0 {
            eb: Turso_ErrB
            if json.unmarshal_string(body_str, &eb) == nil {
                if len(eb.message) > 0 { msg = eb.message }
                if len(msg) == 0 && len(eb.error) > 0 { msg = eb.error }
                if len(msg) == 0 && len(eb.errorMessage) > 0 { msg = eb.errorMessage }
                if len(msg) > 0 {
                    if len(eb.code) > 0 {
                        storage_last_error = fmt.tprintf("turso %v (%s): %s; sql=%s", status, eb.code, msg, storage_last_sql)
                        log.warn(storage_last_error)
                        return resp, false
                    }
                }
            }
        }
        // { error: { message, code } }
        if len(msg) == 0 {
            ec: Turso_ErrC
            if json.unmarshal_string(body_str, &ec) == nil && len(ec.error.message) > 0 {
                if len(ec.error.code) > 0 {
                    storage_last_error = fmt.tprintf("turso %v (%s): %s; sql=%s", status, ec.error.code, ec.error.message, storage_last_sql)
                } else {
                    storage_last_error = fmt.tprintf("turso %v: %s; sql=%s", status, ec.error.message, storage_last_sql)
                }
                log.warn(storage_last_error)
                return resp, false
            }
        }
        if len(msg) == 0 { msg = preview }
        storage_last_error = fmt.tprintf("turso %v: %s; sql=%s", status, msg, storage_last_sql)
        log.warn(storage_last_error)
        return resp, false
    }

    // Parse pipeline response and extract first result (support multiple shapes)
    // 1) Direct: { results: [ { columns, rows, ... } ] }
    d: Turso_Pipeline_Resp_Direct
    if json.unmarshal_string(body_str, &d) == nil && len(d.results) > 0 {
        r := d.results[0]
        if len(r.rows) > 0 || len(r.columns) > 0 {
            storage_last_rows = len(r.rows)
            return Turso_Result{ columns = r.columns, rows = r.rows, lastInsertRowid = r.lastInsertRowid, rowsAffected = r.rowsAffected }, true
        }
    }
    // 2) Wrapped: { results: [ { result: { ... } } ] }
    w1: Turso_Pipeline_Resp_Wrapped1
    if json.unmarshal_string(body_str, &w1) == nil && len(w1.results) > 0 {
        r := w1.results[0].result
        if len(r.rows) > 0 || len(r.columns) > 0 {
            storage_last_rows = len(r.rows)
            return Turso_Result{ columns = r.columns, rows = r.rows, lastInsertRowid = r.lastInsertRowid, rowsAffected = r.rowsAffected }, true
        }
    }
    // 3) Wrapped as response: { results: [ { response: { ... } } ] }
    w2: Turso_Pipeline_Resp_Wrapped2
    if json.unmarshal_string(body_str, &w2) == nil && len(w2.results) > 0 {
        r := w2.results[0].response
        if len(r.rows) > 0 || len(r.columns) > 0 {
            storage_last_rows = len(r.rows)
            return Turso_Result{ columns = r.columns, rows = r.rows, lastInsertRowid = r.lastInsertRowid, rowsAffected = r.rowsAffected }, true
        }
    }
    // 4) Wrapped with response { type: "ok", result: { ... } }
    w3: Turso_Pipeline_Resp_Wrapped3
    if json.unmarshal_string(body_str, &w3) == nil && len(w3.results) > 0 {
        ro := w3.results[0].response
        if ro.type == "ok" {
            r := ro.result
            if len(r.rows) > 0 || len(r.columns) > 0 {
                storage_last_rows = len(r.rows)
                return Turso_Result{ columns = r.columns, rows = r.rows, lastInsertRowid = r.lastInsertRowid, rowsAffected = r.rowsAffected }, true
            }
        }
    }
    // 5) Wrapped with typed cells: { results: [ { response: { type:"execute", result:{ cols:[{name,decltype}], rows:[[ {type,value}, ... ]] } } ] }
    wc: Turso_Pipeline_Resp_Wrapped_Cells
    if json.unmarshal_string(body_str, &wc) == nil && len(wc.results) > 0 {
        ro := wc.results[0].response
        rr := ro.result
        // Convert typed cells -> [][]string (take .value)
        out_rows, _ := make([dynamic][]string, 0, len(rr.rows))
        for rrow in rr.rows {
            vals, _ := make([dynamic]string, 0, len(rrow))
            for cell in rrow {
                _, _ = append(&vals, cell.value)
            }
            _, _ = append(&out_rows, vals[:])
        }
        // Extract column names
        cols, _ := make([dynamic]string, 0, len(rr.cols))
        for c in rr.cols { _, _ = append(&cols, c.name) }
        storage_last_rows = len(out_rows)
        return Turso_Result{ columns = cols[:], rows = out_rows[:], lastInsertRowid = 0, rowsAffected = 0 }, true
    }
    storage_last_error = "turso ok but unrecognized results shape"
    log.warn(storage_last_error)
    return resp, false
}

// Create messages table if needed
turso_ensure_schema :: proc(allocator := context.temp_allocator) -> bool {
    // messages
    if _, ok := turso_execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, user TEXT NOT NULL, text TEXT NOT NULL, at INTEGER NOT NULL)", allocator); !ok {
        if len(storage_last_error) == 0 { storage_last_error = "schema ensure failed (messages)" }
        return false
    }
    // users
    if _, ok := turso_execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE)", allocator); !ok {
        if len(storage_last_error) == 0 { storage_last_error = "schema ensure failed (users)" }
        return false
    }
    // webauthn credentials
    if _, ok := turso_execute("CREATE TABLE IF NOT EXISTS webauthn_credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, public_key TEXT NOT NULL, alg INTEGER NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)", allocator); !ok {
        if len(storage_last_error) == 0 { storage_last_error = "schema ensure failed (webauthn_credentials)" }
        return false
    }
    // webauthn challenges
    if _, ok := turso_execute("CREATE TABLE IF NOT EXISTS webauthn_challenges (challenge TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)", allocator); !ok {
        if len(storage_last_error) == 0 { storage_last_error = "schema ensure failed (webauthn_challenges)" }
        return false
    }
    return true
}

// Public API: configure Turso at runtime
set_turso_config :: proc(url: string, token: string) -> bool {
    // Normalize database URL: accept libsql:// or https:// and strip any path/query to keep only the origin.
    normalize_base :: proc(in_url: string, allocator := context.temp_allocator) -> string {
        s := strings.trim_space(in_url)
        // Drop scheme if present
        scheme_i := strings.index(s, "://")
        if scheme_i >= 0 { s = s[scheme_i+3:] }
        // Keep only host[:port]
        cut := len(s)
        for ch, i in transmute([]byte)s {
            if ch == '/' || ch == '?' { cut = i; break }
        }
        hostport := s[:cut]
        return strings.concatenate([]string{"https://", hostport}, allocator)
    }

    base := normalize_base(url, context.temp_allocator)
    turso_url = strings.clone(base, context.allocator)
    turso_token = strings.clone(token, context.allocator)
    turso_enabled = len(turso_url) > 0 && len(turso_token) > 0
    // Defer schema creation until first DB operation to prevent slow startup.
    turso_schema_attempted = false
    turso_schema_ready = false
    storage_last_error = ""
    storage_last_status = 0
    storage_last_sql = ""
    storage_last_rows = 0
    storage_last_body_preview = ""
    return turso_enabled
}

// Turso-backed add/get
turso_add_message :: proc(m: Message, allocator := context.temp_allocator) -> bool {
    // Use args as strings to avoid type issues; SQLite coerces where applicable.
    // Embed values directly (escaped): INSERT INTO messages(user, text, at) VALUES ('user','text', at)
    u := sql_quote(m.user, allocator)
    t := sql_quote(m.text, allocator)
    sql := fmt.tprintf("INSERT INTO messages(user, text, at) VALUES (%s, %s, %s)", u, t, m.at)
    _, ok := turso_execute(sql, allocator)
    return ok
}

turso_get_messages :: proc(limit: int = max_messages, allocator := context.temp_allocator) -> ([]Message, bool) {
    // Cast numeric columns to text so JSON rows decode as strings consistently.
    q_base := "SELECT CAST(id AS TEXT), user, text, CAST(at AS TEXT) FROM messages ORDER BY id ASC LIMIT ?1"
    sbuf: [32]u8
    lstr := strconv.itoa(sbuf[:], limit)
    // Embed limit directly (integer)
    q := fmt.tprintf("SELECT CAST(id AS TEXT), user, text, CAST(at AS TEXT) FROM messages ORDER BY id ASC LIMIT %s", lstr)
    _ = q_base // silence unused
    resp, ok := turso_execute(q, allocator)
    if !ok {
        return nil, false
    }

    rows := resp.rows
    out, _ := make([dynamic]Message, 0, len(rows))
    for r in rows {
        if len(r) < 4 { continue }
        // r = [id_text, user, text, at_text]
        _, _ = append(&out, Message{ user = r[1], text = r[2], at = r[3] })
    }
    return out[:], true
}

// -----------------------
// Unified storage facade
// -----------------------

storage_init :: proc() {
    // Prefer TURSO_* and fall back to LIBSQL_* env vars.
    url := ""
    tok := ""
    v := os.get_env("TURSO_DATABASE_URL")
    if len(v) > 0 { url = v } else {
        v2 := os.get_env("LIBSQL_URL")
        if len(v2) > 0 { url = v2 }
    }

    t := os.get_env("TURSO_AUTH_TOKEN")
    if len(t) > 0 { tok = t } else {
        t2 := os.get_env("LIBSQL_AUTH_TOKEN")
        if len(t2) > 0 { tok = t2 }
    }

    if len(url) > 0 && len(tok) > 0 {
        if set_turso_config(url, tok) {
            log.info("storage: turso enabled via env vars")
            return
        }
        log.warn("storage: turso init failed; storage disabled")
    } else {
        log.warn("storage: turso env vars not set; storage disabled")
    }
}

add_message :: proc(m: Message) -> bool {
    if !turso_enabled { return false }
    if !turso_schema_attempted { turso_schema_attempted = true; turso_schema_ready = turso_ensure_schema() }
    return turso_add_message(m)
}

get_messages :: proc() -> (out: []Message, ok: bool) {
    if !turso_enabled { return nil, false }
    if !turso_schema_attempted { turso_schema_attempted = true; turso_schema_ready = turso_ensure_schema() }
    return turso_get_messages(max_messages)
}

storage_status :: proc() -> struct {
    enabled: bool,
    schema_attempted: bool,
    schema_ready: bool,
    base_url: string,
    last_error: string,
    last_status: int,
    last_sql: string,
    last_rows: int,
    last_body_preview: string,
} {
    return struct{
        enabled: bool,
        schema_attempted: bool,
        schema_ready: bool,
        base_url: string,
        last_error: string,
        last_status: int,
        last_sql: string,
        last_rows: int,
        last_body_preview: string,
    }{ turso_enabled, turso_schema_attempted, turso_schema_ready, turso_url, storage_last_error, storage_last_status, storage_last_sql, storage_last_rows, storage_last_body_preview }
}

// -----------------------
// Passkey storage helpers
// -----------------------

// Ensure schema lazily like messages facade
ensure_schema_if_needed :: proc() {
    if !turso_schema_attempted { turso_schema_attempted = true; turso_schema_ready = turso_ensure_schema() }
}

get_or_create_user :: proc(username: string, allocator := context.temp_allocator) -> (u: User, ok: bool) {
    if !turso_enabled { return User{}, false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return User{}, false }
    uname := sql_quote(username, allocator)
    // Try fetch existing
    q := fmt.tprintf("SELECT id, username FROM users WHERE username = %s LIMIT 1", uname)
    res, rok := turso_execute(q, allocator)
    if rok && len(res.rows) > 0 {
        r := res.rows[0]
        if len(r) >= 2 { return User{ id = r[0], username = r[1] }, true }
    }
    // Create new
    id, okr := rand_b64url(16, allocator)
    if !okr { return User{}, false }
    idq := sql_quote(id, allocator)
    ins := fmt.tprintf("INSERT INTO users(id, username) VALUES (%s, %s)", idq, uname)
    if _, iok := turso_execute(ins, allocator); !iok { return User{}, false }
    return User{ id = id, username = username }, true
}

list_credentials_for_user :: proc(user_id: string, allocator := context.temp_allocator) -> ([]Credential, bool) {
    if !turso_enabled { return nil, false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return nil, false }
    uid := sql_quote(user_id, allocator)
    q := fmt.tprintf("SELECT id, user_id, public_key, alg, sign_count, IFNULL(transports,''), created_at FROM webauthn_credentials WHERE user_id = %s", uid)
    res, ok := turso_execute(q, allocator)
    if !ok { return nil, false }
    out, _ := make([dynamic]Credential, 0, len(res.rows))
    for r in res.rows {
        if len(r) < 7 { continue }
        algv, _ := strconv.parse_int(r[3], 10)
        scv, _ := strconv.parse_int(r[4], 10)
        cav, _ := strconv.parse_int(r[6], 10)
        _, _ = append(&out, Credential{ id = r[0], user_id = r[1], public_key = r[2], alg = algv, sign_count = scv, transports = r[5], created_at = cav })
    }
    return out[:], true
}

insert_challenge :: proc(user_id: string, kind: string, challenge: string, ttl_seconds: int = 300, allocator := context.temp_allocator) -> bool {
    if !turso_enabled { return false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return false }
    uid := sql_quote(user_id, allocator)
    ch := sql_quote(challenge, allocator)
    k := sql_quote(kind, allocator)
    // created_at = unix seconds, expires_at = +ttl
    // Use '%%s' inside strftime format to avoid fmt interpreting '%s'
    ins := fmt.tprintf("INSERT OR REPLACE INTO webauthn_challenges(challenge, user_id, type, created_at, expires_at) VALUES (%s, %s, %s, CAST(strftime('%%s','now') AS INTEGER), CAST(strftime('%%s','now') AS INTEGER)+%d)", ch, uid, k, ttl_seconds)
    _, ok := turso_execute(ins, allocator)
    if !ok {
        log.warnf("turso insert_challenge failed: status=%v err=%s sql=%s", storage_last_status, storage_last_error, storage_last_sql)
    } else {
        log.infof("turso insert_challenge ok: status=%v sql=%s", storage_last_status, storage_last_sql)
    }
    return ok
}

get_challenge :: proc(challenge: string, kind: string, allocator := context.temp_allocator) -> (user_id: string, created_at: int, expires_at: int, ok: bool) {
    if !turso_enabled { return "", 0, 0, false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return "", 0, 0, false }
    ch := sql_quote(challenge, allocator)
    k := sql_quote(kind, allocator)
    q := fmt.tprintf("SELECT user_id, created_at, expires_at FROM webauthn_challenges WHERE challenge = %s AND type = %s LIMIT 1", ch, k)
    res, okq := turso_execute(q, allocator)
    if !okq || len(res.rows) == 0 { return "", 0, 0, false }
    r := res.rows[0]
    if len(r) < 3 { return "", 0, 0, false }
    ca, _ := strconv.parse_int(r[1], 10)
    ea, _ := strconv.parse_int(r[2], 10)
    return r[0], ca, ea, true
}

delete_challenge :: proc(challenge: string, allocator := context.temp_allocator) -> bool {
    if !turso_enabled { return false }
    ch := sql_quote(challenge, allocator)
    q := fmt.tprintf("DELETE FROM webauthn_challenges WHERE challenge = %s", ch)
    _, ok := turso_execute(q, allocator)
    return ok
}

insert_credential :: proc(cred: Credential, allocator := context.temp_allocator) -> bool {
    if !turso_enabled { return false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return false }
    id := sql_quote(cred.id, allocator)
    uid := sql_quote(cred.user_id, allocator)
    pk := sql_quote(cred.public_key, allocator)
    tr := sql_quote(cred.transports, allocator)
    // Escape '%s' in strftime for fmt
    sql := fmt.tprintf("INSERT OR REPLACE INTO webauthn_credentials(id, user_id, public_key, alg, sign_count, transports, created_at) VALUES (%s,%s,%s,%d,%d,%s,CAST(strftime('%%s','now') AS INTEGER))", id, uid, pk, cred.alg, cred.sign_count, tr)
    _, ok := turso_execute(sql, allocator)
    return ok
}

get_credential_by_id :: proc(id_b64: string, allocator := context.temp_allocator) -> (cred: Credential, ok: bool) {
    if !turso_enabled { return Credential{}, false }
    ensure_schema_if_needed()
    if !turso_schema_ready { return Credential{}, false }
    id := sql_quote(id_b64, allocator)
    q := fmt.tprintf("SELECT id, user_id, public_key, alg, sign_count, IFNULL(transports,''), created_at FROM webauthn_credentials WHERE id = %s LIMIT 1", id)
    res, rok := turso_execute(q, allocator)
    if !rok || len(res.rows) == 0 { return Credential{}, false }
    r := res.rows[0]
    if len(r) < 7 { return Credential{}, false }
    algv, _ := strconv.parse_int(r[3], 10)
    scv, _ := strconv.parse_int(r[4], 10)
    cav, _ := strconv.parse_int(r[6], 10)
    return Credential{ id = r[0], user_id = r[1], public_key = r[2], alg = algv, sign_count = scv, transports = r[5], created_at = cav }, true
}

update_credential_sign_count :: proc(id_b64: string, new_count: int, allocator := context.temp_allocator) -> bool {
    if !turso_enabled { return false }
    id := sql_quote(id_b64, allocator)
    sql := fmt.tprintf("UPDATE webauthn_credentials SET sign_count = %d WHERE id = %s", new_count, id)
    _, ok := turso_execute(sql, allocator)
    return ok
}
