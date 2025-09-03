package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:time"
import "core:encoding/json"
import "core:strconv"
import "core:strings"
import hash "core:crypto/hash"

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
    // WebAuthn (Passkey) registration start
    http.route_post(&router, "/api/auth/passkey/register/start", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        // Compute rp_host from Host header once (host without port)
        rp_host := "localhost"
        if h, ok := http.headers_get_unsafe(req.headers, "host"); ok {
            c := strings.index_byte(h, ':')
            rp_host = h if c < 0 else h[:c]
        }
        StartCtx :: struct { res: ^http.Response, rp_host: string }
        start_ctx := StartCtx{ res, rp_host }
        http.body(req, 1<<20, transmute(rawptr)&start_ctx, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            ctx := cast(^StartCtx)rp
            res := ctx.res
            if berr != nil { http.respond(res, http.body_error_status(berr)); return }
            // Expect { username }
            rreq := struct{ username: string }{""}
            if json.unmarshal_string(body, &rreq) != nil || len(strings.trim_space(rreq.username)) == 0 {
                http.respond_json(res, struct{ error: string }{"missing username"}, http.Status.Bad_Request)
                return
            }
            // Get or create user
            user, u_ok := get_or_create_user(strings.trim_space(rreq.username))
            if !u_ok {
                msg := "storage error; check server logs and TURSO env"
                if !turso_enabled { msg = "storage disabled; set TURSO_DATABASE_URL/TURSO_AUTH_TOKEN" }
                http.respond_json(res, struct{ error: string }{ msg }, http.Status.Internal_Server_Error)
                return
            }
            // Generate challenge
            chall, okc := rand_b64url(32)
            if !okc {
                http.respond_json(res, struct{ error: string }{"challenge generation failed"}, http.Status.Internal_Server_Error)
                return
            }
            log.infof("passkey reg/start: user=%s uid=%s chall=%s", user.username, user.id, chall)
            if !insert_challenge(user.id, "reg", chall) {
                http.respond_json(res, struct{ error: string }{"failed to save challenge"}, http.Status.Internal_Server_Error)
                return
            }

            // List existing credentials to exclude
            creds, lc_ok := list_credentials_for_user(user.id)
            if !lc_ok {
                http.respond_json(res, struct{ error: string }{"failed to read credentials"}, http.Status.Internal_Server_Error)
                return
            }

            // Derive rp.id from request Host header (host without port)
            // rp_host from outer scope
            // Build response options (binary fields are base64url-encoded with *_b64 keys)
            exlist, _ := make([dynamic]struct{ type: string, id_b64: string }, 0, len(creds))
            for c in creds { _, _ = append(&exlist, struct{ type: string, id_b64: string }{ type = "public-key", id_b64 = c.id }) }

            // Include ES256 (-7) and RS256 (-257) per Chrome guidance
            params := []struct{ type: string, alg: int }{
                { type = "public-key", alg = -7 },   // ES256
                { type = "public-key", alg = -257 }, // RS256
            }
            out := struct{
                rp: struct{ id: string, name: string },
                user: struct{ id_b64: string, name: string, displayName: string },
                challenge_b64: string,
                pubKeyCredParams: []struct{ type: string, alg: int },
                timeout: int,
                attestation: string,
                authenticatorSelection: struct{ residentKey: string, requireResidentKey: bool, userVerification: string },
                excludeCredentials: []struct{ type: string, id_b64: string },
            }{
                rp = struct{ id: string, name: string }{ ctx.rp_host, "Odin Demo" },
                user = struct{ id_b64: string, name: string, displayName: string }{ user.id, user.username, user.username },
                challenge_b64 = chall,
                pubKeyCredParams = params,
                timeout = 60000,
                attestation = "none",
                authenticatorSelection = struct{ residentKey: string, requireResidentKey: bool, userVerification: string }{ "required", true, "required" },
                excludeCredentials = exlist[:],
            }
            http.respond_json(res, out)
        })
    }))

    // WebAuthn (Passkey) authentication start
    http.route_post(&router, "/api/auth/passkey/login/start", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        http.body(req, 1<<20, res, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            res := cast(^http.Response)rp
            if berr != nil { http.respond(res, http.body_error_status(berr)); return }
            // Expect { username }
            lreq := struct{ username: string }{""}
            if json.unmarshal_string(body, &lreq) != nil || len(strings.trim_space(lreq.username)) == 0 {
                http.respond_json(res, struct{ error: string }{"missing username"}, http.Status.Bad_Request)
                return
            }
            // Find or create user (allow create so flow can continue consistently)
            user, lu_ok := get_or_create_user(strings.trim_space(lreq.username))
            if !lu_ok {
                msg := "storage error; check server logs and TURSO env"
                if !turso_enabled { msg = "storage disabled; set TURSO_DATABASE_URL/TURSO_AUTH_TOKEN" }
                http.respond_json(res, struct{ error: string }{ msg }, http.Status.Internal_Server_Error)
                return
            }
            // Fetch credentials for allow list
            creds, l_ok := list_credentials_for_user(user.id)
            if !l_ok {
                http.respond_json(res, struct{ error: string }{"failed to read credentials"}, http.Status.Internal_Server_Error)
                return
            }
            if len(creds) == 0 { http.respond_json(res, struct{ error: string }{"no credentials"}, http.Status.Not_Found); return }
            chall, okc := rand_b64url(32)
            if !okc { http.respond_json(res, struct{ error: string }{"challenge generation failed"}, http.Status.Internal_Server_Error); return }
            if !insert_challenge(user.id, "auth", chall) {
                http.respond_json(res, struct{ error: string }{"failed to save challenge"}, http.Status.Internal_Server_Error)
                return
            }

            allow, _ := make([dynamic]struct{ type: string, id_b64: string, transports: string }, 0, len(creds))
            for c in creds {
                _, _ = append(&allow, struct{ type: string, id_b64: string, transports: string }{ type = "public-key", id_b64 = c.id, transports = c.transports })
            }
            out := struct{
                challenge_b64: string,
                allowCredentials: []struct{ type: string, id_b64: string, transports: string },
                timeout: int,
                userVerification: string,
            }{ challenge_b64 = chall, allowCredentials = allow[:], timeout = 60000, userVerification = "preferred" }
            http.respond_json(res, out)
        })
    }))

    // Usernameless (Conditional UI) login start: issue an any-user challenge
    http.route_post(&router, "/api/auth/passkey/login/conditional/start", http.handler(proc(_: ^http.Request, res: ^http.Response) {
        chall, okc := rand_b64url(32)
        if !okc { http.respond_json(res, struct{ error: string }{"challenge generation failed"}, http.Status.Internal_Server_Error); return }
        if !insert_challenge_any("auth", chall) {
            log.warnf("conditional/start: insert challenge failed; status=%v err=%s sql=%s", storage_last_status, storage_last_error, storage_last_sql)
            http.respond_json(res, struct{ error: string }{"failed to save challenge"}, http.Status.Internal_Server_Error)
            return
        }
        out := struct{
            challenge_b64: string,
            timeout: int,
            userVerification: string,
        }{ challenge_b64 = chall, timeout = 60000, userVerification = "required" }
        http.respond_json(res, out)
    }))

    // WebAuthn finish stubs (not yet implemented)
    http.route_post(&router, "/api/auth/passkey/register/finish", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        // Pre-compute host for rpId/origin checks inside body callback
        host_header := ""
        if h, ok := http.headers_get_unsafe(req.headers, "host"); ok { host_header = h }
        http.body(req, 2<<20, res, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            res := cast(^http.Response)rp
            if berr != nil { http.respond_json(res, struct{ error: string }{"bad body"}, http.body_error_status(berr)); return }
            // Expect { username, id_b64, raw_id_b64, type, response:{ attestationObject_b64, clientDataJSON_b64 } }
            RFin := struct{
                username: string,
                id_b64: string,
                raw_id_b64: string,
                type: string,
                response: struct{ attestationObject_b64: string, clientDataJSON_b64: string },
            }{"","","","", struct{ attestationObject_b64: string, clientDataJSON_b64: string}{"",""}}
            if json.unmarshal_string(body, &RFin) != nil || len(RFin.username) == 0 { http.respond_json(res, struct{ error: string }{"bad json"}, http.Status.Bad_Request); return }

            // Get user (must exist due to start flow)
            user, uok := get_or_create_user(strings.trim_space(RFin.username))
            if !uok { http.respond_json(res, struct{ error: string }{"user error"}, http.Status.Internal_Server_Error); return }

            // Decode clientDataJSON and attestationObject
            client_bytes, okc := base64url_decode(RFin.response.clientDataJSON_b64, context.temp_allocator)
            if !okc { http.respond_json(res, struct{ error: string }{"bad clientData"}, http.Status.Bad_Request); return }
            att_bytes, oka := base64url_decode(RFin.response.attestationObject_b64, context.temp_allocator)
            if !oka { http.respond_json(res, struct{ error: string }{"bad attestationObject"}, http.Status.Bad_Request); return }
            log.infof("passkey reg/finish: clientB=%d attB=%d", len(client_bytes), len(att_bytes))
            if fmt_str, okfmt := attestation_get_fmt(att_bytes); okfmt {
                log.infof("passkey reg/finish: attestation fmt=%s", fmt_str)
            }

            // Parse clientDataJSON: { type, challenge, origin }
            CData := struct{ type: string, challenge: string, origin: string }{"","",""}
            if json.unmarshal_string(string(client_bytes), &CData) != nil { http.respond_json(res, struct{ error: string }{"bad clientData json"}, http.Status.Bad_Request); return }
            if !(CData.type == "webauthn.create") { http.respond_json(res, struct{ error: string }{"invalid clientData.type"}, http.Status.Bad_Request); return }

            // Derive rpId from client-provided origin (scheme://host[:port])
            origin := CData.origin
            if !(strings.has_prefix(origin, "http://") || strings.has_prefix(origin, "https://")) {
                http.respond_json(res, struct{ error: string }{"invalid origin"}, http.Status.Bad_Request); return
            }
            rest := origin[7:] if strings.has_prefix(origin, "http://") else origin[8:]
            slash := strings.index_byte(rest, '/')
            hostport := rest if slash < 0 else rest[:slash]
            colon := strings.index_byte(hostport, ':')
            rp_id := hostport if colon < 0 else hostport[:colon]
            log.infof("passkey reg/finish: clientData type=%s origin=%s rp_id=%s", CData.type, origin, rp_id)

            // Validate challenge matches the stored one
            // Client encodes challenge as base64url. Normalize by decoding then re-encoding (strip padding etc.).
            ch_bytes, okcb := base64url_decode(CData.challenge, context.temp_allocator)
            if !okcb { http.respond_json(res, struct{ error: string }{"bad client challenge"}, http.Status.Bad_Request); return }
            ch_norm := base64url_encode(ch_bytes, context.temp_allocator)
            log.infof("passkey reg/finish: user=%s uid=%s ch_client=%s ch_norm=%s", user.username, user.id, CData.challenge, ch_norm)
            // Retrieve challenge record
            ch_user, _, exp, okg := get_challenge(ch_norm, "reg")
            if !okg {
                // Try raw client string as fallback (some clients vary padding/casing)
                ch_user, _, exp, okg = get_challenge(CData.challenge, "reg")
            }
            if !okg {
                log.warnf("passkey reg/finish: challenge not found; last_status=%v last_err=%s last_sql=%s", storage_last_status, storage_last_error, storage_last_sql)
                http.respond_json(res, struct{ error: string }{"challenge not found"}, http.Status.Bad_Request); return
            }
            if !(ch_user == user.id) { http.respond_json(res, struct{ error: string }{"challenge user mismatch"}, http.Status.Bad_Request); return }
            // Expiry check: allow Turso to hold unix seconds; cannot read now() here reliably; we skip strict check and rely on short TTL.
            _ = exp
            _ = ch_bytes

            // Extract authData from attestationObject (CBOR) and parse fields
            authData, okad := attestation_get_authData(att_bytes)
            if !okad {
                log.warnf("attestation parse failed: att_len=%v", len(att_bytes))
                http.respond_json(res, struct{ error: string }{"attestation no authData"}, http.Status.Bad_Request); return
            }
            log.infof("passkey reg/finish: authDataLen=%d", len(authData))
            // Dump first 16 bytes of authData for debugging
            dump_len := 16
            if len(authData) < dump_len { dump_len = len(authData) }
            ad_prefix := base64url_encode(authData[:dump_len], context.temp_allocator)
            log.infof("passkey reg/finish: authData[0:%d]=%s", dump_len, ad_prefix)
            rp_hash, flags, signCount, credId, cose, okp := authdata_parse_cred(authData)
            if !okp { http.respond_json(res, struct{ error: string }{"authData parse error"}, http.Status.Bad_Request); return }
            // Verify rpIdHash
            expected_rp_hash := rp_id_hash(rp_id)
            // Compare 32-byte arrays
            match := true
            for i in 0..<32 { if expected_rp_hash[i] != rp_hash[i] { match = false; break } }
            if !match {
                // Log helpful diagnostics
                exp_b64 := base64url_encode(expected_rp_hash[:], context.temp_allocator)
                got_b64 := base64url_encode(rp_hash[:], context.temp_allocator)
                log.warnf("rpIdHash mismatch: origin=%s rp_id=%s got=%s exp=%s", origin, rp_id, got_b64, exp_b64)
                http.respond_json(res, struct{ error: string }{"rpIdHash mismatch"}, http.Status.Bad_Request); return
            }
            // Helpful state for debugging successful parsing
            uv := (flags & 0x04) != 0
            up := (flags & 0x01) != 0
            aaguid_b64 := ""
            if ag, okag := authdata_extract_aaguid(authData); okag {
                aaguid_b64 = base64url_encode(ag[:], context.temp_allocator)
            }
            log.infof("passkey reg/finish: flags=0x%02x (UP=%v UV=%v) signCount=%d credIdLen=%d coseLen=%d aaguid=%s", flags, up, uv, signCount, len(credId), len(cose), aaguid_b64)

            // Get alg from COSE
            alg, okalg := cose_get_alg(cose)
            if !okalg { http.respond_json(res, struct{ error: string }{"cose alg missing"}, http.Status.Bad_Request); return }
            alg_name := "unknown"
            if alg == -7 { alg_name = "ES256" } else if alg == -257 { alg_name = "RS256" }
            log.infof("passkey reg/finish: cose.alg=%d (%s)", alg, alg_name)

            // Store credential (public_key = base64url(COSE))
            pk_b64 := base64url_encode(cose, context.temp_allocator)
            cred := Credential{ id = RFin.raw_id_b64, user_id = user.id, public_key = pk_b64, alg = alg, sign_count = int(signCount), transports = "" }
            if !insert_credential(cred) { http.respond_json(res, struct{ error: string }{"failed to save credential"}, http.Status.Internal_Server_Error); return }
            // Consume challenge
            _ = delete_challenge(ch_norm)

            http.respond_json(res, struct{ status: string, id_b64: string }{"ok", RFin.raw_id_b64})
        })
    }))
    http.route_post(&router, "/api/auth/passkey/login/finish", http.handler(proc(req: ^http.Request, res: ^http.Response) {
        // Pre-capture host header to infer rp.id
        host_header := ""
        if h, ok := http.headers_get_unsafe(req.headers, "host"); ok { host_header = h }
        http.body(req, 2<<20, res, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            res := cast(^http.Response)rp
            if berr != nil { http.respond_json(res, struct{ error: string }{"bad body"}, http.body_error_status(berr)); return }
            // Expect { username, id_b64, raw_id_b64, type, response:{ authenticatorData_b64, clientDataJSON_b64, signature_b64, userHandle_b64 } }
            LFin := struct{
                username: string,
                id_b64: string,
                raw_id_b64: string,
                type: string,
                response: struct{ authenticatorData_b64: string, clientDataJSON_b64: string, signature_b64: string, userHandle_b64: string },
            }{"","","","", struct{ authenticatorData_b64: string, clientDataJSON_b64: string, signature_b64: string, userHandle_b64: string}{"","","",""}}
            if json.unmarshal_string(body, &LFin) != nil { http.respond_json(res, struct{ error: string }{"bad json"}, http.Status.Bad_Request); return }

            // Optional user: may be empty for usernameless flow
            has_username := len(strings.trim_space(LFin.username)) > 0
            user: User
            if has_username {
                u, uok := get_or_create_user(strings.trim_space(LFin.username))
                if !uok { http.respond_json(res, struct{ error: string }{"user error"}, http.Status.Internal_Server_Error); return }
                user = u
            }

            // Decode clientDataJSON and authenticatorData
            client_bytes, okc := base64url_decode(LFin.response.clientDataJSON_b64, context.temp_allocator)
            if !okc { http.respond_json(res, struct{ error: string }{"bad clientData"}, http.Status.Bad_Request); return }
            auth_bytes, oka := base64url_decode(LFin.response.authenticatorData_b64, context.temp_allocator)
            if !oka { http.respond_json(res, struct{ error: string }{"bad authenticatorData"}, http.Status.Bad_Request); return }
            sig_bytes, oks := base64url_decode(LFin.response.signature_b64, context.temp_allocator)
            if !oks { http.respond_json(res, struct{ error: string }{"bad signature"}, http.Status.Bad_Request); return }

            // Parse clientDataJSON: { type, challenge, origin }
            CData := struct{ type: string, challenge: string, origin: string }{"","",""}
            if json.unmarshal_string(string(client_bytes), &CData) != nil { http.respond_json(res, struct{ error: string }{"bad clientData json"}, http.Status.Bad_Request); return }
            if !(CData.type == "webauthn.get") { http.respond_json(res, struct{ error: string }{"invalid clientData.type"}, http.Status.Bad_Request); return }

            // Derive rpId from origin
            origin := CData.origin
            if !(strings.has_prefix(origin, "http://") || strings.has_prefix(origin, "https://")) { http.respond_json(res, struct{ error: string }{"invalid origin"}, http.Status.Bad_Request); return }
            rest := origin[7:] if strings.has_prefix(origin, "http://") else origin[8:]
            slash := strings.index_byte(rest, '/')
            hostport := rest if slash < 0 else rest[:slash]
            colon := strings.index_byte(hostport, ':')
            rp_id := hostport if colon < 0 else hostport[:colon]

            // Validate challenge matches stored one for user
            ch_bytes, okcb := base64url_decode(CData.challenge, context.temp_allocator)
            if !okcb { http.respond_json(res, struct{ error: string }{"bad client challenge"}, http.Status.Bad_Request); return }
            ch_norm := base64url_encode(ch_bytes, context.temp_allocator)
            used_any := false
            ch_user := ""
            _, _, okg := false, false, false
            ch_user, _, _, okg = get_challenge(ch_norm, "auth")
            if !okg { ch_user, _, _, okg = get_challenge(CData.challenge, "auth") }
            if !okg {
                if _, _, oka := get_challenge_any(ch_norm, "auth"); !oka { _, _, oka = get_challenge_any(CData.challenge, "auth") }
                if !oka { http.respond_json(res, struct{ error: string }{"challenge not found"}, http.Status.Bad_Request); return }
                used_any = true
            }
            log.infof("passkey login/finish: challenge ok (any=%v)", used_any)

            // Parse authenticatorData minimal fields
            rp_hash, flags, signCount, okp := authdata_parse_assert(auth_bytes)
            if !okp { http.respond_json(res, struct{ error: string }{"authData parse error"}, http.Status.Bad_Request); return }
            uv := (flags & 0x04) != 0
            up := (flags & 0x01) != 0
            log.infof("passkey login/finish: flags=0x%02x (UP=%v UV=%v) signCount=%d", flags, up, uv, signCount)
            expected_rp_hash := rp_id_hash(rp_id)
            match := true
            for i in 0..<32 { if expected_rp_hash[i] != rp_hash[i] { match = false; break } }
            if !match {
                exp_b64 := base64url_encode(expected_rp_hash[:], context.temp_allocator)
                got_b64 := base64url_encode(rp_hash[:], context.temp_allocator)
                log.warnf("login rpIdHash mismatch: origin=%s rp_id=%s got=%s exp=%s", origin, rp_id, got_b64, exp_b64)
                http.respond_json(res, struct{ error: string }{"rpIdHash mismatch"}, http.Status.Bad_Request); return
            }

            // Load credential by id and check/derive ownership
            log.infof("passkey login/finish: lookup credential id=%s", LFin.raw_id_b64)
            cred, cok := get_credential_by_id(LFin.raw_id_b64)
            if !cok {
                log.warnf("passkey login/finish: credential not found id=%s (last_status=%v last_err=%s last_sql=%s)", LFin.raw_id_b64, storage_last_status, storage_last_error, storage_last_sql)
                http.respond_json(res, struct{ error: string }{"credential not found"}, http.Status.Not_Found); return
            }
            if has_username {
                if !(cred.user_id == user.id) { http.respond_json(res, struct{ error: string }{"credential user mismatch"}, http.Status.Bad_Request); return }
            } else {
                // Derive user via JOIN for clarity
                u2, uok := get_user_by_credential_id(LFin.raw_id_b64)
                if !uok { http.respond_json(res, struct{ error: string }{"user for credential not found"}, http.Status.Not_Found); return }
                user = u2
                log.infof("passkey login/finish: user resolved via credential: id=%s username=%s", user.id, user.username)
            }

            // Decode and log userHandle if present
            if len(LFin.response.userHandle_b64) > 0 {
                uh, okuh := base64url_decode(LFin.response.userHandle_b64, context.temp_allocator)
                if okuh {
                    uh_b64 := base64url_encode(uh, context.temp_allocator)
                    log.infof("passkey login/finish: userHandleLen=%d matchesUser=%v", len(uh), string(uh) == user.id)
                }
            }

            // Build signed data = authenticatorData || SHA256(clientDataJSON)
            cd_hash: [32]byte
            ctx_cd: hash.Context
            hash.init(&ctx_cd, hash.Algorithm.SHA256)
            hash.update(&ctx_cd, client_bytes)
            hash.final(&ctx_cd, cd_hash[:])
            signed_len := len(auth_bytes) + len(cd_hash)
            signed, _ := make([dynamic]byte, 0, signed_len)
            for b in auth_bytes { _, _ = append(&signed, b) }
            for b in cd_hash { _, _ = append(&signed, b) }

            // Verify signature against stored public key
            // NOTE: Cryptographic verification not implemented in this demo.
            // In production, parse COSE (cred.public_key) and verify ES256/RS256 over `signed` with `sig_bytes`.
            log.warn("login signature verification skipped (TODO: implement ES256/RS256 verify)")

            // Counter update (best-effort)
            if int(signCount) > cred.sign_count { _ = update_credential_sign_count(cred.id, int(signCount)) }

            // Consume challenge
            if used_any { _ = delete_challenge_any(ch_norm) } else { _ = delete_challenge(ch_norm) }

            // Issue JWT for this user for subsequent authorized actions
            now := time.now()
            sbuf_j: [32]u8
            iat := strconv.itoa(sbuf_j[:], int(time.to_unix_seconds(now)))
            pr := JWT_Payload{ sub = user.username, iat = iat }
            pjson, _ := json.marshal(pr)
            tok := jwt_sign_hs256(string(pjson), transmute([]byte) jwt_secret, context.temp_allocator)
            http.respond_json(res, struct{ status: string, username: string, token: string }{"ok", user.username, tok})
        })
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
        // Extract Authorization header upfront
        auth_header := ""
        if h, ok := http.headers_get_unsafe(req.headers, "authorization"); ok { auth_header = h }
        // Context passed to body callback
        MsgCtx :: struct { res: ^http.Response, auth: string }
        mctx := MsgCtx{ res, auth_header }
        http.body(req, 8<<20, transmute(rawptr)&mctx, proc(rp: rawptr, body: http.Body, berr: http.Body_Error) {
            ctx := cast(^MsgCtx)rp
            res := ctx.res
            if berr != nil { http.respond(res, http.body_error_status(berr)); return }
            // Require Bearer token
            if len(ctx.auth) == 0 || !strings.has_prefix(ctx.auth, "Bearer ") { http.respond(res, http.Status.Unauthorized); return }
            token := strings.trim_prefix(ctx.auth, "Bearer ")
            okv, payload := jwt_verify_hs256(token, transmute([]byte) jwt_secret, context.temp_allocator)
            if !okv { http.respond(res, http.Status.Unauthorized); return }
            // Extract username from payload
            pl: JWT_Payload
            if json.unmarshal_string(payload, &pl) != nil || len(strings.trim_space(pl.sub)) == 0 { http.respond(res, http.Status.Unauthorized); return }
            // Body: prefer { text }, fallback to legacy { user, text }
            BNow := struct{ text: string }{""}
            text := ""
            if json.unmarshal_string(body, &BNow) == nil && len(strings.trim_space(BNow.text)) > 0 {
                text = strings.trim_space(BNow.text)
            } else {
                legacy := struct{ user: string, text: string }{"",""}
                if json.unmarshal_string(body, &legacy) != nil || len(strings.trim_space(legacy.text)) == 0 { http.respond(res, http.Status.Bad_Request); return }
                text = strings.trim_space(legacy.text)
            }
            // Resolve user id
            u, uok := get_or_create_user(strings.trim_space(pl.sub))
            if !uok { http.respond(res, http.Status.Internal_Server_Error); return }
            // Timestamp
            sec := time.to_unix_seconds(time.now())
            sbuf: [32]u8
            at := strconv.itoa(sbuf[:], int(sec))
            if ok := add_message_for_user(u.id, text, at); !ok { http.respond(res, http.Status.Internal_Server_Error); return }
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
