package main

import "core:strings"
import "core:encoding/base64"
import crypto "core:crypto"
import hmac "core:crypto/hmac"
import hash "core:crypto/hash"

// base64url without padding
base64url_encode :: proc(data: []byte, allocator := context.allocator) -> string {
    enc, _ := base64.encode(data, base64.ENC_TABLE, allocator)
    // Replace +/ with -_
    b := transmute([]byte) enc
    for ch, i in b {
        switch ch {
        case '+': b[i] = '-'
        case '/': b[i] = '_'
        }
    }
    // Strip '=' padding
    i := len(b)-1
    for ; i >= 0; i -= 1 {
        if b[i] != '=' { break }
    }
    return string(b[:i+1])
}

base64url_decode :: proc(s: string, allocator := context.allocator) -> (out: []byte, ok: bool) {
    size := len(s)
    padding := 0
    for size % 4 != 0 {
        size += 1
        padding += 1
    }
    tmp := make([]byte, size, context.temp_allocator)
    // Copy input
    copy(tmp, transmute([]byte) s)
    // Translate URL alphabet to standard
    for ch, i in tmp {
        switch ch {
        case '-': tmp[i] = '+'
        case '_': tmp[i] = '/'
        }
    }
    // Pad with '=' at the end as needed
    for k in 0..<padding {
        tmp[len(tmp)-1-k] = '='
    }
    dec, err := base64.decode(string(tmp), base64.DEC_TABLE, allocator)
    if err != nil { return nil, false }
    return dec, true
}

// sign HS256: header and payload are JSON strings
jwt_sign_hs256 :: proc(payload_json: string, secret: []byte, allocator := context.allocator) -> string {
    header_json := "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
    header_b64 := base64url_encode(transmute([]byte) header_json, allocator)
    payload_b64 := base64url_encode(transmute([]byte) payload_json, allocator)
    signing_input := strings.concatenate([]string{header_b64, ".", payload_b64}, allocator)

    // HMAC-SHA256
    tag_buf: [32]byte // SHA-256 tag length
    hmac.sum(hash.Algorithm.SHA256, tag_buf[:], transmute([]byte) signing_input, secret)
    sig_b64 := base64url_encode(tag_buf[:], allocator)
    return strings.concatenate([]string{signing_input, ".", sig_b64}, allocator)
}

// verify HS256 token and return the decoded payload JSON
jwt_verify_hs256 :: proc(token: string, secret: []byte, allocator := context.allocator) -> (ok: bool, payload_json: string) {
    // Split into 3 parts
    first_dot := strings.index_byte(token, '.')
    if first_dot < 0 { return false, "" }
    second_dot := strings.index_byte(token[first_dot+1:], '.')
    if second_dot < 0 { return false, "" }
    second_dot += first_dot + 1

    header_b64 := token[:first_dot]
    payload_b64 := token[first_dot+1:second_dot]
    sig_b64 := token[second_dot+1:]

    signing_input := strings.concatenate([]string{header_b64, ".", payload_b64}, allocator)

    // Compute expected signature
    tag_buf: [32]byte
    hmac.sum(hash.Algorithm.SHA256, tag_buf[:], transmute([]byte) signing_input, secret)

    // Compare signatures in constant time
    sig_bytes, ok_d := base64url_decode(sig_b64, context.temp_allocator)
    if !ok_d { return false, "" }
    if crypto.compare_constant_time(sig_bytes, tag_buf[:]) != 1 { return false, "" }

    // Decode payload
    payload_bytes, ok_p := base64url_decode(payload_b64, allocator)
    if !ok_p { return false, "" }
    return true, string(payload_bytes)
}
