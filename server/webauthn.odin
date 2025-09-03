package main

import "core:strings"
import hash "core:crypto/hash"

// Minimal CBOR reader sufficient for WebAuthn parsing

CBOR_Reader :: struct { data: []byte, i: int }

cbor_peek :: proc(r: ^CBOR_Reader) -> (mt: u8, ai: u8, ok: bool) {
    if r.i >= len(r.data) { return 0, 0, false }
    b := r.data[r.i]
    return (b >> 5), (b & 0x1f), true
}

cbor_u64 :: proc(r: ^CBOR_Reader, ai: u8) -> (val: u64, ok: bool) {
    switch ai {
    case 0..=23:
        return u64(ai), true
    case 24:
        if r.i >= len(r.data) { return 0, false }
        v := r.data[r.i]
        r.i += 1
        return u64(v), true
    case 25:
        if r.i+2 > len(r.data) { return 0, false }
        v := (u16(r.data[r.i])<<8) | u16(r.data[r.i+1])
        r.i += 2
        return u64(v), true
    case 26:
        if r.i+4 > len(r.data) { return 0, false }
        v := (u32(r.data[r.i])<<24) | (u32(r.data[r.i+1])<<16) | (u32(r.data[r.i+2])<<8) | u32(r.data[r.i+3])
        r.i += 4
        return u64(v), true
    case 27:
        if r.i+8 > len(r.data) { return 0, false }
        v := (u64(r.data[r.i])<<56) | (u64(r.data[r.i+1])<<48) | (u64(r.data[r.i+2])<<40) |
             (u64(r.data[r.i+3])<<32) | (u64(r.data[r.i+4])<<24) | (u64(r.data[r.i+5])<<16) |
             (u64(r.data[r.i+6])<<8) | u64(r.data[r.i+7])
        r.i += 8
        return v, true
    case:
        return 0, false
    }
}

cbor_skip :: proc(r: ^CBOR_Reader) -> bool {
    if r.i >= len(r.data) { return false }
    mt, ai, _ := cbor_peek(r)
    r.i += 1
    // Major types: 0 uint,1 nint,2 bytes,3 text,4 array,5 map,6 tag,7 simple
    switch mt {
    case 0, 1: // ints
        _, ok := cbor_u64(r, ai)
        return ok
    case 2: // bytes
        if ai == 31 { // indefinite-length
            for {
                if r.i >= len(r.data) { return false }
                mtb := r.data[r.i] >> 5
                aib := r.data[r.i] & 0x1f
                if mtb == 7 && aib == 31 { r.i += 1; break }
                if mtb != 2 { return false }
                r.i += 1
                n, ok := cbor_u64(r, aib)
                if !ok || r.i+int(n) > len(r.data) { return false }
                r.i += int(n)
            }
            return true
        } else {
            n, ok := cbor_u64(r, ai)
            if !ok || r.i+int(n) > len(r.data) { return false }
            r.i += int(n)
            return true
        }
    case 3: // text
        if ai == 31 {
            for {
                if r.i >= len(r.data) { return false }
                mtb := r.data[r.i] >> 5
                aib := r.data[r.i] & 0x1f
                if mtb == 7 && aib == 31 { r.i += 1; break }
                if mtb != 3 { return false }
                r.i += 1
                n, ok := cbor_u64(r, aib)
                if !ok || r.i+int(n) > len(r.data) { return false }
                r.i += int(n)
            }
            return true
        } else {
            n, ok := cbor_u64(r, ai)
            if !ok || r.i+int(n) > len(r.data) { return false }
            r.i += int(n)
            return true
        }
    case 4: // array
        if ai == 31 {
            for {
                if r.i >= len(r.data) { return false }
                mtb := r.data[r.i] >> 5
                aib := r.data[r.i] & 0x1f
                if mtb == 7 && aib == 31 { r.i += 1; break }
                if !cbor_skip(r) { return false }
            }
            return true
        } else {
            n, ok := cbor_u64(r, ai)
            if !ok { return false }
            for _ in 0..<int(n) { if !cbor_skip(r) { return false } }
            return true
        }
    case 5: // map
        if ai == 31 {
            for {
                if r.i >= len(r.data) { return false }
                mtb := r.data[r.i] >> 5
                aib := r.data[r.i] & 0x1f
                if mtb == 7 && aib == 31 { r.i += 1; break }
                if !cbor_skip(r) { return false } // key
                if !cbor_skip(r) { return false } // value
            }
            return true
        } else {
            n, ok := cbor_u64(r, ai)
            if !ok { return false }
            for _ in 0..<int(n) {
                if !cbor_skip(r) { return false } // key
                if !cbor_skip(r) { return false } // value
            }
            return true
        }
    case 6: // tag
        // skip tag argument, then the tagged item
        if _, ok := cbor_u64(r, ai); !ok { return false }
        return cbor_skip(r)
    case 7:
        // simple/float: handle 1-byte forms only
        if ai < 24 { return true }
        if ai == 24 { r.i += 1; return r.i <= len(r.data) }
        if ai == 25 { r.i += 2; return r.i <= len(r.data) }
        if ai == 26 { r.i += 4; return r.i <= len(r.data) }
        if ai == 27 { r.i += 8; return r.i <= len(r.data) }
        return false
    case:
        return false
    }
}

cbor_read_bytes :: proc(r: ^CBOR_Reader) -> (out: []byte, ok: bool) {
    if r.i >= len(r.data) { return nil, false }
    mt := r.data[r.i] >> 5
    ai := r.data[r.i] & 0x1f
    if mt != 2 { return nil, false }
    r.i += 1
    if ai == 31 { // indefinite-length
        // Collect chunks
        buf, _ := make([dynamic]byte, 0, 64)
        for {
            if r.i >= len(r.data) { return nil, false }
            mtb := r.data[r.i] >> 5
            aib := r.data[r.i] & 0x1f
            if mtb == 7 && aib == 31 { r.i += 1; break }
            if mtb != 2 { return nil, false }
            r.i += 1
            n, ok := cbor_u64(r, aib)
            if !ok || r.i+int(n) > len(r.data) { return nil, false }
            chunk := r.data[r.i:r.i+int(n)]
            r.i += int(n)
            // append chunk
            for b in chunk { _, _ = append(&buf, b) }
        }
        return buf[:], true
    } else {
        n, nok := cbor_u64(r, ai)
        if !nok || r.i+int(n) > len(r.data) { return nil, false }
        out = r.data[r.i:r.i+int(n)]
        r.i += int(n)
        return out, true
    }
}

cbor_read_text :: proc(r: ^CBOR_Reader) -> (out: string, ok: bool) {
    if r.i >= len(r.data) { return "", false }
    mt := r.data[r.i] >> 5
    ai := r.data[r.i] & 0x1f
    if mt != 3 { return "", false }
    r.i += 1
    if ai == 31 {
        // Concatenate chunks
        bldr := strings.builder_make(0, 0, context.temp_allocator)
        for {
            if r.i >= len(r.data) { return "", false }
            mtb := r.data[r.i] >> 5
            aib := r.data[r.i] & 0x1f
            if mtb == 7 && aib == 31 { r.i += 1; break }
            if mtb != 3 { return "", false }
            r.i += 1
            n, ok := cbor_u64(r, aib)
            if !ok || r.i+int(n) > len(r.data) { return "", false }
            strings.write_string(&bldr, string(r.data[r.i:r.i+int(n)]))
            r.i += int(n)
        }
        return strings.to_string(bldr), true
    } else {
        n, nok := cbor_u64(r, ai)
        if !nok || r.i+int(n) > len(r.data) { return "", false }
        s := string(r.data[r.i:r.i+int(n)])
        r.i += int(n)
        return s, true
    }
}

// Extract authData from attestationObject (CBOR map with key "authData")
attestation_get_authData :: proc(cbor: []byte) -> (authData: []byte, ok: bool) {
    r := CBOR_Reader{ data = cbor }
    mt, ai, ok0 := cbor_peek(&r)
    if !ok0 || mt != 5 { return nil, false } // expect map
    r.i += 1
    if ai == 31 { // indefinite-length map
        for {
            // Check for break (0xff)
            if r.i < len(r.data) {
                mtb := r.data[r.i] >> 5
                aib := r.data[r.i] & 0x1f
                if mtb == 7 && aib == 31 { r.i += 1; break }
            } else { return nil, false }
            key, okk := cbor_read_text(&r)
            if !okk { return nil, false }
            if key == "authData" {
                v, okv := cbor_read_bytes(&r)
                if !okv { return nil, false }
                return v, true
            }
            if !cbor_skip(&r) { return nil, false }
        }
        return nil, false
    } else {
        n, nok := cbor_u64(&r, ai)
        if !nok { return nil, false }
        for _ in 0..<int(n) {
            key, okk := cbor_read_text(&r)
            if !okk { return nil, false }
            if key == "authData" {
                v, okv := cbor_read_bytes(&r)
                if !okv { return nil, false }
                return v, true
            }
            if !cbor_skip(&r) { return nil, false }
        }
        return nil, false
    }
}

// Extract fmt string from attestationObject (CBOR map with key "fmt")
attestation_get_fmt :: proc(cbor: []byte) -> (fmt: string, ok: bool) {
    r := CBOR_Reader{ data = cbor }
    mt, ai, ok0 := cbor_peek(&r)
    if !ok0 || mt != 5 { return "", false }
    r.i += 1
    if ai == 31 { // indefinite-length map
        for {
            if r.i >= len(r.data) { return "", false }
            mtb := r.data[r.i] >> 5
            aib := r.data[r.i] & 0x1f
            if mtb == 7 && aib == 31 { r.i += 1; break }
            key, okk := cbor_read_text(&r)
            if !okk { return "", false }
            if key == "fmt" {
                v, okv := cbor_read_text(&r)
                if !okv { return "", false }
                return v, true
            }
            if !cbor_skip(&r) { return "", false }
        }
        return "", false
    } else {
        n, nok := cbor_u64(&r, ai)
        if !nok { return "", false }
        for _ in 0..<int(n) {
            key, okk := cbor_read_text(&r)
            if !okk { return "", false }
            if key == "fmt" {
                v, okv := cbor_read_text(&r)
                if !okv { return "", false }
                return v, true
            }
            if !cbor_skip(&r) { return "", false }
        }
        return "", false
    }
}

// Parse authData to extract rpIdHash, flags, signCount, credentialId, and COSE public key
authdata_parse_cred :: proc(authData: []byte) -> (rpIdHash: [32]byte, flags: u8, signCount: u32, credId: []byte, cose: []byte, ok: bool) {
    if len(authData) < 37 { return rpIdHash, 0, 0, nil, nil, false }
    // rpIdHash (32), flags (1), signCount (4)
    // Copy explicitly to avoid any slice casting pitfalls
    for i in 0..<32 { rpIdHash[i] = authData[i] }
    flags = authData[32]
    sc_b := authData[33:37]
    signCount = (u32(sc_b[0])<<24) | (u32(sc_b[1])<<16) | (u32(sc_b[2])<<8) | u32(sc_b[3])
    // Attested Credential Data if AT flag set
    if (flags & 0x40) == 0 { return rpIdHash, flags, signCount, nil, nil, false }
    i := 37
    if i+16 > len(authData) { return rpIdHash, flags, signCount, nil, nil, false } // aaguid skip
    i += 16
    if i+2 > len(authData) { return rpIdHash, flags, signCount, nil, nil, false }
    cred_len := (int(authData[i])<<8) | int(authData[i+1])
    i += 2
    if i+cred_len > len(authData) { return rpIdHash, flags, signCount, nil, nil, false }
    cred := authData[i:i+cred_len]
    i += cred_len
    // COSE key (CBOR), parse until end of buffer
    cose_key := authData[i:]
    return rpIdHash, flags, signCount, cred, cose_key, true
}

// Extract alg (label 3) from COSE key (CBOR map)
cose_get_alg :: proc(cose: []byte) -> (alg: int, ok: bool) {
    r := CBOR_Reader{ data = cose }
    mt, _, ok0 := cbor_peek(&r)
    if !ok0 || mt != 5 { return 0, false }
    r.i += 1
    n, nok := cbor_u64(&r, r.data[r.i-1]&0x1f)
    if !nok { return 0, false }
    for _ in 0..<int(n) {
        // Keys are small ints in COSE
        mt_k, ai_k, okk := cbor_peek(&r)
        if !okk { return 0, false }
        if mt_k == 0 || mt_k == 1 { // uint or nint
            // read key int
            r.i += 1
            uk, _ := cbor_u64(&r, ai_k)
            k := int(uk)
            if mt_k == 1 { k = -1 - int(uk) }
            // read value
            mt_v, ai_v, okv := cbor_peek(&r)
            if !okv { return 0, false }
            if k == 3 {
                // value is int
                r.i += 1
                uv, _ := cbor_u64(&r, ai_v)
                v := int(uv)
                if mt_v == 1 { v = -1 - int(uv) }
                return v, true
            } else {
                if !cbor_skip(&r) { return 0, false }
            }
        } else {
            // Skip key and value
            if !cbor_skip(&r) { return 0, false }
            if !cbor_skip(&r) { return 0, false }
        }
    }
    return 0, false
}

// Helper: SHA-256 of rpId string
rp_id_hash :: proc(rpId: string) -> [32]byte {
    out: [32]byte
    ctx: hash.Context
    hash.init(&ctx, hash.Algorithm.SHA256)
    hash.update(&ctx, transmute([]byte)rpId)
    hash.final(&ctx, out[:])
    return out
}

// Parse minimal fields from authenticatorData for assertions (no attested credential data)
authdata_parse_assert :: proc(authData: []byte) -> (rpIdHash: [32]byte, flags: u8, signCount: u32, ok: bool) {
    if len(authData) < 37 { return rpIdHash, 0, 0, false }
    for i in 0..<32 { rpIdHash[i] = authData[i] }
    flags = authData[32]
    sc_b := authData[33:37]
    signCount = (u32(sc_b[0])<<24) | (u32(sc_b[1])<<16) | (u32(sc_b[2])<<8) | u32(sc_b[3])
    return rpIdHash, flags, signCount, true
}
