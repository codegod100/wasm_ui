// Minimal auth/OAuth utilities and Bluesky flow
// Exposes a global `Auth` object
(function(){
  const state = {
    onStatus: null,
    onAfterLogin: null,
    onLog: null,
  };

  const log = (...args) => {
    try {
      console.log('[oauth]', ...args);
      const line = args.map(a => {
        if (a == null) return String(a);
        if (typeof a === 'string') return a;
        try { return JSON.stringify(a); } catch { return String(a); }
      }).join(' ');
      const prev = sessionStorage.getItem('authLog') || '';
      sessionStorage.setItem('authLog', prev + line + '\n');
      if (typeof state.onLog === 'function') state.onLog(line);
    } catch {}
  };

  const setStatus = (msg, kind='info') => {
    if (typeof state.onStatus === 'function') state.onStatus(msg, kind);
  };

  const b64uToBytes = (s) => {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  };
  const bytesToB64u = (u8) => {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  };

  const postJson = async (url, body) => {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type':'application/json' }, body: JSON.stringify(body) });
    const text = await r.text();
    if (!text) {
      if (!r.ok) throw new Error(`HTTP ${r.status} empty body`);
      return {};
    }
    try {
      const json = JSON.parse(text);
      if (!r.ok) throw new Error(json && json.error ? json.error : `HTTP ${r.status}`);
      return json;
    } catch (e) {
      if (!r.ok) throw new Error(`HTTP ${r.status} ${text.slice(0,160)}`);
      throw e;
    }
  };

  const b64u = (u8) => bytesToB64u(u8);
  const enc = (s) => new TextEncoder().encode(s);
  const toHex = (u8) => Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join('');
  const uuid = () => { const a=new Uint8Array(16); crypto.getRandomValues(a); a[6]=(a[6]&0x0f)|0x40; a[8]=(a[8]&0x3f)|0x80; const h=toHex(a); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`; };
  const derToJose = (der) => {
    const b = new Uint8Array(der);
    if (b.length === 64) return b;
    let i = 0;
    const expect = (val) => { if (b[i++] !== val) throw new Error('DER parse error'); };
    const readLen = () => {
      let len = b[i++];
      if (len & 0x80) { const n = len & 0x7f; len = 0; for (let j=0;j<n;j++){ len = (len<<8) | b[i++]; } }
      return len;
    };
    expect(0x30); void readLen();
    expect(0x02); let rlen = readLen(); let r = b.slice(i, i + rlen); i += rlen;
    expect(0x02); let slen = readLen(); let s = b.slice(i, i + slen); i += slen;
    while (r.length > 0 && r[0] === 0x00) r = r.slice(1);
    while (s.length > 0 && s[0] === 0x00) s = s.slice(1);
    if (r.length > 32 || s.length > 32) throw new Error('Invalid r|s length');
    const ro = new Uint8Array(32); ro.set(r, 32 - r.length);
    const so = new Uint8Array(32); so.set(s, 32 - s.length);
    const out = new Uint8Array(64); out.set(ro, 0); out.set(so, 32);
    return out;
  };
  const makeDpop = async (htu, nonce) => {
    const key = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key.publicKey);
    const hdr = { typ:'dpop+jwt', alg:'ES256', jwk:{kty:jwk.kty, crv:jwk.crv, x:jwk.x, y:jwk.y} };
    const now = Math.floor(Date.now()/1000);
    const pld = { htm:'POST', htu, iat: now, jti: uuid() };
    if (nonce) pld.nonce = nonce;
    const data = b64u(enc(JSON.stringify(hdr))) + '.' + b64u(enc(JSON.stringify(pld)));
    const sigDer = new Uint8Array(await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, key.privateKey, enc(data)));
    const sigJose = derToJose(sigDer);
    return data + '.' + b64u(sigJose);
  };

  const fetchBskyProfile = async (actor, accessToken, issuerBase) => {
    if (!actor) return { ok:false, text:'' };
    const tryProfile = async (base) => {
      const url = base.replace(/\/$/, '') + '/xrpc/app.bsky.actor.getProfile?actor=' + encodeURIComponent(actor);
      log('GET profile', { url });
      if (base.startsWith('https://api.bsky.app')) {
        const pr = await fetch(url, { method:'GET' });
        const ptext = await pr.text();
        log('Profile resp (appview)', { status: pr.status, preview: ptext.slice(0,200) });
        return { ok: pr.ok, text: ptext };
      }
      const resourceFetch = async (nonce) => {
        const dpop = await makeDpop(url, nonce);
        return fetch(url, { method:'GET', headers:{ 'Authorization': 'DPoP ' + accessToken, 'DPoP': dpop } });
      };
      let pr = await resourceFetch();
      let ptext = await pr.text();
      log('Profile resp (issuer)', { status: pr.status, preview: ptext.slice(0,200) });
      if (!pr.ok) {
        const n = pr.headers.get('DPoP-Nonce') || pr.headers.get('dpop-nonce');
        let perr={}; try { perr = JSON.parse(ptext) } catch {}
        if (n || (perr && perr.error === 'use_dpop_nonce')) {
          log('Retry profile with nonce', { nonce: n });
          pr = await resourceFetch(n||'');
          ptext = await pr.text();
          log('Profile retry resp', { status: pr.status, preview: ptext.slice(0,200) });
        }
      }
      return { ok: pr.ok, text: ptext };
    };
    let res = await tryProfile('https://api.bsky.app');
    if (!res.ok && issuerBase) {
      log('Profile fallback to issuer');
      res = await tryProfile(issuerBase);
    }
    return res;
  };

  const handleOAuthCallbackIfPresent = async () => {
    try {
      if (!(location.search && /[?&](code|error)=/.test(location.search))) return false;
      const p = new URLSearchParams(location.search);
      const msg = {
        source: 'bsky_oauth',
        code: p.get('code') || '',
        state: p.get('state') || '',
        iss: p.get('iss') || '',
        error: p.get('error') || '',
        error_description: p.get('error_description') || '',
        error_uri: p.get('error_uri') || ''
      };
      log('Callback', { state: msg.state, iss: msg.iss, hasCode: !!msg.code, hasErr: !!msg.error });
      if (window.opener) {
        try { window.opener.postMessage(msg, '*'); } catch {}
        if (!msg.error) { document.write('You may close this window.'); setTimeout(()=>{ try{ window.close(); }catch{} },10); }
        return true;
      }
      if (!(msg.code && msg.state && !msg.error)) return true; // consumed
      // Full-window token exchange using DPoP
      const stateVal = sessionStorage.getItem('oauth_bsky_state')||'';
      const verifier = sessionStorage.getItem('oauth_bsky_verifier')||'';
      const clientId = sessionStorage.getItem('oauth_bsky_client_id')||'http://localhost';
      const tokenEndpoint = sessionStorage.getItem('oauth_bsky_token_endpoint')||'';
      const redirectUri = sessionStorage.getItem('oauth_bsky_redirect_uri')||location.origin+'/';
      if (stateVal !== msg.state || !verifier || !tokenEndpoint) { document.body.innerHTML='<h2>Exchange failed</h2><p>Missing verifier or state mismatch.</p>'; return true; }
      const form = (obj) => Object.entries(obj).map(([k,v])=>k+'='+encodeURIComponent(v)).join('&');
      const tokenFetch = async (nonce) => {
        const dpop = await makeDpop(tokenEndpoint, nonce);
        const body = form({ grant_type:'authorization_code', code: msg.code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier });
        log('POST token', { url: tokenEndpoint, hasNonce: !!nonce });
        return fetch(tokenEndpoint, { method:'POST', headers:{ 'content-type':'application/x-www-form-urlencoded', 'DPoP': dpop }, body });
      };
      let r = await tokenFetch();
      let nonce = r.headers.get('DPoP-Nonce') || r.headers.get('dpop-nonce');
      let text = await r.text();
      log('Token resp', { status: r.status, preview: text.slice(0,200) });
      let bodyErr = {}; try { bodyErr = JSON.parse(text) } catch {}
      if ((!r.ok) && (nonce || (bodyErr && bodyErr.error === 'use_dpop_nonce'))) {
        if (!nonce) { nonce = (r.headers.get('DPoP-Nonce') || r.headers.get('dpop-nonce')) || ''; }
        if (nonce) {
          log('Retry token with nonce', { nonce });
          r = await tokenFetch(nonce);
          text = await r.text();
          log('Token retry resp', { status: r.status, preview: text.slice(0,200) });
        }
      }
      if (!r.ok) { document.body.innerHTML = '<h2>Exchange failed</h2><pre>'+text.slice(0,400)+'</pre>'; return true; }
      let tr={}; try { tr = JSON.parse(text); } catch {}
      log('Token OK', { keys: Object.keys(tr) });
      let username = '';
      let didFromAT = '';
      try {
        if (tr.access_token && tr.access_token.includes('.')) {
          const atParts = tr.access_token.split('.');
          if (atParts.length >= 2) {
            const atDec = JSON.parse(new TextDecoder().decode(b64uToBytes(atParts[1])));
            if (atDec && atDec.sub) didFromAT = String(atDec.sub);
            log('access_token decoded', { hasSub: !!didFromAT });
          }
        }
      } catch { log('access_token decode failed'); }
      if (!username && tr.id_token) {
        try { const [,p]=tr.id_token.split('.'); const dec = JSON.parse(new TextDecoder().decode(b64uToBytes(p))); username = dec.handle || dec.did || dec.sub || ''; log('id_token decoded', { haveHandle: !!dec.handle, haveDid: !!dec.did }); } catch { log('id_token decode failed'); }
      }
      try {
        const issuer = (sessionStorage.getItem('oauth_bsky_issuer') || msg.iss || 'https://bsky.social').replace(/\/$/, '');
        const actor = (tr.handle || tr.sub || tr.did || didFromAT || '').trim();
        const res1 = await fetchBskyProfile(actor, tr.access_token || '', issuer);
        if (res1.ok) {
          const prof = JSON.parse(res1.text);
          try { sessionStorage.setItem('bskyProfile', JSON.stringify(prof)); } catch {}
          log('Bluesky profile', { handle: prof && prof.handle });
          if (prof && prof.handle) username = prof.handle;
        } else {
          log('Bluesky profile fetch failed');
        }
      } catch (e) { log('Profile fetch error', String(e)); }
      if (!username) username = tr.handle || 'bsky';
      log('Username chosen', { username });
      try {
        const j = await (await fetch('/api/auth/token?sub='+encodeURIComponent(username))).json();
        if (j && j.token) sessionStorage.setItem('authToken', j.token);
      } catch {}
      try { sessionStorage.setItem('authUsername', username); } catch {}
      if (typeof state.onAfterLogin === 'function') {
        const tok = sessionStorage.getItem('authToken') || '';
        state.onAfterLogin(username, tok);
      }
      setStatus(`Signed in as ${username}`, 'success');
      // Remove query params to keep URL clean
      try { const u = new URL(location.href); u.search = ''; history.replaceState({}, document.title, u.toString()); } catch {}
      return true;
    } catch (e) {
      log('Callback handler error', String(e));
      return false;
    }
  };

  const startBlueskyLogin = async () => {
    try {
      log('Start /api/auth/bsky/start');
      setStatus('Starting Bluesky sign-in…');
      const start = await postJson('/api/auth/bsky/start', {});
      if (!start || !start.url) { setStatus('OAuth start failed', 'error'); return; }
      log('Start OK', { url: start.url, state: start.state, client_id: start.client_id, token_endpoint: start.token_endpoint, redirect_uri: start.redirect_uri, scope: start.scope });
      try {
        sessionStorage.setItem('oauth_bsky_state', start.state || '');
        sessionStorage.setItem('oauth_bsky_verifier', start.code_verifier || '');
        sessionStorage.setItem('oauth_bsky_client_id', start.client_id || '');
        sessionStorage.setItem('oauth_bsky_token_endpoint', start.token_endpoint || '');
        sessionStorage.setItem('oauth_bsky_redirect_uri', start.redirect_uri || '');
        sessionStorage.setItem('oauth_bsky_scope', start.scope || '');
      } catch {}
      window.location.href = start.url; // full-window flow
    } catch (e) {
      const msg = (e && e.message) ? e.message : String(e);
      setStatus('OAuth start failed: ' + msg, 'error');
    }
  };

  const flushAuthLog = (el) => {
    try {
      const prev = sessionStorage.getItem('authLog')||'';
      if (el && prev) { el.textContent += prev; el.scrollTop = el.scrollHeight; sessionStorage.removeItem('authLog'); }
    } catch {}
  };

  const init = (opts={}) => {
    state.onStatus = opts.onStatus || null;
    state.onAfterLogin = opts.onAfterLogin || null;
    state.onLog = opts.onLog || null;
  };

  window.Auth = { init, startBlueskyLogin, handleOAuthCallbackIfPresent, flushAuthLog, b64uToBytes, bytesToB64u };
})();

