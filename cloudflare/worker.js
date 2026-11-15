// Ecker's Family – Push-Worker (Cloudflare Workers, Gratis-Tarif)
// Braucht: KV-Namespace mit der Bindung "KV". Keine Geheimnisse im Code.
const PROJECT = 'ecker-s-family-app';
const ORIGIN = 'https://tristanecker-hue.github.io';
const FAMILY = ['tristan', 'claudia', 'lina', 'florian'];
const SUBJECT = 'https://tristanecker-hue.github.io/Ecker-Family/';
const JWKS = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

const enc = new TextEncoder();
const b64u = buf => { let s = ''; new Uint8Array(buf).forEach(b => s += String.fromCharCode(b)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s); const u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; a.forEach(x => { o.set(x, p); p += x.length; }); return o; };

const cors = () => ({ 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Max-Age': '86400' });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json', ...cors() } });

// ---- Firebase-Anmeldung prüfen (ID-Token, RS256) ----
async function verifyUser(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.get('Authorization') || '');
  if (!m) return null;
  const parts = m[1].split('.');
  if (parts.length !== 3) return null;
  try {
    const head = JSON.parse(new TextDecoder().decode(unb64u(parts[0])));
    const claims = JSON.parse(new TextDecoder().decode(unb64u(parts[1])));
    if (head.alg !== 'RS256') return null;
    const res = await fetch(JWKS, { cf: { cacheTtl: 3600, cacheEverything: true } });
    const keys = (await res.json()).keys || [];
    const jwk = keys.find(k => k.kid === head.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
    if (!ok) return null;
    const now = Date.now() / 1000;
    if (claims.aud !== PROJECT || claims.iss !== 'https://securetoken.google.com/' + PROJECT || claims.exp < now || claims.iat > now + 300) return null;
    const email = String(claims.email || '').toLowerCase();
    const user = email.split('@')[0];
    if (!email.endsWith('@ecker.ch') || !FAMILY.includes(user)) return null;
    return user;
  } catch (e) { return null; }
}

// ---- VAPID-Schlüssel (werden beim ersten Aufruf erzeugt und im KV gespeichert) ----
async function getVapid(env) {
  const saved = await env.KV.get('vapid', 'json');
  if (saved) return saved;
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const v = { pub: b64u(await crypto.subtle.exportKey('raw', kp.publicKey)), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) };
  await env.KV.put('vapid', JSON.stringify(v));
  return v;
}

async function vapidHeader(endpoint, v) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const key = await crypto.subtle.importKey('jwk', v.priv, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + body));
  return 'vapid t=' + head + '.' + body + '.' + b64u(sig) + ', k=' + v.pub;
}

// ---- Web-Push-Verschlüsselung (RFC 8291, aes128gcm) ----
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encrypt(sub, payload) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, secret, cat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const data = cat(enc.encode(payload), new Uint8Array([2]));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, data));
  return cat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct);
}

async function sendPush(sub, msg, v) {
  const body = await encrypt(sub, JSON.stringify(msg));
  return fetch(sub.endpoint, { method: 'POST', body, headers: { Authorization: await vapidHeader(sub.endpoint, v), 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' } });
}

const goodSub = s => s && typeof s.endpoint === 'string' && s.endpoint.startsWith('https://') && s.keys && typeof s.keys.p256dh === 'string' && typeof s.keys.auth === 'string';

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
    const path = new URL(req.url).pathname;
    try {
      if (path === '/' ) return json({ ok: true, name: 'ecker-family-push' });
      if (path === '/vapid') return json({ pub: (await getVapid(env)).pub });
      if (req.method !== 'POST') return json({ error: 'not found' }, 404);
      const user = await verifyUser(req);
      if (!user) return json({ error: 'nicht angemeldet' }, 401);
      const data = await req.json().catch(() => ({}));

      if (path === '/subscribe') {
        if (!goodSub(data.sub)) return json({ error: 'ungültig' }, 400);
        const list = ((await env.KV.get('sub:' + user, 'json')) || []).filter(s => s.endpoint !== data.sub.endpoint);
        list.push({ endpoint: data.sub.endpoint, keys: { p256dh: data.sub.keys.p256dh, auth: data.sub.keys.auth } });
        await env.KV.put('sub:' + user, JSON.stringify(list.slice(-8)));
        return json({ ok: true });
      }
      if (path === '/unsubscribe') {
        const list = ((await env.KV.get('sub:' + user, 'json')) || []).filter(s => s.endpoint !== data.endpoint);
        await env.KV.put('sub:' + user, JSON.stringify(list));
        return json({ ok: true });
      }
      if (path === '/notify') {
        const msgs = Array.isArray(data.msgs) ? data.msgs.slice(0, 10) : [];
        const v = await getVapid(env);
        let sent = 0;
        for (const m of msgs) {
          const msg = { title: String(m.title || "Ecker's Family").slice(0, 80), body: String(m.body || '').slice(0, 200), url: String(m.url || './').slice(0, 100) };
          for (const to of [...new Set((m.to || []).map(String))].filter(k => FAMILY.includes(k))) {
            const subs = (await env.KV.get('sub:' + to, 'json')) || [];
            const keep = [];
            await Promise.all(subs.map(async s => {
              try {
                const r = await sendPush(s, msg, v);
                if (r.status === 404 || r.status === 410) return;   // Gerät abgemeldet
                if (r.ok) sent++;
              } catch (e) {}
              keep.push(s);
            }));
            if (keep.length !== subs.length) await env.KV.put('sub:' + to, JSON.stringify(keep));
          }
        }
        return json({ ok: true, sent });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) { return json({ error: 'Fehler' }, 500); }
  }
};
