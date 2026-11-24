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
async function verifyUser(req, allowPad) {
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
    if (!email.endsWith('@ecker.ch') || !(FAMILY.includes(user) || (allowPad && user === 'pad'))) return null;
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

const cleanMsg = m => ({ title: String(m.title || "Ecker's Family").slice(0, 80), body: String(m.body || '').slice(0, 200), url: String(m.url || './').slice(0, 100) });

async function pushToUser(env, v, user, msg) {
  const subs = (await env.KV.get('sub:' + user, 'json')) || [];
  const keep = [];
  let sent = 0;
  await Promise.all(subs.map(async s => {
    try {
      const r = await sendPush(s, msg, v);
      if (r.status === 404 || r.status === 410) return;   // Gerät abgemeldet
      if (r.ok) sent++;
    } catch (e) {}
    keep.push(s);
  }));
  if (keep.length !== subs.length) await env.KV.put('sub:' + user, JSON.stringify(keep));
  return sent;
}
async function pushToMany(env, v, to, msg) {
  let n = 0;
  for (const u of [...new Set((to || []).map(String))].filter(k => FAMILY.includes(k))) n += await pushToUser(env, v, u, msg);
  return n;
}

// Fällige Erinnerungen versenden (wird vom Cron-Trigger alle paar Minuten aufgerufen)
// Zeitzonen-Hilfen: nächster Tag zur gleichen Ortszeit (Sommerzeit-fest)
const tzOffset = (ts, tz) => {
  const p = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' }).formatToParts(ts).reduce((a, x) => (a[x.type] = x.value, a), {});
  return Date.UTC(+p.year, p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - Math.floor(ts / 1000) * 1000;
};
const goodTz = tz => { try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); return true; } catch (e) { return false; } };
const nextDayAt = (prev, tz, days) => {
  const o = tzOffset(prev, tz), loc = new Date(prev + o);
  loc.setUTCDate(loc.getUTCDate() + days);
  const guess = loc.getTime();
  return guess - tzOffset(guess - o, tz);
};
const putRem = async (env, id, at, val) => {
  const key = 'rem:' + String(Math.floor(at / 1000)).padStart(11, '0') + ':' + id;
  await env.KV.put(key, JSON.stringify(val));
  await env.KV.put('remid:' + id, key);
};

async function runDue(env) {
  const now = Date.now(), v = await getVapid(env);
  const list = await env.KV.list({ prefix: 'rem:', limit: 200 });
  for (const k of list.keys) {
    const at = parseInt(k.name.split(':')[1], 10) * 1000;
    if (at > now) break;
    const val = await env.KV.get(k.name, 'json');
    await env.KV.delete(k.name);
    if (val && val.id) await env.KV.delete('remid:' + val.id);
    if (!val) continue;
    // Wiederholte Erinnerung (z. B. «überfällig»): am nächsten Tag zur gleichen Ortszeit erneut einplanen
    if (val.repeat && val.id) {
      let nx = at;
      do { nx = nextDayAt(nx, val.tz || 'UTC', val.repeat); } while (nx <= now);
      if (!val.until || nx <= val.until) await putRem(env, val.id, nx, val);
    }
    if (now - at > 6 * 3600000) continue;   // zu alt (z. B. Pause) – nicht mehr senden
    await pushToMany(env, v, val.to, val.msg);
  }
}


// ---- Philips Hue (Remote API, Anmeldung einmalig durch Tristan) ----
const HUE = 'https://api.meethue.com';
const hueBasic = env => 'Basic ' + btoa(env.HUE_CLIENT_ID + ':' + env.HUE_CLIENT_SECRET);
async function hueToken(env, form) {
  const r = await fetch(HUE + '/v2/oauth2/token', { method: 'POST', headers: { Authorization: hueBasic(env), 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString() });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error('hue-token');
  return j;
}
async function hueAccess(env) {
  const h = await env.KV.get('hue', 'json');
  if (!h || !h.refresh || !h.user) return null;
  if (h.exp > Date.now() + 60000) return h;
  const j = await hueToken(env, { grant_type: 'refresh_token', refresh_token: h.refresh });
  const n = { ...h, access: j.access_token, refresh: j.refresh_token || h.refresh, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000 };
  await env.KV.put('hue', JSON.stringify(n));
  return n;
}
async function hueCall(env, method, path, body) {
  const h = await hueAccess(env);
  if (!h) return null;
  const r = await fetch(HUE + '/route/clip/v2/resource/' + path, { method, headers: { Authorization: 'Bearer ' + h.access, 'hue-application-key': h.user, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('hue-' + r.status);
  return j.data || [];
}
const page = (t, ok) => new Response('<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><body style="font:20px system-ui;text-align:center;padding:60px 20px"><div style="font-size:60px">' + (ok ? '💡' : '⚠️') + '</div><p>' + t + '</p><p><a href="' + SUBJECT + '">Zurück zur App</a></p>', { status: ok ? 200 : 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
async function hueCallback(env, url) {
  const code = url.searchParams.get('code'), state = url.searchParams.get('state') || '';
  if (!env.HUE_CLIENT_ID || !env.HUE_CLIENT_SECRET) return page('Hue ist im Worker nicht eingerichtet (Secrets fehlen).', false);
  if (!code || !/^[A-Za-z0-9_-]{10,80}$/.test(state) || !(await env.KV.get('huestate:' + state))) return page('Ungültige oder abgelaufene Anfrage. Bitte in der App nochmals auf «Hue verbinden» tippen.', false);
  await env.KV.delete('huestate:' + state);
  try {
    const j = await hueToken(env, { grant_type: 'authorization_code', code });
    const auth = { Authorization: 'Bearer ' + j.access_token, 'Content-Type': 'application/json' };
    await fetch(HUE + '/route/api/0/config', { method: 'PUT', headers: auth, body: JSON.stringify({ linkbutton: true }) });
    const r = await fetch(HUE + '/route/api/', { method: 'POST', headers: auth, body: JSON.stringify({ devicetype: 'ecker-family' }) });
    const k = await r.json().catch(() => []);
    const user = k && k[0] && k[0].success && k[0].success.username;
    if (!user) return page('Die Hue Bridge hat die Verbindung nicht freigegeben.', false);
    await env.KV.put('hue', JSON.stringify({ access: j.access_token, refresh: j.refresh_token, exp: Date.now() + (Number(j.expires_in) || 3600) * 1000, user }));
    return page('Hue ist verbunden. Du kannst dieses Fenster schliessen.', true);
  } catch (e) { return page('Verbindung mit Hue fehlgeschlagen.', false); }
}
async function hueState(env, all) {
  const [rooms, gls, scenes, lts] = await Promise.all([hueCall(env, 'GET', 'room'), hueCall(env, 'GET', 'grouped_light'), hueCall(env, 'GET', 'scene'), hueCall(env, 'GET', 'light')]);
  if (!rooms) return { connected: false };
  const gm = {}; (gls || []).forEach(g => gm[g.id] = g);
  const out = (rooms || []).map(r => {
    const sv = (r.services || []).find(x => x.rtype === 'grouped_light'); const g = sv && gm[sv.rid];
    return g ? { id: r.id, name: (r.metadata && r.metadata.name) || '?', gl: g.id, on: !!(g.on && g.on.on), bri: g.dimming ? Math.round(g.dimming.brightness) : null } : null;
  }).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name, 'de'));
  const cfg = await env.KV.get('huecfg', 'json');
  const okIds = cfg && Array.isArray(cfg.rooms) ? cfg.rooms : null;
  if (all) out.forEach(r => r.enabled = !okIds || okIds.includes(r.id));
  else if (okIds) for (let i = out.length - 1; i >= 0; i--) if (!okIds.includes(out[i].id)) out.splice(i, 1);
  const dev2room = {}; (rooms || []).forEach(r => (r.children || []).forEach(c => { dev2room[c.rid] = r.id; }));
  const okLights = cfg && Array.isArray(cfg.lights) ? cfg.lights : null;
  let lights = (lts || []).map(l => ({ id: l.id, name: (l.metadata && l.metadata.name) || '?', on: !!(l.on && l.on.on), bri: l.dimming ? Math.round(l.dimming.brightness) : null, room: dev2room[l.owner && l.owner.rid] || null }));
  if (all) lights.forEach(l => l.enabled = !okLights || okLights.includes(l.id));
  else if (okLights) lights = lights.filter(l => okLights.includes(l.id));
  lights.sort((a, b) => a.name.localeCompare(b.name, 'de'));
  const sc = (scenes || []).map(x => ({ id: x.id, name: (x.metadata && x.metadata.name) || '?', room: x.group && x.group.rid })).filter(x => out.some(r => r.id === x.room));
  return { connected: true, rooms: out, scenes: sc, lights };
}

const goodSub = s => s && typeof s.endpoint === 'string' && s.endpoint.startsWith('https://') && s.keys && typeof s.keys.p256dh === 'string' && typeof s.keys.auth === 'string';

export default {
  async scheduled(event, env, ctx) { ctx.waitUntil(runDue(env)); },
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
    const path = new URL(req.url).pathname;
    try {
      if (path === '/' ) return json({ ok: true, name: 'ecker-family-push' });
      if (path === '/vapid') return json({ pub: (await getVapid(env)).pub });
      if (path === '/hue/callback') return hueCallback(env, new URL(req.url));
      if (req.method !== 'POST') return json({ error: 'not found' }, 404);
      if (path.startsWith('/hue/')) {
        const hu = await verifyUser(req, true);
        if (!hu) return json({ error: 'nicht angemeldet' }, 401);
        const d = await req.json().catch(() => ({}));
        const GID = /^[0-9a-f-]{36}$/;
        if (path === '/hue/start') {
          if (hu !== 'tristan') return json({ error: 'nur Tristan' }, 403);
          if (!env.HUE_CLIENT_ID || !env.HUE_CLIENT_SECRET) return json({ error: 'Hue-Secrets fehlen im Worker' }, 400);
          const st = b64u(crypto.getRandomValues(new Uint8Array(18)));
          await env.KV.put('huestate:' + st, '1', { expirationTtl: 600 });
          return json({ url: HUE + '/v2/oauth2/authorize?client_id=' + encodeURIComponent(env.HUE_CLIENT_ID) + '&response_type=code&state=' + st });
        }
        if (path === '/hue/disconnect') {
          if (hu !== 'tristan') return json({ error: 'nur Tristan' }, 403);
          await env.KV.delete('hue'); return json({ ok: true });
        }
        if (path === '/hue/state') return json(await hueState(env, d.all === true && hu === 'tristan'));
        if (path === '/hue/config') {
          if (hu !== 'tristan') return json({ error: 'nur Tristan' }, 403);
          const ids = (Array.isArray(d.rooms) ? d.rooms : []).map(String).filter(x => GID.test(x)).slice(0, 100);
          const nc = { rooms: ids };
          if (Array.isArray(d.lights)) nc.lights = d.lights.map(String).filter(x => GID.test(x)).slice(0, 300);
          else { const o = await env.KV.get('huecfg', 'json'); if (o && o.lights) nc.lights = o.lights; }
          await env.KV.put('huecfg', JSON.stringify(nc)); return json({ ok: true });
        }
        if (path === '/hue/setlight') {
          if (!GID.test(String(d.id))) return json({ error: 'ungültig' }, 400);
          const sl = await hueState(env);
          if (!sl.connected || !sl.lights.some(l => l.id === d.id)) return json({ error: 'nicht freigegeben' }, 403);
          const lb = { on: { on: !!d.on } };
          if (d.bri != null) lb.dimming = { brightness: Math.max(1, Math.min(100, Number(d.bri) || 1)) };
          await hueCall(env, 'PUT', 'light/' + d.id, lb); return json({ ok: true });
        }
        if (path === '/hue/alloff') {
          const st = await hueState(env);
          if (!st.connected) return json({ error: 'nicht verbunden' }, 400);
          const offRooms = st.rooms.filter(r => r.on);
          const covered = new Set(offRooms.map(r => r.id));
          const jobs = offRooms.map(r => hueCall(env, 'PUT', 'grouped_light/' + r.gl, { on: { on: false } }));
          st.lights.filter(l => l.on && !covered.has(l.room)).forEach(l => jobs.push(hueCall(env, 'PUT', 'light/' + l.id, { on: { on: false } })));
          const res = await Promise.allSettled(jobs);
          return json({ ok: true, n: jobs.length, failed: res.filter(x => x.status === 'rejected').length });
        }
        if (path === '/hue/plan') return json((await env.KV.get('hueplan', 'json')) || {});
        if (path === '/hue/plan-save') {
          if (hu !== 'tristan') return json({ error: 'nur Tristan' }, 403);
          const old = (await env.KV.get('hueplan', 'json')) || {};
          let img = old.img || '';
          if (typeof d.img === 'string' && d.img) {
            if (!d.img.startsWith('data:image/jpeg;base64,') || d.img.length > 1500000) return json({ error: 'Bild ungültig oder zu gross' }, 400);
            img = d.img;
          }
          const pins = (Array.isArray(d.pins) ? d.pins : []).filter(p => p && (p.k === 'room' || p.k === 'light') && GID.test(String(p.id)) && p.x >= 0 && p.x <= 1 && p.y >= 0 && p.y <= 1).slice(0, 150).map(p => ({ k: p.k, id: p.id, x: Math.round(p.x * 10000) / 10000, y: Math.round(p.y * 10000) / 10000 }));
          await env.KV.put('hueplan', JSON.stringify({ img, pins })); return json({ ok: true });
        }
        if (path === '/hue/set') {
          if (!GID.test(String(d.gl))) return json({ error: 'ungültig' }, 400);
          const stt = await hueState(env);
          if (!stt.connected || !stt.rooms.some(r => r.gl === d.gl)) return json({ error: 'nicht freigegeben' }, 403);
          const b = { on: { on: !!d.on } };
          if (d.bri != null) b.dimming = { brightness: Math.max(1, Math.min(100, Number(d.bri) || 1)) };
          await hueCall(env, 'PUT', 'grouped_light/' + d.gl, b); return json({ ok: true });
        }
        if (path === '/hue/scene') {
          if (!GID.test(String(d.id))) return json({ error: 'ungültig' }, 400);
          const st2 = await hueState(env);
          if (!st2.connected || !st2.scenes.some(x => x.id === d.id)) return json({ error: 'nicht freigegeben' }, 403);
          await hueCall(env, 'PUT', 'scene/' + d.id, { recall: { action: 'active' } }); return json({ ok: true });
        }
        return json({ error: 'not found' }, 404);
      }
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
        for (const m of msgs) sent += await pushToMany(env, v, m.to, cleanMsg(m));
        return json({ ok: true, sent });
      }
      if (path === '/remind') {
        const id = String(data.id || ''), at = Number(data.at), to = [...new Set((data.to || []).map(String))].filter(k => FAMILY.includes(k));
        const now = Date.now();
        if (!/^[A-Za-z0-9_-]{1,100}$/.test(id) || !to.length || !(at > now - 60000) || at > now + 400 * 86400000) return json({ error: 'ungültig' }, 400);
        const old = await env.KV.get('remid:' + id);
        if (old) await env.KV.delete(old);
        const rec = { id, to, msg: cleanMsg({ title: data.title || '⏰ Erinnerung', body: data.body, url: data.url }) };
        const rep = Math.floor(Number(data.repeat) || 0);
        if (rep >= 1 && rep <= 7) {
          const tz = String(data.tz || 'Europe/Zurich');
          if (!goodTz(tz)) return json({ error: 'ungültig' }, 400);
          rec.repeat = rep; rec.tz = tz;
          rec.until = Math.min(Number(data.until) || at + 60 * 86400000, at + 120 * 86400000);
        }
        await putRem(env, id, at, rec);
        return json({ ok: true });
      }
      if (path === '/remind-cancel') {
        const id = String(data.id || '');
        const old = await env.KV.get('remid:' + id);
        if (old) { await env.KV.delete(old); await env.KV.delete('remid:' + id); }
        return json({ ok: true });
      }
      return json({ error: 'not found' }, 404);
    } catch (e) { return json({ error: 'Fehler', detail: String((e && e.message) || e).slice(0, 80) }, 500); }
  }
};
