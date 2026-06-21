const SESSION_COOKIE = 'journal_session';
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

export class JournalRoom {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/auth' && request.method === 'POST') return this.authenticate(request);
    if (url.pathname === '/session' && request.method === 'POST') return this.validateSession(request);
    if (url.pathname === '/logout' && request.method === 'POST') return this.logout(request);
    if (url.pathname === '/entries' && request.method === 'GET') return this.listEntries(request);
    if (url.pathname === '/entries' && request.method === 'POST') return this.createEntry(request);
    return json({ error: 'Not found' }, 404);
  }

  async authenticate(request) {
    const { password } = await request.json().catch(() => ({}));
    const cleanPassword = String(password || '');
    if (cleanPassword.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400);

    let user = await this.state.storage.get('user');
    if (!user) {
      user = await createUserRecord(cleanPassword);
      await this.state.storage.put('user', user);
    } else {
      const valid = await verifyPassword(cleanPassword, user);
      if (!valid) return json({ error: 'That password does not match this journal.' }, 401);
    }

    const token = crypto.randomUUID();
    const sessions = (await this.state.storage.get('sessions')) || {};
    sessions[token] = Date.now() + SESSION_TTL_SECONDS * 1000;
    await this.state.storage.put('sessions', pruneSessions(sessions));
    return json({ token });
  }

  async validateSession(request) {
    const { token } = await request.json().catch(() => ({}));
    if (!token) return json({ authenticated: false }, 401);
    const sessions = pruneSessions((await this.state.storage.get('sessions')) || {});
    await this.state.storage.put('sessions', sessions);
    if (!sessions[token]) return json({ authenticated: false }, 401);
    return json({ authenticated: true });
  }

  async logout(request) {
    const { token } = await request.json().catch(() => ({}));
    const sessions = (await this.state.storage.get('sessions')) || {};
    delete sessions[token];
    await this.state.storage.put('sessions', sessions);
    return json({ ok: true });
  }

  async listEntries() {
    const entries = (await this.state.storage.get('entries')) || [];
    return json({ entries: organizeEntries(entries) });
  }

  async createEntry(request) {
    const body = await request.json().catch(() => ({}));
    const text = String(body.text || '').trim();
    if (!text) return json({ error: 'Write something first.' }, 400);
    if (text.length > 20000) return json({ error: 'Entries are limited to 20,000 characters.' }, 400);

    const entries = (await this.state.storage.get('entries')) || [];
    const now = new Date();
    entries.unshift({
      id: crypto.randomUUID(),
      text,
      createdAt: now.toISOString(),
      localTimeHint: body.localTimeHint ? String(body.localTimeHint).slice(0, 120) : null,
    });
    await this.state.storage.put('entries', entries.slice(0, 1000));
    return json({ entries: organizeEntries(entries) }, 201);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!env.JOURNALS) {
      return json({ error: 'JOURNALS Durable Object binding is not configured.' }, 500);
    }

    if (url.pathname === '/api/session') return getSession(request, env);
    if (url.pathname === '/api/auth' && request.method === 'POST') return authenticate(request, env);
    if (url.pathname === '/api/logout' && request.method === 'POST') return logout(request, env);
    if (url.pathname === '/api/entries') return entries(request, env);

    if (request.method !== 'GET') return new Response('Not found', { status: 404 });
    return new Response(renderApp(), { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  },
};

async function getSession(request, env) {
  const session = await readSession(request, env);
  return json({ authenticated: Boolean(session), username: session?.username ?? null });
}

async function authenticate(request, env) {
  const { username, password } = await request.json().catch(() => ({}));
  const cleanUsername = normalizeUsername(username);
  if (!cleanUsername) {
    return json({ error: 'Use 3–40 characters: letters, numbers, dots, dashes, or underscores.' }, 400);
  }

  const response = await journalStub(env, cleanUsername).fetch('https://journal.local/auth', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });
  const payload = await response.json();
  if (!response.ok) return json(payload, response.status);

  const packedToken = packSession(cleanUsername, payload.token);
  return json(
    { authenticated: true, username: cleanUsername },
    200,
    { 'set-cookie': cookie(packedToken, SESSION_TTL_SECONDS) },
  );
}

async function logout(request, env) {
  const session = unpackSession(parseCookies(request.headers.get('cookie'))[SESSION_COOKIE]);
  if (session) {
    await journalStub(env, session.username).fetch('https://journal.local/logout', {
      method: 'POST',
      body: JSON.stringify({ token: session.token }),
    });
  }
  return json({ ok: true }, 200, {
    'set-cookie': `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
  });
}

async function entries(request, env) {
  const session = await readSession(request, env);
  if (!session) return json({ error: 'Sign in to keep writing.' }, 401);

  const stub = journalStub(env, session.username);
  const response = await stub.fetch('https://journal.local/entries', {
    method: request.method,
    body: request.method === 'POST' ? await request.text() : undefined,
  });
  return new Response(response.body, response);
}

async function readSession(request, env) {
  const packed = parseCookies(request.headers.get('cookie'))[SESSION_COOKIE];
  const session = unpackSession(packed);
  if (!session) return null;

  const response = await journalStub(env, session.username).fetch('https://journal.local/session', {
    method: 'POST',
    body: JSON.stringify({ token: session.token }),
  });
  return response.ok ? session : null;
}

function journalStub(env, username) {
  return env.JOURNALS.get(env.JOURNALS.idFromName(username));
}

function normalizeUsername(username) {
  const cleanUsername = String(username || '').trim().toLowerCase();
  return /^[a-z0-9._-]{3,40}$/.test(cleanUsername) ? cleanUsername : null;
}

function packSession(username, token) {
  return `${username}:${token}`;
}

function unpackSession(value) {
  if (!value) return null;
  const separator = value.indexOf(':');
  if (separator < 1) return null;
  const username = normalizeUsername(value.slice(0, separator));
  const token = value.slice(separator + 1);
  return username && token ? { username, token } : null;
}

function organizeEntries(entries) {
  return entries.map((entry) => ({
    ...entry,
    day: entry.createdAt.slice(0, 10),
    month: new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(entry.createdAt)),
    timeAgo: relativeTime(entry.createdAt),
  }));
}

function relativeTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
  if (diff < DAY_MS) return `${Math.floor(diff / 3_600_000)} hr ago`;
  return `${Math.floor(diff / DAY_MS)} days ago`;
}

function pruneSessions(sessions) {
  const now = Date.now();
  return Object.fromEntries(Object.entries(sessions).filter(([, expiresAt]) => expiresAt > now));
}

async function createUserRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { salt: toBase64(salt), hash: await hashPassword(password, salt), iterations: 150000 };
}

async function verifyPassword(password, record) {
  const salt = fromBase64(record.salt);
  const hash = await hashPassword(password, salt, record.iterations);
  return constantTimeEqual(hash, record.hash);
}

async function hashPassword(password, salt, iterations = 150000) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return toBase64(new Uint8Array(bits));
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let index = 0; index < a.length; index++) mismatch |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return mismatch === 0;
}

function parseCookies(header) {
  return Object.fromEntries((header || '').split(';').filter(Boolean).map((part) => {
    const [key, ...value] = part.trim().split('=');
    return [key, decodeURIComponent(value.join('='))];
  }));
}

function cookie(token, maxAge) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function toBase64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function fromBase64(value) { return Uint8Array.from(atob(value), (char) => char.charCodeAt(0)); }

function json(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json;charset=UTF-8', ...headers },
  });
}

function renderApp() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Quiet Journal</title>
<style>
:root{color-scheme:light;--ink:#191714;--muted:#7f766c;--paper:#fffaf1;--card:rgba(255,255,255,.74);--line:rgba(25,23,20,.11);--accent:#886a45;--accent-2:#d8b98f;--shadow:0 24px 70px rgba(74,57,38,.14)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 20% 0%,#fff 0,#fff7e7 28%,transparent 42%),linear-gradient(135deg,#f8efe0,#fffaf4 44%,#f1eadf);color:var(--ink)}
body:before{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(136,106,69,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(136,106,69,.035) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 78%);pointer-events:none}.shell{width:min(1120px,calc(100% - 32px));margin:0 auto;padding:42px 0}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:36px}.brand{font-family:Georgia,serif;font-size:clamp(2rem,5vw,4.2rem);letter-spacing:-.06em}.tag{color:var(--muted);max-width:420px;line-height:1.6}.card{background:var(--card);backdrop-filter:blur(22px);border:1px solid var(--line);border-radius:32px;box-shadow:var(--shadow)}.login{max-width:460px;margin:8vh auto;padding:34px}.login h1{font-family:Georgia,serif;font-size:3.2rem;line-height:.95;margin:0 0 14px}.field{display:grid;gap:8px;margin:18px 0}.field span{font-size:.78rem;text-transform:uppercase;letter-spacing:.14em;color:var(--muted)}input,textarea,button{font:inherit}input,textarea{width:100%;border:1px solid var(--line);border-radius:18px;background:rgba(255,255,255,.72);padding:15px 16px;color:var(--ink);outline:none}textarea{min-height:260px;resize:vertical;line-height:1.7}.button{border:0;border-radius:999px;background:var(--ink);color:#fff;padding:13px 19px;cursor:pointer;box-shadow:0 12px 26px rgba(25,23,20,.18);transition:.2s}.button:hover{transform:translateY(-1px)}.ghost{background:transparent;color:var(--ink);border:1px solid var(--line);box-shadow:none}.app{display:none;grid-template-columns:minmax(0,1fr) 360px;gap:22px}.editor{padding:24px}.editorbar{display:flex;justify-content:space-between;gap:14px;align-items:center;margin-top:14px}.hint,.error{color:var(--muted);font-size:.92rem}.error{color:#9d3d2f}.timeline{padding:22px;max-height:72vh;overflow:auto}.timeline h2{font-family:Georgia,serif;font-size:2rem;margin:0 0 18px}.month{margin:20px 0 10px;color:var(--accent);font-size:.76rem;text-transform:uppercase;letter-spacing:.18em}.entry{border-top:1px solid var(--line);padding:16px 0}.entry time{display:block;color:var(--muted);font-size:.86rem;margin-bottom:8px}.entry p{white-space:pre-wrap;line-height:1.65;margin:0}.empty{text-align:center;padding:42px 16px;color:var(--muted)}.search{margin-bottom:12px}.pill{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:999px;padding:9px 12px;color:var(--muted);background:rgba(255,255,255,.54)}@media(max-width:860px){.top{align-items:flex-start;gap:18px;flex-direction:column}.app{grid-template-columns:1fr}.timeline{max-height:none}.shell{padding-top:24px}}
</style>
</head>
<body>
<main class="shell">
  <section id="login" class="card login">
    <div class="pill">✦ private by username</div>
    <h1>Quiet Journal</h1>
    <p class="tag">A minimal place to pour thoughts. Sign in with a username and password; first sign-in creates your journal.</p>
    <form id="authForm">
      <label class="field"><span>Username</span><input name="username" autocomplete="username" required minlength="3" /></label>
      <label class="field"><span>Password</span><input name="password" type="password" autocomplete="current-password" required minlength="8" /></label>
      <button class="button" type="submit">Open journal</button>
      <p id="authError" class="error"></p>
    </form>
  </section>

  <section id="journal" style="display:none">
    <header class="top"><div><div class="brand">Quiet Journal</div><p class="tag" id="welcome"></p></div><button class="button ghost" id="logout">Sign out</button></header>
    <div class="app" id="appGrid">
      <section class="card editor">
        <textarea id="entryText" placeholder="What feels true right now?"></textarea>
        <div class="editorbar"><span class="hint" id="timeHint"></span><button class="button" id="save">Save entry</button></div>
        <p id="saveError" class="error"></p>
      </section>
      <aside class="card timeline">
        <h2>Organized moments</h2>
        <input class="search" id="search" placeholder="Search entries" />
        <div id="entries"></div>
      </aside>
    </div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
let allEntries = [];
const fmt = new Intl.DateTimeFormat(undefined,{dateStyle:'full',timeStyle:'short'});
setInterval(()=> $('timeHint').textContent = 'Captured at ' + fmt.format(new Date()), 1000);
async function api(path, options={}){const res=await fetch(path,{headers:{'content-type':'application/json'},...options});const data=await res.json();if(!res.ok) throw new Error(data.error||'Something went wrong');return data;}
function showApp(username){$('login').style.display='none';$('journal').style.display='block';$('appGrid').style.display='grid';$('welcome').textContent='Welcome, '+username+'. Every entry is timestamped and grouped automatically.';loadEntries();}
function showLogin(){$('login').style.display='block';$('journal').style.display='none';}
$('authForm').addEventListener('submit',async(e)=>{e.preventDefault();$('authError').textContent='';const form=new FormData(e.currentTarget);try{const data=await api('/api/auth',{method:'POST',body:JSON.stringify(Object.fromEntries(form))});showApp(data.username)}catch(err){$('authError').textContent=err.message}});
$('save').addEventListener('click',async()=>{const text=$('entryText').value;$('saveError').textContent='';try{const data=await api('/api/entries',{method:'POST',body:JSON.stringify({text,localTimeHint:fmt.format(new Date())})});$('entryText').value='';allEntries=data.entries;renderEntries()}catch(err){$('saveError').textContent=err.message}});
$('logout').addEventListener('click',async()=>{await api('/api/logout',{method:'POST'});showLogin()});
$('search').addEventListener('input',renderEntries);
async function loadEntries(){const data=await api('/api/entries');allEntries=data.entries;renderEntries()}
function renderEntries(){const q=$('search').value.toLowerCase();const entries=allEntries.filter(e=>e.text.toLowerCase().includes(q));let month='';$('entries').innerHTML=entries.length?entries.map(e=>{const heading=e.month!==month?'<div class="month">'+(month=e.month)+'</div>':'';return heading+'<article class="entry"><time>'+fmt.format(new Date(e.createdAt))+' · '+e.timeAgo+'</time><p>'+escapeHtml(e.text)+'</p></article>'}).join(''):'<div class="empty">No entries yet. Begin with one honest sentence.</div>'}
function escapeHtml(value){return value.replace(/[&<>"]/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
api('/api/session').then(data=>data.authenticated?showApp(data.username):showLogin()).catch(showLogin);
</script>
</body>
</html>`;
}
