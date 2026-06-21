const SESSION_COOKIE = 'journal_session';
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const PASSWORD_ITERATIONS = 100000;
const ENCRYPTION_VERSION = 1;

export class JournalRoomCore {
  constructor(storage) {
    this.storage = storage;
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

    let user = await this.storage.get('user');
    if (!user) {
      user = await createUserRecord(cleanPassword);
      await this.storage.put('user', user);
    } else {
      const valid = await verifyPassword(cleanPassword, user);
      if (!valid) return json({ error: 'That password does not match this journal.' }, 401);
      if (!user.encryptionSalt) {
        user = { ...user, encryptionSalt: randomSalt() };
        await this.storage.put('user', user);
      }
    }

    const token = crypto.randomUUID();
    const sessions = (await this.storage.get('sessions')) || {};
    sessions[token] = Date.now() + SESSION_TTL_SECONDS * 1000;
    await this.storage.put('sessions', pruneSessions(sessions));
    return json({ token, encryptionSalt: user.encryptionSalt });
  }

  async validateSession(request) {
    const { token } = await request.json().catch(() => ({}));
    if (!token) return json({ authenticated: false }, 401);
    const sessions = pruneSessions((await this.storage.get('sessions')) || {});
    await this.storage.put('sessions', sessions);
    if (!sessions[token]) return json({ authenticated: false }, 401);
    return json({ authenticated: true });
  }

  async logout(request) {
    const { token } = await request.json().catch(() => ({}));
    const sessions = (await this.storage.get('sessions')) || {};
    delete sessions[token];
    await this.storage.put('sessions', sessions);
    return json({ ok: true });
  }

  async listEntries() {
    const entries = (await this.storage.get('entries')) || [];
    const draftIndex = entries.findIndex((entry) => entry.draft === true);
    if (draftIndex >= 0) {
      entries[draftIndex] = { ...entries[draftIndex], draft: false, finalizedAt: new Date().toISOString() };
      await this.storage.put('entries', entries);
    }
    return json(journalPayload(entries));
  }

  async createEntry(request) {
    const body = await request.json().catch(() => ({}));
    const ciphertext = String(body.ciphertext || '');
    const iv = String(body.iv || '');
    const encrypted = Number(body.encryptionVersion) === ENCRYPTION_VERSION && ciphertext && iv;
    const entryId = String(body.id || '').trim().slice(0, 80) || crypto.randomUUID();
    let entries = (await this.storage.get('entries')) || [];
    const existingIndex = entries.findIndex((entry) => entry.id === entryId);

    if (!encrypted) {
      if (body.discard && existingIndex >= 0 && entries[existingIndex].draft === true) {
        entries.splice(existingIndex, 1);
        await this.storage.put('entries', entries);
        return json({ ...journalPayload(entries), entry: null });
      }
      return json({ error: 'Entries must be encrypted before they are saved.' }, 400);
    }
    const plaintextLength = Number(body.plaintextLength) || 0;
    if (plaintextLength < 1 || plaintextLength > 20000 || ciphertext.length > 120000 || iv.length > 100) {
      return json({ error: 'Encrypted entry is invalid or too large.' }, 400);
    }

    const now = new Date().toISOString();
    const existing = existingIndex >= 0 ? entries[existingIndex] : null;
    const finalized = existing?.draft === false || body.finalize === true;
    const entry = {
      id: entryId,
      encryptionVersion: ENCRYPTION_VERSION,
      ciphertext,
      iv,
      plaintextLength,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
      localTimeHint: body.localTimeHint ? String(body.localTimeHint).slice(0, 120) : null,
      draft: !finalized,
    };

    if (existingIndex >= 0) entries.splice(existingIndex, 1);
    if (entry.draft) {
      entries = entries.map((saved) => saved.draft === true ? { ...saved, draft: false } : saved);
    }
    entries.unshift(entry);
    await this.storage.put('entries', entries.slice(0, 1000));
    return json({ ...journalPayload(entries), entry: organizeEntry(entry) }, existing ? 200 : 201);
  }
}

export const worker = {
  async fetch(request, env) {
    try {
      return await routeRequest(request, env);
    } catch (error) {
      console.error('Unhandled journal request error', error);
      const url = new URL(request.url);
      if (url.pathname.startsWith('/api/')) {
        return json({ error: 'The journal hit a server error. Please try again.' }, 500);
      }
      return new Response('The journal hit a server error.', { status: 500 });
    }
  },
};

export default worker;

async function routeRequest(request, env) {
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
}

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
    { authenticated: true, username: cleanUsername, encryptionSalt: payload.encryptionSalt },
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
  return entries.map(organizeEntry);
}

function organizeEntry(entry) {
  return {
    ...entry,
    day: entry.createdAt.slice(0, 10),
    month: new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(entry.createdAt)),
    timeAgo: relativeTime(entry.createdAt),
  };
}

function journalPayload(entries) {
  const draft = entries.find((entry) => entry.draft === true) || null;
  return {
    draft: draft ? organizeEntry(draft) : null,
    entries: organizeEntries(entries.filter((entry) => entry.draft !== true)),
  };
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
  return { salt: toBase64(salt), hash: await hashPassword(password, salt), iterations: PASSWORD_ITERATIONS, encryptionSalt: randomSalt() };
}

function randomSalt() {
  return toBase64(crypto.getRandomValues(new Uint8Array(16)));
}

async function verifyPassword(password, record) {
  const salt = fromBase64(record.salt);
  const hash = await hashPassword(password, salt, record.iterations);
  return constantTimeEqual(hash, record.hash);
}

async function hashPassword(password, salt, iterations = PASSWORD_ITERATIONS) {
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
:root {
  color-scheme: dark;
  --ink: #f3eee6;
  --muted: #aaa095;
  --card: rgba(25, 23, 21, .82);
  --line: rgba(255, 247, 235, .11);
  --accent: #d6a66a;
  --danger: #ff9b88;
  --shadow: 0 28px 90px rgba(0, 0, 0, .46);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    radial-gradient(circle at 16% -8%, rgba(139, 94, 48, .34), transparent 35%),
    radial-gradient(circle at 92% 20%, rgba(84, 58, 38, .18), transparent 30%),
    linear-gradient(145deg, #090908, #12100e 48%, #0a0908);
  color: var(--ink);
}
body:before {
  content: "";
  position: fixed;
  inset: 0;
  background-image: linear-gradient(rgba(214, 166, 106, .035) 1px, transparent 1px), linear-gradient(90deg, rgba(214, 166, 106, .035) 1px, transparent 1px);
  background-size: 42px 42px;
  mask-image: linear-gradient(to bottom, black, transparent 78%);
  pointer-events: none;
}
::selection { background: rgba(214, 166, 106, .32); }
.shell { width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 42px 0; }
.top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 36px; }
.brand { font-family: Georgia, serif; font-size: clamp(2rem, 5vw, 4.2rem); letter-spacing: -.06em; }
.tag { color: var(--muted); max-width: 420px; line-height: 1.6; }
.card { background: var(--card); backdrop-filter: blur(24px); border: 1px solid var(--line); border-radius: 32px; box-shadow: var(--shadow); }
.login { max-width: 460px; margin: 8vh auto; padding: 34px; }
.login h1 { font-family: Georgia, serif; font-size: 3.2rem; line-height: .95; margin: 0 0 14px; }
.field { display: grid; gap: 8px; margin: 18px 0; }
.field span { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .14em; }
input, textarea, button { font: inherit; }
input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 18px; background: rgba(6, 6, 5, .58); padding: 15px 16px; color: var(--ink); outline: none; transition: border-color .2s, box-shadow .2s, background .2s; }
input::placeholder, textarea::placeholder { color: #746d65; }
input:focus, textarea:focus { border-color: rgba(214, 166, 106, .6); background: rgba(9, 8, 7, .78); box-shadow: 0 0 0 4px rgba(214, 166, 106, .1); }
textarea { min-height: 260px; resize: vertical; line-height: 1.7; }
.button { border: 0; border-radius: 999px; background: #eee6da; color: #171411; padding: 13px 19px; cursor: pointer; box-shadow: 0 12px 30px rgba(0, 0, 0, .32); transition: transform .2s, background .2s, opacity .2s; }
.button:hover { transform: translateY(-1px); background: #fff9ef; }
.button:disabled { cursor: wait; opacity: .58; transform: none; }
.ghost { background: rgba(255, 255, 255, .025); color: var(--ink); border: 1px solid var(--line); box-shadow: none; }
.ghost:hover { background: rgba(255, 255, 255, .07); }
.app { display: none; grid-template-columns: minmax(0, 1fr) 360px; gap: 22px; }
.editor { padding: 24px; }
.editorbar { display: flex; justify-content: space-between; gap: 14px; align-items: center; margin-top: 14px; }
.hint, .error { color: var(--muted); font-size: .92rem; }
.error { min-height: 1.35em; color: var(--danger); }
.timeline { padding: 22px; max-height: 72vh; overflow: auto; scrollbar-color: #554534 transparent; }
.timeline h2 { font-family: Georgia, serif; font-size: 2rem; margin: 0 0 18px; }
.month { margin: 20px 0 10px; color: var(--accent); font-size: .76rem; text-transform: uppercase; letter-spacing: .18em; }
.entry { border-top: 1px solid var(--line); padding: 16px 0; }
.entry time { display: block; color: var(--muted); font-size: .86rem; margin-bottom: 8px; }
.entry p { white-space: pre-wrap; line-height: 1.65; margin: 0; }
.empty { text-align: center; padding: 42px 16px; color: var(--muted); }
.search { margin-bottom: 12px; }
.pill { display: inline-flex; gap: 8px; align-items: center; border: 1px solid var(--line); border-radius: 999px; padding: 9px 12px; color: var(--muted); background: rgba(255, 255, 255, .035); }
body:not(.writing) { background: #1d1d1d; }
body:not(.writing):before { display: none; }
body:not(.writing) .shell { width: 100%; padding: 0; }
.login { min-height: 100svh; max-width: 320px; margin: 0 auto; padding: 24px; display: flex; align-items: center; background: transparent; border: 0; border-radius: 0; box-shadow: none; backdrop-filter: none; }
#authForm { width: 100%; display: grid; }
.login .field { position: relative; margin: 0; }
.login .field span { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.login input { border: 0; border-bottom: 1px solid #363636; border-radius: 0; background: transparent; padding: 15px 0; color: #e6e6e6; font-size: .95rem; }
.login input:focus { border-color: #777; background: transparent; box-shadow: none; }
.login input::placeholder { color: #666; }
.login .button { justify-self: end; margin-top: 22px; padding: 8px 0; border-radius: 0; background: transparent; color: #999; box-shadow: none; font-size: .82rem; }
.login .button:hover { background: transparent; color: #eee; transform: none; }
.login .error { margin: 12px 0 0; min-height: 1.2em; font-size: .78rem; }
body.writing { background: #1d1d1d; }
body.writing:before { display: none; }
body.writing .shell { width: 100%; padding: 0; }
.write-page { position: relative; min-height: 100svh; background: #1d1d1d; }
.editing-state { position: absolute; top: 18px; right: 20px; display: flex; align-items: center; gap: 8px; color: #aaa; font-size: .86rem; }
.editing-state.error { color: var(--danger); }
.editing-mark { color: #d4d4d4; font-size: 1.15rem; line-height: 1; }
#entryText { display: block; width: min(1080px, calc(100% - 48px)); height: calc(100svh - 72px); min-height: 520px; margin: 0 auto; padding: 64px 0 80px; resize: none; overflow: hidden; border: 0; border-radius: 0; background: transparent; box-shadow: none; color: #e8e8e8; caret-color: #f5f5f5; font-size: clamp(1.05rem, 1.4vw, 1.28rem); font-weight: 400; line-height: 1.65; letter-spacing: -.01em; }
#entryText:focus { border: 0; background: transparent; box-shadow: none; }
#entryText::placeholder { color: #666; }
.editor-metrics { position: absolute; right: 0; bottom: 14px; left: 0; color: #999; text-align: center; font-size: .84rem; }
.archive { min-height: 100svh; width: min(1080px, calc(100% - 48px)); margin: 0 auto; padding: 96px 0 140px; border-top: 1px solid #333; }
.archive-head { display: flex; align-items: baseline; justify-content: space-between; gap: 24px; margin-bottom: 64px; }
.archive h2 { margin: 0; color: #e4e4e4; font-size: 1.1rem; font-weight: 500; }
.archive-account { display: flex; align-items: center; gap: 14px; color: #777; font-size: .8rem; }
.text-button { border: 0; padding: 0; background: none; color: #999; cursor: pointer; font: inherit; }
.text-button:hover { color: #eee; }
.day-group { margin-bottom: 58px; }
.day-heading { margin-bottom: 20px; color: #707070; font-size: .75rem; text-transform: uppercase; letter-spacing: .14em; }
.past-entry { padding: 0 0 32px; }
.past-entry + .past-entry { padding-top: 32px; border-top: 1px solid #303030; }
.past-entry time { display: block; margin-bottom: 10px; color: #686868; font-size: .76rem; }
.past-entry p { max-width: 860px; margin: 0; white-space: pre-wrap; color: #c9c9c9; font-size: 1rem; line-height: 1.75; }
.archive-empty { color: #666; font-size: .9rem; }
@media (max-width: 860px) {
  .top { align-items: flex-start; gap: 18px; flex-direction: column; }
  .app { grid-template-columns: 1fr; }
  .timeline { max-height: none; }
  .shell { padding-top: 24px; }
  body.writing .shell { padding-top: 0; }
  #entryText { width: calc(100% - 36px); padding-top: 58px; }
  .archive { width: calc(100% - 36px); padding-top: 72px; }
}
</style>
</head>
<body>
<main class="shell">
  <section id="login" class="card login">
    <form id="authForm" aria-label="Open journal">
      <label class="field"><span>Username</span><input name="username" autocomplete="username" placeholder="username" required minlength="3" /></label>
      <label class="field"><span>Password</span><input name="password" type="password" autocomplete="current-password" placeholder="password" required minlength="8" /></label>
      <button class="button" type="submit">Enter →</button>
      <p id="authError" class="error"></p>
    </form>
  </section>

  <section id="journal" style="display:none">
    <section class="write-page">
      <div class="editing-state" id="saveStatus"><span id="saveLabel">Editing</span><span class="editing-mark">✎</span></div>
      <textarea id="entryText" aria-label="Journal entry" autofocus maxlength="20000" placeholder="Start writing…"></textarea>
      <div class="editor-metrics" id="metrics">0 lines | 0 words | 0 chars</div>
    </section>
    <section class="archive" id="pastEntries">
      <header class="archive-head">
        <h2>Past journals</h2>
        <div class="archive-account"><span id="welcome"></span><button class="text-button" id="logout">Sign out</button></div>
      </header>
      <div id="entries"></div>
    </section>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
let allEntries = [];
let currentEntryId = makeEntryId();
let lastSavedText = '';
let saveTimer;
let journalKey = null;
const CLIENT_KDF_ITERATIONS = 250000;
const fmt = new Intl.DateTimeFormat(undefined,{dateStyle:'full',timeStyle:'short'});
async function api(path, options={}){
  const res=await fetch(path,{headers:{'content-type':'application/json'},...options});
  const raw=await res.text();
  let data={};
  if(raw){
    try{data=JSON.parse(raw)}
    catch{throw new Error(res.ok?'The server returned an unreadable response.':'The server had a problem ('+res.status+'). Please try again.')}
  }
  if(!res.ok) throw new Error(data.error||'Something went wrong. Please try again.');
  return data;
}
function makeEntryId(){return self.crypto&&crypto.randomUUID?crypto.randomUUID():'entry-'+Date.now()+'-'+Math.random().toString(16).slice(2)}
function setSaveStatus(message,isError=false){$('saveLabel').textContent=message;$('saveStatus').classList.toggle('error',isError)}
function showApp(username){document.body.classList.add('writing');$('login').style.display='none';$('journal').style.display='block';$('welcome').textContent=username;loadEntries()}
function showLogin(){journalKey=null;document.body.classList.remove('writing');$('login').style.display='block';$('journal').style.display='none';setTimeout(()=>document.querySelector('[name="username"]').focus(),0)}
$('authForm').addEventListener('submit',async(e)=>{e.preventDefault();$('authError').textContent='';const form=e.currentTarget;const button=form.querySelector('button');const label=button.textContent;button.disabled=true;button.textContent='Unlocking…';const credentials=Object.fromEntries(new FormData(form));try{const data=await api('/api/auth',{method:'POST',body:JSON.stringify(credentials)});await unlockJournal(credentials.password,data.encryptionSalt);form.elements.password.value='';showApp(data.username)}catch(err){journalKey=null;$('authError').textContent=err.message}finally{button.disabled=false;button.textContent=label}});
$('entryText').addEventListener('input',()=>{updateEditor();clearTimeout(saveTimer);setSaveStatus('Editing');saveTimer=setTimeout(()=>persistEntry(false),850)});
$('logout').addEventListener('click',async()=>{clearTimeout(saveTimer);try{await persistEntry(true);await api('/api/logout',{method:'POST'});$('entryText').value='';lastSavedText='';currentEntryId=makeEntryId();journalKey=null;showLogin()}catch(err){setSaveStatus(err.message,true)}});
async function loadEntries(){try{const data=await api('/api/entries');const legacy=[...(data.entries||[]),...(data.draft?[data.draft]:[])].filter(entry=>typeof entry.text==='string'&&!entry.ciphertext);if(legacy.length){setSaveStatus('Encrypting older entries…');await migrateLegacyEntries(legacy)}const decoded=await decryptPayload(data);allEntries=decoded.entries||[];if(decoded.draft){currentEntryId=decoded.draft.id;$('entryText').value=decoded.draft.text;lastSavedText=decoded.draft.text}else{currentEntryId=makeEntryId();lastSavedText=''}renderEntries();updateEditor();setSaveStatus('Editing');requestAnimationFrame(()=>$('entryText').focus())}catch(err){setSaveStatus('Could not decrypt this journal',true)}}
async function persistEntry(finalize=false,useBeacon=false){
  const text=$('entryText').value;
  if(!finalize&&text===lastSavedText)return;
  if(!text.trim()&&!lastSavedText){setSaveStatus('Editing');return;}
  const encrypted=text.trim()?await encryptText(text):{};
  const payload={id:currentEntryId,...encrypted,finalize,discard:!text.trim(),localTimeHint:fmt.format(new Date())};
  if(useBeacon&&navigator.sendBeacon){navigator.sendBeacon('/api/entries',new Blob([JSON.stringify(payload)],{type:'application/json'}));return;}
  setSaveStatus(finalize?'Organizing…':'Saving…');
  try{const data=await api('/api/entries',{method:'POST',body:JSON.stringify(payload)});const decoded=await decryptPayload(data);allEntries=decoded.entries||[];if(decoded.entry)currentEntryId=decoded.entry.id;lastSavedText=text.trim()?text:'';renderEntries();setSaveStatus(finalize?'Organized':'Saved')}catch(err){setSaveStatus(err.message,true);throw err}
}
async function unlockJournal(password,salt){if(!salt)throw new Error('This journal is missing its encryption salt.');const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);journalKey=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:base64ToBytes(salt),iterations:CLIENT_KDF_ITERATIONS},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function encryptText(text){if(!journalKey)throw new Error('Unlock the journal before writing.');const iv=crypto.getRandomValues(new Uint8Array(12));const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},journalKey,new TextEncoder().encode(text));return{encryptionVersion:1,iv:bytesToBase64(iv),ciphertext:bytesToBase64(new Uint8Array(ciphertext)),plaintextLength:text.length}}
async function decryptEntry(entry){if(typeof entry.text==='string'&&!entry.ciphertext)return entry;if(entry.encryptionVersion!==1||!entry.iv||!entry.ciphertext)throw new Error('Unsupported encrypted entry.');const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:base64ToBytes(entry.iv)},journalKey,base64ToBytes(entry.ciphertext));return{...entry,text:new TextDecoder().decode(plaintext)}}
async function decryptPayload(data){return{...data,entries:await Promise.all((data.entries||[]).map(decryptEntry)),draft:data.draft?await decryptEntry(data.draft):null,entry:data.entry?await decryptEntry(data.entry):null}}
async function migrateLegacyEntries(entries){for(const entry of entries){const encrypted=await encryptText(entry.text);await api('/api/entries',{method:'POST',body:JSON.stringify({id:entry.id,...encrypted,finalize:entry.draft!==true,localTimeHint:entry.localTimeHint})})}}
function bytesToBase64(bytes){let value='';for(const byte of bytes)value+=String.fromCharCode(byte);return btoa(value)}
function base64ToBytes(value){return Uint8Array.from(atob(value),char=>char.charCodeAt(0))}
function updateEditor(){const text=$('entryText').value;const lines=text?text.split('\\n').length:0;const words=(text.trim().match(/\\S+/g)||[]).length;$('metrics').textContent=lines+' lines | '+words+' words | '+text.length+' chars';const editor=$('entryText');editor.style.height='auto';editor.style.height=Math.max(window.innerHeight-72,editor.scrollHeight)+'px'}
function dayLabel(iso){const date=new Date(iso);const today=new Date();const a=new Date(today.getFullYear(),today.getMonth(),today.getDate());const b=new Date(date.getFullYear(),date.getMonth(),date.getDate());const days=Math.round((a-b)/86400000);if(days===0)return'Today';if(days===1)return'Yesterday';if(days>1&&days<7)return new Intl.DateTimeFormat(undefined,{weekday:'long'}).format(date);return new Intl.DateTimeFormat(undefined,{month:'long',day:'numeric',year:'numeric'}).format(date)}
function renderEntries(){if(!allEntries.length){$('entries').innerHTML='<div class="archive-empty">Your finished entries will appear here when you leave.</div>';return}let html='';let day='';for(const entry of allEntries){const label=dayLabel(entry.createdAt);if(label!==day){if(day)html+='</section>';day=label;html+='<section class="day-group"><div class="day-heading">'+escapeHtml(label)+'</div>'}html+='<article class="past-entry"><time>'+fmt.format(new Date(entry.createdAt))+' · '+entry.timeAgo+'</time><p>'+escapeHtml(entry.text)+'</p></article>'}if(day)html+='</section>';$('entries').innerHTML=html}
function escapeHtml(value){return value.replace(/[&<>"]/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
window.addEventListener('resize',updateEditor);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden'&&document.body.classList.contains('writing'))persistEntry(true,true)});
window.addEventListener('pagehide',()=>{clearTimeout(saveTimer);if(document.body.classList.contains('writing'))persistEntry(true,true)});
api('/api/session').then(data=>{if(data.username)$('authForm').elements.username.value=data.username;showLogin()}).catch(showLogin);
</script>
</body>
</html>`;
}
