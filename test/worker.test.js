import assert from 'node:assert/strict';
import test from 'node:test';
import worker, { JournalRoomCore } from '../src/app.js';

class MemoryStorage {
  constructor() { this.store = new Map(); }
  async get(key) { return this.store.get(key); }
  async put(key, value) { this.store.set(key, value); }
  async delete(key) { this.store.delete(key); }
}

class MemoryDurableObjectNamespace {
  constructor() { this.objects = new Map(); }
  idFromName(name) { return name; }
  get(id) {
    if (!this.objects.has(id)) {
      const room = new JournalRoomCore(new MemoryStorage());
      this.objects.set(id, room);
    }
    return {
      fetch: (input, init) => this.objects.get(id).fetch(new Request(input, init)),
    };
  }
}

const env = () => ({ JOURNALS: new MemoryDurableObjectNamespace() });

test('serves the journal shell', async () => {
  const response = await worker.fetch(new Request('https://journal.test/'), env());
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /Quiet Journal/);
  assert.match(html, /Past journals/);
  assert.match(html, /color-scheme:\s*dark/);
  assert.match(html, /The server had a problem/);
  assert.match(html, /navigator\.sendBeacon/);
  assert.doesNotMatch(html, /id="save"/);
  assert.doesNotMatch(html, /private by username/);
  assert.match(html, /Enter →/);
  assert.match(html, /AES-GCM/);
  assert.match(html, /deriveKey/);
});

test('autosaves one draft and finalizes it without duplicates', async () => {
  const bindings = env();
  const auth = await worker.fetch(new Request('https://journal.test/api/auth', {
    method: 'POST',
    body: JSON.stringify({ username: 'writer', password: 'beautiful-password' }),
  }), bindings);
  assert.equal(auth.status, 200);
  const authData = await auth.clone().json();
  assert.match(authData.encryptionSalt, /^[A-Za-z0-9+/]+=*$/);
  const cookie = auth.headers.get('set-cookie');
  assert.match(cookie, /journal_session=/);

  const reauth = await worker.fetch(new Request('https://journal.test/api/auth', {
    method: 'POST',
    body: JSON.stringify({ username: 'writer', password: 'beautiful-password' }),
  }), bindings);
  assert.equal((await reauth.json()).encryptionSalt, authData.encryptionSalt);

  const autosave = await worker.fetch(new Request('https://journal.test/api/entries', {
    method: 'POST',
    headers: { cookie },
    body: JSON.stringify({
      id: 'entry-1',
      encryptionVersion: 1,
      ciphertext: 'ZW5jcnlwdGVkLWpvdXJuYWw=',
      iv: 'MTIzNDU2Nzg5MDEy',
      plaintextLength: 22,
      finalize: false,
    }),
  }), bindings);
  assert.equal(autosave.status, 201);
  const draft = await autosave.json();
  assert.equal(draft.draft.text, undefined);
  assert.equal(draft.draft.ciphertext, 'ZW5jcnlwdGVkLWpvdXJuYWw=');
  assert.equal(draft.entries.length, 0);

  const revisit = await worker.fetch(new Request('https://journal.test/api/entries', {
    headers: { cookie },
  }), bindings);
  assert.equal(revisit.status, 200);
  const saved = await revisit.json();
  assert.equal(saved.draft, null);
  assert.equal(saved.entries.length, 1);
  assert.equal(saved.entries[0].text, undefined);
  assert.equal(saved.entries[0].encryptionVersion, 1);
  assert.match(saved.entries[0].createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(saved.entries[0].month, /\d{4}/);
});

test('rejects plaintext journal writes', async () => {
  const bindings = env();
  const auth = await worker.fetch(new Request('https://journal.test/api/auth', {
    method: 'POST',
    body: JSON.stringify({ username: 'private-writer', password: 'beautiful-password' }),
  }), bindings);
  const response = await worker.fetch(new Request('https://journal.test/api/entries', {
    method: 'POST',
    headers: { cookie: auth.headers.get('set-cookie') },
    body: JSON.stringify({ text: 'This must never be stored as plaintext.' }),
  }), bindings);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'Entries must be encrypted before they are saved.' });
});

test('rejects entry access without a session', async () => {
  const response = await worker.fetch(new Request('https://journal.test/api/entries'), env());
  assert.equal(response.status, 401);
});

test('returns JSON when durable storage throws', async () => {
  const bindings = {
    JOURNALS: {
      idFromName: (name) => name,
      get: () => ({ fetch: async () => { throw new Error('storage unavailable'); } }),
    },
  };
  const response = await worker.fetch(new Request('https://journal.test/api/auth', {
    method: 'POST',
    body: JSON.stringify({ username: 'writer', password: 'beautiful-password' }),
  }), bindings);
  assert.equal(response.status, 500);
  assert.match(response.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await response.json(), { error: 'The journal hit a server error. Please try again.' });
});
