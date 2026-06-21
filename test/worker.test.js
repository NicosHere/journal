import assert from 'node:assert/strict';
import test from 'node:test';
import worker, { JournalRoom } from '../src/worker.js';

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
      const room = new JournalRoom({ storage: new MemoryStorage() });
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
  assert.match(html, /Organized moments/);
});

test('creates a durable-object user session and saves a timestamped entry', async () => {
  const bindings = env();
  const auth = await worker.fetch(new Request('https://journal.test/api/auth', {
    method: 'POST',
    body: JSON.stringify({ username: 'writer', password: 'beautiful-password' }),
  }), bindings);
  assert.equal(auth.status, 200);
  const cookie = auth.headers.get('set-cookie');
  assert.match(cookie, /journal_session=/);

  const save = await worker.fetch(new Request('https://journal.test/api/entries', {
    method: 'POST',
    headers: { cookie },
    body: JSON.stringify({ text: 'A small true sentence.' }),
  }), bindings);
  assert.equal(save.status, 201);
  const saved = await save.json();
  assert.equal(saved.entries[0].text, 'A small true sentence.');
  assert.match(saved.entries[0].createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(saved.entries[0].month, /\d{4}/);
});

test('rejects entry access without a session', async () => {
  const response = await worker.fetch(new Request('https://journal.test/api/entries'), env());
  assert.equal(response.status, 401);
});
