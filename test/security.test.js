import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { createApp } from '../server/app.js';

const password = 'test-only-master-password-2026';
async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'agentautofill-test-'));
  let fills = 0;
  const runner = options.runner || { async fill({ mappings }) { fills++; return { filled: mappings.length }; }, async closeAll() {} };
  const app = createApp({ dataPath: join(dir, 'vault.enc'), runner, ...options });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  let token;
  async function request(path, body, { owner = true, method, headers = {} } = {}) {
    const response = await fetch(`${origin}${path}`, { method: method || (body === undefined ? 'GET' : 'POST'), headers: { Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(owner && token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json(), headers: response.headers };
  }
  const setup = await request('/api/setup', { password });
  assert.equal(setup.status, 200); token = setup.body.token;
  await request('/api/entries', { type: 'identity', label: 'Personal identity', values: { firstName: 'NeverReturnThisSecret', email: 'secret-value@example.com' } });
  const entry = (await request('/api/vault')).body.entries[0];
  async function grant(overrides = {}) {
    return request('/api/passes', { entryId: entry.id, minutes: 15, mappings: [{ field: 'firstName', selector: '#firstName' }], ...overrides });
  }
  t.after(async () => { await app.close(); await rm(dir, { recursive: true, force: true }); });
  return { app, request, grant, entry, origin, dir, fills: () => fills, setToken: next => { token = next; } };
}

test('encrypted persistence, metadata-only reads, and password protection survive restart', async t => {
  const f = await fixture(t);
  const disk = await readFile(join(f.dir, 'vault.enc'), 'utf8');
  assert.ok(!disk.includes('NeverReturnThisSecret'));
  assert.ok(!disk.includes('secret-value@example.com'));
  assert.ok(!disk.includes(password));
  assert.deepEqual(f.entry.fields, ['firstName', 'email']);
  assert.equal(f.entry.values, undefined);
  assert.equal((await f.request('/api/vault', undefined, { owner: false })).status, 401);
  await f.request('/api/lock', {});
  assert.equal((await f.request('/api/unlock', { password: 'incorrect-but-long-password' })).status, 400);
  const unlock = await f.request('/api/unlock', { password });
  f.setToken(unlock.body.token);
  assert.equal((await f.request('/api/vault')).body.entries.length, 1);
});

test('one-time pass is scoped, redacts secrets, and rejects concurrent replay', async t => {
  const f = await fixture(t);
  const pass = await f.grant();
  assert.equal(pass.status, 201);
  assert.match(pass.body.pin, /^\d{8}(?:-\d{8}){3}$/);
  assert.ok(pass.body.agentUrl.startsWith(`${f.origin}/agent/`));
  assert.equal(Object.hasOwn(pass.body, 'target'), false);
  assert.equal(pass.body.prompt.includes('\nDestination:'), false);
  assert.ok(pass.body.prompt.includes('"target":"<page URL for this task>"'));
  assert.ok(!JSON.stringify(pass.body).includes('NeverReturnThisSecret'));
  assert.ok(!JSON.stringify(pass.body).includes('secret-value@example.com'));
  const endpoint = `/api/agent/${pass.body.id}/execute`;
  const responses = await Promise.all([f.request(endpoint, { pin: pass.body.pin, target: `${f.origin}/demo` }, { owner: false }), f.request(endpoint, { pin: pass.body.pin, target: `${f.origin}/demo` }, { owner: false })]);
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 410]);
  assert.equal(f.fills(), 1);
  const success = responses.find(r => r.status === 200);
  assert.equal(success.body.fieldsFilled, 1);
  assert.ok(!JSON.stringify(responses).includes('NeverReturnThisSecret'));
  const metadata = (await f.request('/api/vault')).body;
  assert.equal(metadata.passes[0].pin, undefined);
  assert.ok(!JSON.stringify(metadata).includes(pass.body.pin));
});

test('keys need no destination; invalid use-time targets are rejected without consuming the PIN', async t => {
  let actualTarget;
  const f = await fixture(t, { runner: { async fill({ target, mappings }) { actualTarget = target; return { filled: mappings.length }; }, async closeAll() {} } });
  const pass = (await f.grant()).body;
  const endpoint = `/api/agent/${pass.id}/execute`;
  for (const target of [undefined, 'invalid', `${f.origin}/api/vault`, 'http://example.com', 'https://127.0.0.1']) {
    const result = await f.request(endpoint, { pin: pass.pin, target }, { owner: false });
    assert.equal(result.status, 400);
    assert.equal((await f.request('/api/vault')).body.passes[0].status, 'ready');
  }
  assert.equal((await f.request(endpoint, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 200);
  assert.equal(actualTarget, `${f.origin}/demo`);
  assert.equal((await f.request(endpoint, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
});

test('login and address keys can be created without a target; login origin binding remains enforced at use time', async t => {
  const f = await fixture(t);
  for (const type of ['login', 'address']) {
    await f.request('/api/entries', { type, label: `Test ${type}`, site: 'https://example.com', values: type === 'login' ? { username: 'demo', password: 'secret' } : { city: 'London' } });
    const entry = (await f.request('/api/vault')).body.entries.find(item => item.type === type);
    const result = await f.grant({ entryId: entry.id, mappings: [{ field: type === 'login' ? 'username' : 'city', selector: '#field' }] });
    assert.equal(result.status, 201);
    assert.equal(Object.hasOwn(result.body, 'target'), false);
    if (type === 'login') {
      const response = await f.request(`/api/agent/${result.body.id}/execute`, { pin: result.body.pin, target: `${f.origin}/demo` }, { owner: false });
      assert.equal(response.status, 400);
      assert.match(response.body.error, /saved website/);
    }
  }
  assert.equal(f.fills(), 0);
});

test('bad PIN attempts revoke a pass; expiry and explicit revoke prevent filling', async t => {
  let now = Date.now();
  const f = await fixture(t, { now: () => now });
  const pass = (await f.grant()).body;
  for (let i = 0; i < 5; i++) assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: 'wrong' }, { owner: false })).status, 401);
  assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  const expiring = (await f.grant()).body;
  now += 16 * 60000;
  assert.equal((await f.request(`/api/agent/${expiring.id}/execute`, { pin: expiring.pin }, { owner: false })).status, 410);
  const revoking = (await f.grant()).body;
  await f.request(`/api/passes/${revoking.id}/revoke`, {});
  assert.equal((await f.request(`/api/agent/${revoking.id}/execute`, { pin: revoking.pin }, { owner: false })).status, 410);
  assert.equal(f.fills(), 0);
});

test('expiry supports up to 30 days, survives daily cleanup, and expires at the exact deadline', async t => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  let now = Date.now();
  const f = await fixture(t, { now: () => now });
  const createdAt = now;
  for (const minutes of [4, 0, -1, 43201, 60.5, 'invalid']) {
    assert.equal((await f.grant({ minutes })).status, 400);
  }
  for (const minutes of [5, 90, 360, 720, 1440, 4320, 10080, 20160]) {
    const result = await f.grant({ minutes });
    assert.equal(result.status, 201);
    assert.equal(result.body.expiresAt, createdAt + minutes * 60000);
  }
  const usable = (await f.grant({ minutes: 43200 })).body;
  const expiring = (await f.grant({ minutes: 43200 })).body;
  assert.equal(usable.expiresAt, createdAt + 30 * 24 * 60 * 60000);
  assert.ok(usable.prompt.includes(new Date(usable.expiresAt).toISOString()));
  now += 29 * 24 * 60 * 60000;
  // Keep owner activity current to isolate retention from the separate inactivity lock.
  await f.request('/api/vault');
  t.mock.timers.tick(30000);
  const passes = (await f.request('/api/vault')).body.passes;
  assert.equal(passes.find(pass => pass.id === usable.id)?.status, 'ready');
  assert.equal((await f.request(`/api/agent/${usable.id}/execute`, { pin: usable.pin, target: `${f.origin}/demo` }, { owner: false })).status, 200);
  now = expiring.expiresAt;
  assert.equal((await f.request(`/api/agent/${expiring.id}/execute`, { pin: expiring.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  assert.equal(f.fills(), 1);
});

test('locking or editing revokes unused grants, and invalid scopes cannot be created', async t => {
  const f = await fixture(t);
  assert.equal((await f.grant({ mappings: [{ field: 'password', selector: '#firstName' }] })).status, 400);
  const pass = (await f.grant()).body;
  await f.request('/api/entries', { id: f.entry.id, type: 'identity', label: 'Updated', values: { firstName: 'Replacement' } });
  assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  const next = (await f.grant()).body;
  await f.request('/api/lock', {});
  assert.equal((await f.request(`/api/agent/${next.id}/execute`, { pin: next.pin }, { owner: false })).status, 410);
});

test('failed browser fills consume the PIN and never return underlying errors', async t => {
  const f = await fixture(t, { runner: { async fill() { throw new Error('Playwright included NeverReturnThisSecret'); }, async closeAll() {} } });
  const pass = (await f.grant()).body;
  const response = await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false });
  assert.equal(response.status, 422);
  assert.ok(!JSON.stringify(response.body).includes('NeverReturnThisSecret'));
  assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
});

test('host, origin, owner authorization, and input boundaries reject unauthorized calls', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/vault', undefined, { headers: { Origin: 'https://attacker.example' } })).status, 403);
  const hostStatus = await new Promise((resolve, reject) => {
    const req = httpRequest(`${f.origin}/api/status`, { headers: { Host: 'attacker.example' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.end();
  });
  assert.equal(hostStatus, 403);
  assert.equal((await f.request('/api/entries', { type: 'identity' }, { owner: false })).status, 401);
  assert.equal((await f.request('/api/entries', { type: 'not-a-type', label: 'x', values: {} })).status, 400);
  assert.equal((await f.request('/api/setup', { password })).status, 400);
  assert.equal((await f.request('/api/entries', { type: 'identity', label: 'x'.repeat(70000), values: {} })).status, 413);
});
