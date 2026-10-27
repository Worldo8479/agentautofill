import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpRequest } from 'node:http';
import { createApp } from '../server/app.js';
import { Vault } from '../server/vault.js';

const password = 'test-only-master-password-2026';
async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'agentautofill-test-'));
  let fills = 0;
  const runner = options.runner || { async fill({ mappings }) { fills++; return { filled: mappings.length }; }, async closeAll() {} };
  const app = createApp({ dataPath: join(dir, 'vault.enc'), runner, ...options });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${app.server.address().port}`;
  let cookie;
  let csrf;
  async function request(path, body, { owner = true, method, headers = {} } = {}) {
    const response = await fetch(`${origin}${path}`, { method: method || (body === undefined ? 'GET' : 'POST'), headers: { Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(owner && cookie ? { Cookie: cookie, 'X-CSRF-Token': csrf } : {}), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const result = { status: response.status, body: await response.json(), headers: response.headers };
    if (owner && response.headers.has('set-cookie')) cookie = response.headers.get('set-cookie').split(';')[0];
    if (owner && result.body.csrf) csrf = result.body.csrf;
    return result;
  }
  const setup = await request('/api/auth/signup', { name: 'Test Owner', email: 'owner@example.com', password });
  assert.equal(setup.status, 201);
  await request('/api/entries', { type: 'identity', label: 'Personal identity', values: { firstName: 'NeverReturnThisSecret', email: 'secret-value@example.com' } });
  const entry = (await request('/api/vault')).body.entries[0];
  async function grant(overrides = {}) {
    return request('/api/passes', { entryId: entry.id, minutes: 15, mappings: [{ field: 'firstName', selector: '#firstName' }], ...overrides });
  }
  t.after(async () => { await app.close(); await rm(dir, { recursive: true, force: true }); });
  return { app, request, grant, entry, origin, dir, fills: () => fills, credentials: () => ({ cookie, csrf }), signup: setup };
}

test('encrypted storage, metadata-only reads, and password protection survive logout', async t => {
  const f = await fixture(t);
  const disk = await readFile(join(f.dir, 'accounts.enc'), 'utf8');
  assert.ok(!disk.includes('NeverReturnThisSecret'));
  assert.ok(!disk.includes('secret-value@example.com'));
  assert.ok(!disk.includes(password));
  assert.deepEqual(f.entry.fields, ['firstName', 'email']);
  assert.equal(f.entry.values, undefined);
  assert.equal((await f.request('/api/vault', undefined, { owner: false })).status, 401);
  await f.request('/api/auth/logout', {});
  assert.equal((await f.request('/api/auth/login', { email: 'owner@example.com', password: 'incorrect-but-long-password' })).status, 401);
  const login = await f.request('/api/auth/login', { email: 'owner@example.com', password });
  assert.equal(login.status, 200);
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
  // Sessions expire separately from keys: log back in after advancing 29 days.
  await f.request('/api/auth/login', { email: 'owner@example.com', password });
  t.mock.timers.tick(30000);
  const passes = (await f.request('/api/vault')).body.passes;
  assert.equal(passes.find(pass => pass.id === usable.id)?.status, 'ready');
  assert.equal((await f.request(`/api/agent/${usable.id}/execute`, { pin: usable.pin, target: `${f.origin}/demo` }, { owner: false })).status, 200);
  now = expiring.expiresAt;
  assert.equal((await f.request(`/api/agent/${expiring.id}/execute`, { pin: expiring.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  assert.equal(f.fills(), 1);
});

test('editing revokes unused grants while account logout preserves authorized keys', async t => {
  const f = await fixture(t);
  assert.equal((await f.grant({ mappings: [{ field: 'password', selector: '#firstName' }] })).status, 400);
  const pass = (await f.grant()).body;
  await f.request('/api/entries', { id: f.entry.id, type: 'identity', label: 'Updated', values: { firstName: 'Replacement' } });
  assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  const next = (await f.grant()).body;
  await f.request('/api/auth/logout', {});
  assert.equal((await f.request(`/api/agent/${next.id}/execute`, { pin: next.pin, target: `${f.origin}/demo` }, { owner: false })).status, 200);
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
  assert.equal((await f.request('/api/auth/signup', { name: 'Duplicate', email: 'OWNER@example.com', password })).status, 409);
  assert.equal((await f.request('/api/entries', { type: 'identity', label: 'x'.repeat(70000), values: {} })).status, 413);
});

test('signup issues a cookie session, refresh restores it, and logout invalidates the old cookie', async t => {
  const f = await fixture(t);
  const cookie = f.signup.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Path=\/api/);
  assert.equal(f.signup.body.token, undefined);
  const session = await f.request('/api/auth/session');
  assert.equal(session.body.user.email, 'owner@example.com');
  assert.equal(session.body.csrf, f.credentials().csrf);
  assert.equal(session.body.user.passwordHash, undefined);
  const old = f.credentials();
  assert.equal((await f.request('/api/auth/logout', {})).status, 200);
  assert.equal((await f.request('/api/auth/session')).body.user, null);
  assert.equal((await f.request('/api/vault', undefined, { headers: { Cookie: old.cookie } })).status, 401);
  assert.equal((await f.request('/api/auth/login', { email: 'OWNER@EXAMPLE.COM', password })).status, 200);
  assert.notEqual(f.credentials().cookie, old.cookie);
  assert.equal((await f.request('/api/vault')).body.entries.length, 1);
});

test('account isolation prevents reading, editing, deleting, or revoking another account’s data', async t => {
  const f = await fixture(t);
  const firstPass = (await f.grant()).body;
  const first = f.credentials();
  const signup = await f.request('/api/auth/signup', { name: 'Second User', email: 'second@example.com', password: 'another-account-password' });
  assert.equal(signup.status, 201);
  const isolated = (await f.request('/api/vault')).body;
  assert.deepEqual(isolated.entries, []);
  assert.deepEqual(isolated.passes, []);
  assert.ok(!JSON.stringify(isolated).includes('Personal identity'));
  assert.equal((await f.request('/api/entries', { id: f.entry.id, type: 'identity', label: 'Stolen', values: { firstName: 'x' } })).status, 404);
  assert.equal((await f.request(`/api/entries/${f.entry.id}`, {}, { method: 'DELETE' })).status, 404);
  assert.equal((await f.grant()).status, 400);
  assert.equal((await f.request(`/api/passes/${firstPass.id}/revoke`, {})).status, 409);
  // Signup rotates only this browser session; signing into the original account restores its records.
  assert.equal((await f.request('/api/vault', undefined, { headers: { Cookie: first.cookie } })).status, 401);
  await f.request('/api/auth/login', { email: 'owner@example.com', password });
  assert.equal((await f.request('/api/vault')).body.entries[0].label, 'Personal identity');
});

test('CSRF, malformed credentials, duplicate signup, login throttling and session expiry are enforced', async t => {
  let now = Date.now();
  const f = await fixture(t, { now: () => now });
  assert.equal((await f.request('/api/entries', { type: 'identity', label: 'CSRF', values: { firstName: 'x' } }, { headers: { 'X-CSRF-Token': '' } })).status, 403);
  assert.equal((await f.request('/api/auth/logout', {}, { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await f.request('/api/auth/signup', { name: 'Bad', email: 'invalid', password })).status, 400);
  assert.equal((await f.request('/api/auth/signup', { name: 'Bad', email: 'bad@example.com', password: 'short' })).status, 400);
  const unknown = await f.request('/api/auth/login', { email: 'missing@example.com', password });
  const wrong = await f.request('/api/auth/login', { email: 'owner@example.com', password: 'wrong-but-long-enough' });
  assert.equal(unknown.status, 401);
  assert.deepEqual(unknown.body, wrong.body);
  for (let i = 0; i < 7; i++) await f.request('/api/auth/login', { email: 'missing@example.com', password });
  assert.equal((await f.request('/api/auth/login', { email: 'missing@example.com', password })).status, 429);
  now += 7 * 24 * 60 * 60000;
  assert.equal((await f.request('/api/auth/session')).body.user, null);
  assert.equal((await f.request('/api/vault')).status, 401);
});

test('legacy import requires its old password, preserves the original, and can be claimed only once', async t => {
  const f = await fixture(t);
  const legacyPath = join(f.dir, 'vault.enc');
  const legacy = new Vault(legacyPath);
  legacy.unlock('old-vault-password-only', true);
  legacy.data.entries.push({ id: 'legacy-id', label: 'Legacy item', type: 'identity', site: '', values: { firstName: 'LegacySecret' }, updatedAt: new Date().toISOString() });
  legacy.save(); legacy.lock();
  const before = await readFile(legacyPath);
  assert.equal((await f.request('/api/auth/session')).body.legacyAvailable, true);
  assert.equal((await f.request('/api/account/import-legacy', { password: 'wrong-old-password' })).status, 400);
  assert.equal((await f.request('/api/vault')).body.entries.length, 1);
  const imported = await f.request('/api/account/import-legacy', { password: 'old-vault-password-only' });
  assert.equal(imported.status, 200);
  assert.equal(imported.body.imported, 1);
  const entries = (await f.request('/api/vault')).body.entries;
  assert.equal(entries.length, 2);
  assert.equal(entries[1].label, 'Legacy item');
  assert.notEqual(entries[1].id, 'legacy-id');
  assert.deepEqual(await readFile(legacyPath), before);
  assert.equal((await f.request('/api/account/import-legacy', { password: 'old-vault-password-only' })).status, 409);
  await f.request('/api/auth/signup', { name: 'Other', email: 'other@example.com', password });
  assert.equal((await f.request('/api/account/import-legacy', { password: 'old-vault-password-only' })).status, 409);
});

test('accounts and one-use keys survive server restart without exposing passwords or plaintext data', async t => {
  const f = await fixture(t);
  const pass = (await f.grant({ minutes: 43200 })).body;
  const oldCookie = f.credentials().cookie;
  const disk = await readFile(join(f.dir, 'accounts.enc'), 'utf8');
  assert.ok(!disk.includes(password));
  assert.ok(!disk.includes('owner@example.com'));
  assert.ok(!disk.includes(pass.pin));
  assert.ok(!disk.includes(f.signup.body.recoveryCode));
  assert.ok(!disk.includes('NeverReturnThisSecret'));
  await f.app.close();
  let fills = 0;
  const restarted = createApp({ dataPath: join(f.dir, 'vault.enc'), runner: { async fill({ mappings }) { fills++; return { filled: mappings.length }; }, async closeAll() {} } });
  await new Promise(resolve => restarted.server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${restarted.server.address().port}`;
  try {
    const oldSession = await fetch(`${origin}/api/auth/session`, { headers: { Cookie: oldCookie } });
    assert.equal((await oldSession.json()).user, null);
    const response = await fetch(`${origin}/api/agent/${pass.id}/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin: pass.pin, target: `${origin}/demo` }) });
    assert.equal(response.status, 200);
    assert.equal(fills, 1);
    const login = await fetch(`${origin}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify({ email: 'owner@example.com', password }) });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    const metadata = await fetch(`${origin}/api/vault`, { headers: { Cookie: cookie } });
    assert.equal((await metadata.json()).passes[0].status, 'used');
  } finally { await restarted.close(); }
  const third = createApp({ dataPath: join(f.dir, 'vault.enc'), runner: { async fill() { throw new Error('Must not replay'); }, async closeAll() {} } });
  await new Promise(resolve => third.server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${third.server.address().port}/api/agent/${pass.id}/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin: pass.pin, target: `${origin}/demo` }) });
    assert.equal(response.status, 410);
    const thirdOrigin = `http://127.0.0.1:${third.server.address().port}`;
    const reset = await fetch(`${thirdOrigin}/api/auth/reset-password`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: thirdOrigin }, body: JSON.stringify({ email: 'owner@example.com', recoveryCode: f.signup.body.recoveryCode, password: 'recovered-after-restart' }) });
    assert.equal(reset.status, 200);
  } finally { await third.close(); }
  const fourth = createApp({ dataPath: join(f.dir, 'vault.enc') });
  try {
    await assert.rejects(fourth.store.resetPassword({ email: 'owner@example.com', recoveryCode: f.signup.body.recoveryCode, password: 'another-new-password' }), /already been used/);
    assert.equal((await fourth.store.login({ email: 'owner@example.com', password: 'recovered-after-restart' })).entries.length, 1);
  } finally { await fourth.close(); }
});

test('recovery codes reset once, preserve items, and invalidate sessions and unused keys', async t => {
  const f = await fixture(t);
  const code = f.signup.body.recoveryCode;
  assert.match(code, /^[A-F0-9]{8}(?:-[A-F0-9]{8}){7}$/);
  assert.equal(f.signup.body.user.recoveryReady, true);
  const originalSession = f.credentials();
  const pass = (await f.grant()).body;
  const second = await f.request('/api/auth/login', { email: 'owner@example.com', password }, { owner: false });
  const secondCookie = second.headers.get('set-cookie').split(';')[0];
  const other = await f.request('/api/auth/signup', { name: 'Other', email: 'other@example.com', password }, { owner: false });
  const otherCookie = other.headers.get('set-cookie').split(';')[0];
  const resetBody = { email: 'OWNER@example.com', recoveryCode: code.toLowerCase(), password: 'replacement-password-2026' };
  const results = await Promise.all([f.request('/api/auth/reset-password', resetBody, { owner: false }), f.request('/api/auth/reset-password', resetBody, { owner: false })]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 400]);
  for (const cookie of [originalSession.cookie, secondCookie]) assert.equal((await f.request('/api/vault', undefined, { headers: { Cookie: cookie } })).status, 401);
  assert.equal((await f.request('/api/vault', undefined, { headers: { Cookie: otherCookie } })).status, 200);
  assert.equal((await f.request(`/api/agent/${pass.id}/execute`, { pin: pass.pin, target: `${f.origin}/demo` }, { owner: false })).status, 410);
  assert.equal((await f.request('/api/auth/login', { email: 'owner@example.com', password })).status, 401);
  assert.equal((await f.request('/api/auth/login', { email: 'owner@example.com', password: resetBody.password })).status, 200);
  const vault = (await f.request('/api/vault')).body;
  assert.equal(vault.entries[0].id, f.entry.id);
  assert.equal(vault.user.recoveryReady, false);
  assert.ok(!JSON.stringify(vault).includes(code));
  assert.ok(!JSON.stringify(f.app.store.accounts).includes(code));
  assert.equal((await f.request('/api/auth/reset-password', resetBody)).status, 400);
});

test('recovery setup requires a session, CSRF, and password; rotation invalidates old codes', async t => {
  const f = await fixture(t);
  const oldCode = f.signup.body.recoveryCode;
  assert.equal((await f.request('/api/account/recovery-code', { password }, { owner: false })).status, 401);
  assert.equal((await f.request('/api/account/recovery-code', { password }, { headers: { 'X-CSRF-Token': 'wrong' } })).status, 403);
  assert.equal((await f.request('/api/account/recovery-code', { password: 'wrong' })).status, 400);
  const result = await f.request('/api/account/recovery-code', { password });
  assert.equal(result.status, 200);
  assert.notEqual(result.body.recoveryCode, oldCode);
  const reset = recoveryCode => ({ email: 'owner@example.com', recoveryCode, password: 'new-password-for-recovery' });
  assert.equal((await f.request('/api/auth/reset-password', reset(oldCode), { owner: false })).status, 400);
  assert.equal((await f.request('/api/auth/reset-password', reset(result.body.recoveryCode), { owner: false, headers: { Origin: 'https://example.com' } })).status, 403);
  assert.equal((await f.request('/api/auth/reset-password', { ...reset(result.body.recoveryCode), password: 'short' }, { owner: false })).status, 400);
  assert.equal((await f.request('/api/auth/reset-password', reset(result.body.recoveryCode), { owner: false })).status, 200);
});

test('invalid recovery attempts are generic, rate limited, and never consume a valid code', async t => {
  const f = await fixture(t);
  const body = { email: 'owner@example.com', recoveryCode: 'incorrect', password: 'replacement-password-2026' };
  const wrong = await f.request('/api/auth/reset-password', body, { owner: false });
  const unknown = await f.request('/api/auth/reset-password', { ...body, email: 'unknown@example.com' }, { owner: false });
  assert.equal(wrong.status, 400);
  assert.deepEqual(wrong.body, unknown.body);
  for (let i = 0; i < 4; i++) assert.equal((await f.request('/api/auth/reset-password', body, { owner: false })).status, 400);
  assert.equal((await f.request('/api/auth/reset-password', body, { owner: false })).status, 429);
  assert.equal((await f.request('/api/vault')).status, 200);
  assert.equal((await f.request('/api/vault')).body.user.recoveryReady, true);
});
