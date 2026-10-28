import { createServer } from 'node:http';
import { randomBytes, randomInt, createHash, timingSafeEqual, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { lookup } from 'node:dns/promises';
import { AccountStore } from './accounts.js';
import { PrivateRunner } from './runner.js';
import { newRecipientKey, seal, unseal } from './envelope.js';

const publicDir = resolve(import.meta.dirname, '../public');
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => a.length === b.length && timingSafeEqual(a, b);
const fields = {
  login: ['username', 'password'],
  identity: ['firstName', 'lastName', 'email', 'phone'],
  address: ['fullName', 'address1', 'address2', 'city', 'region', 'postalCode', 'country'],
};
const MAX_EXPIRY_MINUTES = 30 * 24 * 60;
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const requireThat = (condition, message, status = 400) => { if (!condition) throw new HttpError(status, message); };
const text = (value, max = 200) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
function privateAddress(ip) {
  if (ip.includes(':')) return !/^2[0-9a-f]{3}:/i.test(ip) || /^2001:(db8|0):/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && [0, 168].includes(b)) || (a === 100 && b >= 64 && b <= 127) || a === 198;
}
async function validateTarget(raw, origin) {
  let url;
  try { url = new URL(raw); } catch { throw new HttpError(400, 'Enter a complete destination URL.'); }
  requireThat(!url.username && !url.password && !url.hash, 'URLs cannot contain credentials or fragments.');
  if (url.href === `${origin}/demo`) return { target: url.href };
  requireThat(url.protocol === 'https:' && (!url.port || url.port === '443'), 'Use an HTTPS destination, or the built-in local demo.');
  const answers = await lookup(url.hostname, { all: true }).catch(() => []);
  requireThat(answers.length && answers.every(answer => !privateAddress(answer.address)), 'Destination must resolve to a public website.');
  return { target: url.href, resolvedAddress: (answers.find(answer => answer.family === 4) || answers[0]).address };
}

export function createApp({ dataPath = resolve('.data/vault.enc'), runner, runnerFactory = () => new PrivateRunner(), now = () => Date.now() } = {}) {
  const store = new AccountStore({ directory: dirname(dataPath), legacyPath: dataPath, now });
  const passes = store.passes;
  const runners = new Map();
  const attempts = new Map();
  let closing = false;
  const runnerFor = accountId => {
    if (!runners.has(accountId)) runners.set(accountId, runner || runnerFactory());
    return runners.get(accountId);
  };
  const passState = pass => pass.status === 'ready' && pass.expiresAt <= now() ? 'expired' : pass.status;
  const passMetadata = pass => ({ id: pass.id, label: pass.label, entryId: pass.entryId, mode: pass.mode || 'private-browser', fields: pass.mappings.map(m => m.field), createdAt: pass.createdAt, expiresAt: pass.expiresAt, status: passState(pass) });
  function revokeFor(accountId, entryId) { for (const pass of passes.values()) if (pass.accountId === accountId && pass.entryId === entryId && ['ready', 'validating'].includes(pass.status)) pass.status = 'revoked'; }
  function rateLimit(key, limit) {
    const recent = (attempts.get(key) || []).filter(at => now() - at < 60000);
    requireThat(recent.length < limit, 'Too many attempts. Wait one minute.', 429);
    recent.push(now()); attempts.set(key, recent);
  }
  const maintenance = setInterval(() => {
    store.pruneSessions();
    for (const [key, recent] of attempts) if (!recent.some(at => now() - at < 60000)) attempts.delete(key);
    let changed = false;
    for (const [id, pass] of passes) if (now() - pass.expiresAt > 24 * 60 * 60 * 1000) { passes.delete(id); changed = true; }
    if (changed) store.save();
  }, 30000);
  maintenance.unref();
  // Cookies have no port scope, so name them per installation port to isolate local previews.
  const cookieName = () => `agentautofill_session_${server.address().port}`;
  const sessionToken = req => (req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${cookieName()}=`))?.slice(cookieName().length + 1);
  const setCookie = (res, token) => res.setHeader('Set-Cookie', `${cookieName()}=${token || ''}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${token ? 7 * 24 * 60 * 60 : 0}`);

  const server = createServer(async (req, res) => {
    const port = server.address().port;
    const permittedHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    const origin = `http://${req.headers.host}`;
    const reply = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      requireThat(permittedHosts.includes(req.headers.host), 'Invalid host.', 403);
      const url = new URL(req.url, origin);
      const path = url.pathname;
      requireThat(!req.headers.origin || req.headers.origin === origin, 'Cross-origin requests are not allowed.', 403);
      if (path.startsWith('/api/')) {
        let body = {};
        if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
          requireThat(req.headers['content-type']?.split(';')[0] === 'application/json', 'JSON is required.', 415);
          requireThat(!req.headers['content-length'] || Number(req.headers['content-length']) < 65536, 'Request too large.', 413);
          let raw = '';
          let size = 0;
          for await (const chunk of req) {
            size += chunk.length;
            if (size < 65536) raw += chunk;
          }
          requireThat(size < 65536, 'Request too large.', 413);
          try { body = raw ? JSON.parse(raw) : {}; } catch { throw new HttpError(400, 'Invalid JSON.'); }
          requireThat(body && typeof body === 'object' && !Array.isArray(body), 'Invalid request.');
        }
        requireThat(!closing, 'The server is restarting. Try again shortly.', 503);
        const token = sessionToken(req);
        const session = store.session(token);
        if (path === '/api/status' && req.method === 'GET') return reply(200, { initialized: store.accounts.length > 0, authentication: 'accounts' });
        if (path === '/api/auth/session' && req.method === 'GET') {
          if (!session && token) setCookie(res, null);
          return reply(200, { user: session ? store.publicUser(session.account) : null, csrf: session?.csrf ?? null, legacyAvailable: store.legacyAvailable });
        }
        if (['/api/auth/signup', '/api/auth/login'].includes(path) && req.method === 'POST') {
          requireThat(req.headers.origin === origin, 'Open the app to sign in.', 403);
          rateLimit(`auth:${req.socket.remoteAddress}`, 30);
          rateLimit(`email:${String(body.email || '').trim().toLowerCase()}`, 8);
          const account = path === '/api/auth/signup' ? await store.signup(body) : await store.login(body);
          requireThat(!closing, 'The server is restarting. Please log in again.', 503);
          store.logout(token);
          const next = store.createSession(account);
          setCookie(res, next.token);
          const recoveryCode = path.endsWith('signup') ? store.issueRecovery(account) : undefined;
          return reply(path.endsWith('signup') ? 201 : 200, { user: store.publicUser(account), csrf: next.csrf, legacyAvailable: store.legacyAvailable, recoveryCode });
        }
        if (path === '/api/auth/reset-password' && req.method === 'POST') {
          requireThat(req.headers.origin === origin, 'Open the app to reset your password.', 403);
          rateLimit(`reset:${req.socket.remoteAddress}`, 15);
          rateLimit(`reset-email:${String(body.email || '').trim().toLowerCase()}`, 5);
          const recovered = await store.resetPassword(body);
          await runners.get(recovered.id)?.closeAll().catch(() => {});
          if (session?.account.id === recovered.id) setCookie(res, null);
          return reply(200, { reset: true });
        }
        const submissionMatch = path.match(/^\/api\/forms\/([a-f0-9]{32})\/submit$/);
        if (submissionMatch && req.method === 'POST') {
          rateLimit(`submission:${req.socket.remoteAddress}`, 60);
          const pass = passes.get(submissionMatch[1]);
          requireThat(pass?.mode === 'encrypted-form' && passState(pass) === 'ready', 'This package is unavailable, expired, or already submitted.', 410);
          requireThat(typeof body.payload === 'string' && body.payload.length <= 60000 && equal(digest(body.payload), Buffer.from(pass.payloadHash, 'hex')), 'Invalid encrypted package.', 400);
          const owner = store.accounts.find(item => item.id === pass.accountId);
          requireThat(owner?.entries.some(item => item.id === pass.entryId), 'This package is unavailable.', 410);
          // No await between verification, reservation, and persistence: concurrent submissions cannot both proceed.
          pass.status = 'running'; store.save();
          let submitted;
          try {
            submitted = unseal(store.database.data.recipientPrivateKey, pass.id, body.payload);
            requireThat(submitted && typeof submitted === 'object' && !Array.isArray(submitted) && Object.keys(submitted).length === pass.mappings.length && pass.mappings.every(({ field }) => Object.hasOwn(submitted, field) && typeof submitted[field] === 'string'), 'Invalid encrypted package.');
            const receipt = { id: randomBytes(16).toString('hex'), passId: pass.id, receivedAt: now(), values: submitted };
            owner.submissions ??= [];
            owner.submissions.unshift(receipt);
            owner.submissions = owner.submissions.slice(0, 100);
            pass.status = 'used'; pass.payloadHash = '';
            store.workspace(owner).audit('Encrypted form submitted', `${pass.label} · ${pass.mappings.length} fields received. Receipt ${receipt.id}`);
            return reply(200, { status: 'accepted', receiptId: receipt.id, fieldsReceived: pass.mappings.length, message: 'The receiving server accepted and stored the submission encrypted at rest. No decrypted values are returned.' });
          } catch {
            pass.status = 'failed'; pass.payloadHash = '';
            store.save();
            throw new HttpError(422, 'Submission failed. This package is consumed. Ask the owner for a new package.');
          }
        }
        const agentMatch = path.match(/^\/api\/agent\/([a-f0-9]{32})\/execute$/);
        if (agentMatch && req.method === 'POST') {
          const pass = passes.get(agentMatch[1]);
          const account = pass && store.accounts.find(item => item.id === pass.accountId);
          requireThat(account && pass.mode !== 'encrypted-form' && passState(pass) === 'ready' && !closing, 'This pass is unavailable, expired, or already used.', 410);
          const vault = store.workspace(account);
          requireThat(typeof body.pin === 'string' && body.pin.length <= 64, 'A valid PIN is required.', 401);
          const candidate = digest(body.pin.replace(/[\s-]/g, ''));
          if (!equal(candidate, Buffer.from(pass.pinHash, 'hex'))) {
            pass.attempts++;
            if (pass.attempts >= 5) { pass.status = 'revoked'; vault.audit('Pass revoked', 'Five unsuccessful PIN attempts.'); }
            store.save();
            throw new HttpError(401, 'Incorrect PIN.');
          }
          const entry = vault.data.entries.find(item => item.id === pass.entryId);
          requireThat(entry, 'The vault item was removed.', 410);
          // A key has no destination. Reserve it while validating the URL supplied at use time.
          // Concurrent redemptions cannot pass this reservation, and validation errors are retryable.
          pass.status = 'validating'; store.save();
          let target, resolvedAddress;
          try {
            ({ target, resolvedAddress } = await validateTarget(body.target, origin));
            requireThat(pass.status === 'validating' && !closing && pass.expiresAt > now(), 'This pass is unavailable or expired.', 410);
            requireThat(vault.data.entries.includes(entry), 'This item changed. Ask the owner for a new pass.', 410);
            requireThat(entry.type !== 'login' || new URL(target).origin === entry.site, 'A login can only be filled on its saved website.');
          } catch (error) {
            if (pass.status === 'validating') pass.status = !closing ? 'ready' : 'failed';
            store.save();
            throw error;
          }
          // Consume before browser work. A failed fill still consumes the PIN.
          pass.status = 'running'; pass.pinHash = ''; store.save();
          const values = Object.fromEntries(pass.mappings.map(({ field }) => [field, entry.values[field]]));
          vault.audit('Pass redeemed', `${pass.label} · ${new URL(target).origin}`);
          try {
            const result = await runnerFor(account.id).fill({ target, mappings: pass.mappings, values, resolvedAddress });
            pass.status = 'used';
            vault.audit('Autofill completed', `${pass.label} · ${result.filled} fields`);
            return reply(200, { status: 'filled', fieldsFilled: result.filled, message: 'Filled in the owner’s private browser. The owner must review and submit. No values are returned.' });
          } catch {
            pass.status = 'failed';
            vault.audit('Autofill failed', pass.label);
            throw new HttpError(422, 'Private fill failed. The PIN is consumed. Ask the owner to check the destination and selectors and create a new pass.');
          } finally { for (const field of Object.keys(values)) values[field] = ''; }
        }
        requireThat(session, 'Log in to your account to continue.', 401);
        const account = session.account;
        const vault = store.workspace(account);
        if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
          requireThat(req.headers.origin === origin && typeof req.headers['x-csrf-token'] === 'string' && equal(digest(req.headers['x-csrf-token']), digest(session.csrf)), 'Refresh the app and try again.', 403);
        }
        if (path === '/api/vault' && req.method === 'GET') return reply(200, { entries: vault.metadata(), passes: [...passes.values()].filter(pass => pass.accountId === account.id).map(passMetadata).reverse(), activity: vault.data.activity, user: store.publicUser(account), legacyAvailable: store.legacyAvailable });
        if (path === '/api/auth/logout' && req.method === 'POST') { store.logout(token); setCookie(res, null); return reply(200, { loggedOut: true }); }
        if (path === '/api/account/recovery-code' && req.method === 'POST') {
          rateLimit(`recovery:${account.id}`, 5);
          try { await store.login({ email: account.email, password: body.password }); }
          catch { throw new HttpError(400, 'Your current password is incorrect.'); }
          requireThat(store.session(token), 'Log in again to continue.', 401);
          return reply(200, { recoveryCode: store.issueRecovery(account), user: store.publicUser(account) });
        }
        if (path === '/api/account/import-legacy' && req.method === 'POST') {
          rateLimit(`import:${account.id}`, 5);
          const imported = store.importLegacy(account, body.password);
          return reply(200, { imported, legacyAvailable: false });
        }
        if (path === '/api/entries' && req.method === 'POST') {
          requireThat(Object.hasOwn(fields, body.type) && text(body.label, 80), 'Choose an item type and a name.');
          requireThat(body.values && typeof body.values === 'object' && !Array.isArray(body.values), 'Add at least one field.');
          const prior = body.id ? vault.data.entries.find(entry => entry.id === body.id) : null;
          requireThat(!body.id || prior, 'Item not found.', 404);
          requireThat(!prior || prior.type === body.type, 'Item type cannot be changed.');
          const values = {};
          for (const field of fields[body.type]) {
            if (text(body.values[field], 2048)) values[field] = body.values[field];
            else if (prior?.values[field]) values[field] = prior.values[field];
          }
          requireThat(Object.keys(values).length > 0, 'Add at least one field.');
          let site = '';
          if (body.type === 'login') {
            try { const parsed = new URL(body.site); requireThat(parsed.protocol === 'https:' && !parsed.username && !parsed.password, 'Logins require an HTTPS website.'); site = parsed.origin; }
            catch { throw new HttpError(400, 'Add the HTTPS website this login belongs to.'); }
          }
          const entry = { id: prior?.id ?? randomBytes(12).toString('hex'), type: body.type, label: body.label.trim(), site, values, updatedAt: new Date(now()).toISOString() };
          if (prior) { revokeFor(account.id, prior.id); vault.data.entries[vault.data.entries.indexOf(prior)] = entry; }
          else { requireThat(vault.data.entries.length < 500, 'This vault is limited to 500 items.'); vault.data.entries.push(entry); }
          vault.audit(prior ? 'Item updated' : 'Item added', entry.label);
          return reply(200, { saved: true });
        }
        const itemMatch = path.match(/^\/api\/entries\/([a-f0-9]{24})$/);
        if (itemMatch && req.method === 'DELETE') {
          const entry = vault.data.entries.find(item => item.id === itemMatch[1]);
          requireThat(entry, 'Item not found.', 404);
          revokeFor(account.id, entry.id);
          vault.data.entries = vault.data.entries.filter(item => item.id !== entry.id);
          vault.audit('Item removed', entry.label);
          return reply(200, { deleted: true });
        }
        if (path === '/api/packages' && req.method === 'POST') {
          requireThat([...passes.values()].filter(pass => pass.accountId === account.id && ['ready', 'validating', 'running'].includes(passState(pass))).length < 200, 'Active key limit reached. Revoke unused keys first.');
          const entry = vault.data.entries.find(item => item.id === body.entryId);
          requireThat(entry, 'Select a vault item.');
          requireThat(Array.isArray(body.fields) && body.fields.length > 0 && body.fields.length <= 10 && new Set(body.fields).size === body.fields.length && body.fields.every(field => typeof field === 'string' && Object.hasOwn(entry.values, field)), 'Select valid fields to include.');
          const minutes = Number(body.minutes);
          requireThat(Number.isInteger(minutes) && minutes >= 5 && minutes <= MAX_EXPIRY_MINUTES, 'Choose an expiration between 5 minutes and 30 days.');
          store.database.data.recipientPrivateKey ??= newRecipientKey();
          const id = randomBytes(16).toString('hex');
          const payload = seal(createPublicKey(store.database.data.recipientPrivateKey), id, Object.fromEntries(body.fields.map(field => [field, entry.values[field]])));
          requireThat(payload.length <= 60000, 'This package is too large. Select fewer fields.');
          const pass = { id, accountId: account.id, entryId: entry.id, label: text(body.label, 80) ? body.label.trim() : entry.label, mode: 'encrypted-form', mappings: body.fields.map(field => ({ field })), payloadHash: digest(payload).toString('hex'), createdAt: now(), expiresAt: now() + minutes * 60000, status: 'ready' };
          passes.set(id, pass);
          vault.audit('Encrypted package created', `${pass.label} · agentautofill receiving form`);
          const agentUrl = `${origin}/submit/${id}`;
          const endpoint = `${origin}/api/forms/${id}/submit`;
          const prompt = `Submit this encrypted package unchanged to the agentautofill receiving form.\n\nForm: ${agentUrl}\nEndpoint: ${endpoint}\nExpires: ${new Date(pass.expiresAt).toISOString()}\n\nEncrypted package:\n${payload}\n\nOpen the form, paste the package, and click Submit encrypted package. Or POST JSON {"payload":"<the exact encrypted package above>"} to the endpoint with Content-Type: application/json. The receiving server decrypts only during submission and stores the submitted fields encrypted at rest. You receive a receipt and field count, never plaintext or a decryption key. Submit once; do not retry a consumed package. This package works only with this receiving form, not an arbitrary website. Localhost is reachable only on the owner's computer; use an authorized local tool if needed. Do not request keys or access the server's files, memory, account session, or stored submissions.`;
          return reply(201, { ...passMetadata(pass), payload, agentUrl, endpoint, prompt });
        }
        if (path === '/api/passes' && req.method === 'POST') {
          requireThat([...passes.values()].filter(pass => pass.accountId === account.id && ['ready', 'validating', 'running'].includes(passState(pass))).length < 200, 'Active key limit reached. Revoke unused keys first.');
          const entry = vault.data.entries.find(item => item.id === body.entryId);
          requireThat(entry, 'Select a vault item.');
          requireThat(Array.isArray(body.mappings) && body.mappings.length > 0 && body.mappings.length <= 10, 'Choose at least one field.');
          const mappings = body.mappings.map(m => {
            requireThat(m && Object.hasOwn(entry.values, m.field) && text(m.selector, 300), 'Each selected field needs a valid selector.');
            // Only CSS selectors, never Playwright pseudo-engines or arbitrary script.
            requireThat(!m.selector.includes('>>') && !/^[a-z_-][\w-]*=/i.test(m.selector), 'Use a CSS selector, such as #email.');
            return { field: m.field, selector: m.selector.trim() };
          });
          requireThat(new Set(mappings.map(m => m.field)).size === mappings.length && new Set(mappings.map(m => m.selector)).size === mappings.length, 'Each field and selector must be unique.');
          const minutes = Number(body.minutes);
          requireThat(Number.isInteger(minutes) && minutes >= 5 && minutes <= MAX_EXPIRY_MINUTES, 'Choose an expiration between 5 minutes and 30 days.');
          const pin = Array.from({ length: 4 }, () => String(randomInt(100000000)).padStart(8, '0')).join('');
          const id = randomBytes(16).toString('hex');
          const pass = { id, accountId: account.id, label: text(body.label, 80) ? body.label.trim() : entry.label, entryId: entry.id, mappings, pinHash: digest(pin).toString('hex'), attempts: 0, createdAt: now(), expiresAt: now() + minutes * 60000, status: 'ready' };
          passes.set(id, pass);
          vault.audit('Pass created', pass.label);
          const agentUrl = `${origin}/agent/${id}`;
          const endpoint = `${origin}/api/agent/${id}/execute`;
          const formattedPin = pin.match(/.{8}/g).join('-');
          const prompt = `Use this agentautofill autofill pass for one authorized operation.\n\nAgent page: ${agentUrl}\nOne-time PIN: ${formattedPin}\nAllowed fields: ${mappings.map(m => m.field).join(', ')}\nField selectors: ${JSON.stringify(mappings)}\nExpires: ${new Date(pass.expiresAt).toISOString()}\n\nThis key has no preset destination. Choose the page for the owner's task when using it. Open the agent page and enter the PIN and page URL, or POST JSON {"pin":"${pin}","target":"<page URL for this task>"} to ${endpoint} with Content-Type: application/json. Use a public HTTPS page or the built-in local demo at ${origin}/demo. Login items remain restricted to their saved website origin. Field selectors are preconfigured by the owner.\n\nThis triggers the fill in the owner's separate private browser. It returns only completion status and a field count. Do not retry a consumed pass. The owner reviews and submits the form manually.\n\nThis localhost address is reachable only from the owner's computer. If you run remotely, ask to run this request on that computer through an authorized local tool. Do not upload the vault or expose the owner app. Do not request, read, screenshot, log, or extract autofill values. This pass grants no general browser or shell access.`;
          return reply(201, { ...passMetadata(pass), pin: formattedPin, agentUrl, prompt });
        }
        const revokeMatch = path.match(/^\/api\/passes\/([a-f0-9]{32})\/revoke$/);
        if (revokeMatch && req.method === 'POST') {
          const pass = passes.get(revokeMatch[1]);
          requireThat(pass && pass.accountId === account.id && ['ready', 'validating'].includes(passState(pass)), 'This pass is no longer active.', 409);
          pass.status = 'revoked'; pass.pinHash = ''; vault.audit('Pass revoked', pass.label);
          return reply(200, { revoked: true });
        }
        throw new HttpError(404, 'Not found.');
      }
      requireThat(req.method === 'GET', 'Method not allowed.', 405);
      const routes = { '/': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css', '/agent.js': 'agent.js', '/submission.js': 'submission.js', '/demo': 'demo.html', '/demo.js': 'demo.js', '/favicon.svg': 'favicon.svg' };
      const file = /^\/submit\/[a-f0-9]{32}$/.test(path) ? 'submission.html' : /^\/agent\/[a-f0-9]{32}$/.test(path) ? 'agent.html' : routes[path];
      requireThat(file, 'Not found.', 404);
      const ext = file.split('.').pop();
      const mime = { html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' }[ext];
      const content = await readFile(resolve(publicDir, file));
      res.writeHead(200, { 'Content-Type': `${mime}; charset=utf-8` }); res.end(content);
    } catch (error) { reply(error.status ?? 500, { error: error.status ? error.message : 'Something went wrong. Please try again.' }); }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.on('close', () => { clearInterval(maintenance); });
  return { server, store, close: async () => {
    closing = true;
    clearInterval(maintenance);
    await Promise.allSettled([...new Set(runners.values())].map(browser => browser.closeAll()));
    await new Promise(resolve => server.close(resolve));
    store.close();
  } };

}
