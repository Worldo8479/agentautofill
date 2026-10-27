import { createServer } from 'node:http';
import { randomBytes, randomInt, createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { lookup } from 'node:dns/promises';
import { Vault } from './vault.js';
import { PrivateRunner } from './runner.js';

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

export function createApp({ dataPath = resolve('.data/vault.enc'), runner = new PrivateRunner(), now = () => Date.now() } = {}) {
  const vault = new Vault(dataPath);
  const passes = new Map();
  let session = null;
  let lastActive = 0;
  let unlockAttempts = [];
  let closing = false;
  const passState = pass => pass.status === 'ready' && pass.expiresAt <= now() ? 'expired' : pass.status;
  const passMetadata = pass => ({ id: pass.id, label: pass.label, entryId: pass.entryId, fields: pass.mappings.map(m => m.field), createdAt: pass.createdAt, expiresAt: pass.expiresAt, status: passState(pass) });
  function revokeFor(entryId) { for (const pass of passes.values()) if (pass.entryId === entryId && ['ready', 'validating'].includes(pass.status)) pass.status = 'revoked'; }
  async function lock() {
    closing = true;
    session = null;
    for (const pass of passes.values()) if (['ready', 'validating'].includes(pass.status)) pass.status = 'revoked';
    vault.lock();
    try { await runner.closeAll(); } finally { closing = false; }
  }
  const maintenance = setInterval(() => {
    if (session && now() - lastActive > 30 * 60 * 1000) void lock();
    // Retain long-lived keys until their expiry, plus a day for viewing their final status.
    for (const [id, pass] of passes) if (now() - pass.expiresAt > 24 * 60 * 60 * 1000) passes.delete(id);
  }, 30000);
  maintenance.unref();

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
        if (path === '/api/status' && req.method === 'GET') return reply(200, { initialized: vault.exists });
        if (['/api/setup', '/api/unlock'].includes(path) && req.method === 'POST') {
          requireThat(req.headers.origin === origin, 'Open the owner app to unlock.', 403);
          requireThat(!closing, 'Vault is locking. Try again shortly.', 409);
          unlockAttempts = unlockAttempts.filter(at => now() - at < 60000);
          requireThat(unlockAttempts.length < 5, 'Too many attempts. Wait one minute.', 429);
          unlockAttempts.push(now());
          try { vault.unlock(body.password, path === '/api/setup'); } catch (error) { throw new HttpError(400, error.message); }
          session = randomBytes(32).toString('base64url'); lastActive = now();
          return reply(200, { token: session });
        }
        const agentMatch = path.match(/^\/api\/agent\/([a-f0-9]{32})\/execute$/);
        if (agentMatch && req.method === 'POST') {
          const pass = passes.get(agentMatch[1]);
          requireThat(pass && passState(pass) === 'ready' && vault.unlocked && !closing, 'This pass is unavailable, expired, or already used.', 410);
          requireThat(typeof body.pin === 'string' && body.pin.length <= 64, 'A valid PIN is required.', 401);
          const candidate = digest(body.pin.replace(/[\s-]/g, ''));
          if (!equal(candidate, pass.pinHash)) {
            pass.attempts++;
            if (pass.attempts >= 5) { pass.status = 'revoked'; vault.audit('Pass revoked', 'Five unsuccessful PIN attempts.'); }
            throw new HttpError(401, 'Incorrect PIN.');
          }
          const entry = vault.data.entries.find(item => item.id === pass.entryId);
          requireThat(entry, 'The vault item was removed.', 410);
          // A key has no destination. Reserve it while validating the URL supplied at use time.
          // Concurrent redemptions cannot pass this reservation, and validation errors are retryable.
          pass.status = 'validating';
          let target, resolvedAddress;
          try {
            ({ target, resolvedAddress } = await validateTarget(body.target, origin));
            requireThat(pass.status === 'validating' && vault.unlocked && !closing && pass.expiresAt > now(), 'This pass is unavailable or expired.', 410);
            requireThat(vault.data.entries.includes(entry), 'This item changed. Ask the owner for a new pass.', 410);
            requireThat(entry.type !== 'login' || new URL(target).origin === entry.site, 'A login can only be filled on its saved website.');
          } catch (error) {
            if (pass.status === 'validating') pass.status = vault.unlocked && !closing ? 'ready' : 'revoked';
            throw error;
          }
          // Consume before browser work. A failed fill still consumes the PIN.
          pass.status = 'running'; pass.pinHash.fill(0);
          const values = Object.fromEntries(pass.mappings.map(({ field }) => [field, entry.values[field]]));
          vault.audit('Pass redeemed', `${pass.label} · ${new URL(target).origin}`);
          try {
            const result = await runner.fill({ target, mappings: pass.mappings, values, resolvedAddress });
            pass.status = 'used';
            if (vault.unlocked) vault.audit('Autofill completed', `${pass.label} · ${result.filled} fields`);
            return reply(200, { status: 'filled', fieldsFilled: result.filled, message: 'Filled in the owner’s private browser. The owner must review and submit. No values are returned.' });
          } catch {
            pass.status = 'failed';
            if (vault.unlocked) vault.audit('Autofill failed', pass.label);
            throw new HttpError(422, 'Private fill failed. The PIN is consumed. Ask the owner to check the destination and selectors and create a new pass.');
          } finally { for (const field of Object.keys(values)) values[field] = ''; }
        }
        requireThat(session && req.headers.authorization && equal(digest(req.headers.authorization), digest(`Bearer ${session}`)), 'Unlock your vault to continue.', 401);
        requireThat(vault.unlocked && !closing, 'Vault is locked.', 401);
        lastActive = now();
        if (path === '/api/vault' && req.method === 'GET') return reply(200, { entries: vault.metadata(), passes: [...passes.values()].map(passMetadata).reverse(), activity: vault.data.activity });
        if (path === '/api/lock' && req.method === 'POST') { await lock(); return reply(200, { locked: true }); }
        if (path === '/api/entries' && req.method === 'POST') {
          requireThat(fields[body.type] && text(body.label, 80), 'Choose an item type and a name.');
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
          if (prior) { revokeFor(prior.id); vault.data.entries[vault.data.entries.indexOf(prior)] = entry; }
          else { requireThat(vault.data.entries.length < 500, 'This vault is limited to 500 items.'); vault.data.entries.push(entry); }
          vault.audit(prior ? 'Item updated' : 'Item added', entry.label);
          return reply(200, { saved: true });
        }
        const itemMatch = path.match(/^\/api\/entries\/([a-f0-9]{24})$/);
        if (itemMatch && req.method === 'DELETE') {
          const entry = vault.data.entries.find(item => item.id === itemMatch[1]);
          requireThat(entry, 'Item not found.', 404);
          revokeFor(entry.id);
          vault.data.entries = vault.data.entries.filter(item => item.id !== entry.id);
          vault.audit('Item removed', entry.label);
          return reply(200, { deleted: true });
        }
        if (path === '/api/passes' && req.method === 'POST') {
          requireThat(passes.size < 200, 'Pass limit reached. Restart the server to clear old passes.');
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
          const pass = { id, label: text(body.label, 80) ? body.label.trim() : entry.label, entryId: entry.id, mappings, pinHash: digest(pin), attempts: 0, createdAt: now(), expiresAt: now() + minutes * 60000, status: 'ready' };
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
          requireThat(pass && ['ready', 'validating'].includes(passState(pass)), 'This pass is no longer active.', 409);
          pass.status = 'revoked'; pass.pinHash.fill(0); vault.audit('Pass revoked', pass.label);
          return reply(200, { revoked: true });
        }
        throw new HttpError(404, 'Not found.');
      }
      requireThat(req.method === 'GET', 'Method not allowed.', 405);
      const routes = { '/': 'index.html', '/app.js': 'app.js', '/styles.css': 'styles.css', '/agent.js': 'agent.js', '/demo': 'demo.html', '/demo.js': 'demo.js', '/favicon.svg': 'favicon.svg' };
      const file = /^\/agent\/[a-f0-9]{32}$/.test(path) ? 'agent.html' : routes[path];
      requireThat(file, 'Not found.', 404);
      const ext = file.split('.').pop();
      const mime = { html: 'text/html', js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml' }[ext];
      const content = await readFile(resolve(publicDir, file));
      res.writeHead(200, { 'Content-Type': `${mime}; charset=utf-8` }); res.end(content);
    } catch (error) { reply(error.status ?? 500, { error: error.status ? error.message : 'Something went wrong. Please try again.' }); }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.on('close', () => { clearInterval(maintenance); void lock(); });
  return { server, vault, close: async () => { clearInterval(maintenance); await lock(); await new Promise(resolve => server.close(resolve)); } };
}
