// Disposable UI fixture. Never uses the real .data vault.
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createApp } from '../server/app.js';
import { Vault } from '../server/vault.js';
import { randomBytes } from 'node:crypto';
const dir = await mkdtemp(join(tmpdir(), 'agentautofill-ui-'));
const dataPath = join(dir, 'vault.enc');
const vault = new Vault(dataPath);
vault.unlock('local-ui-test-only-password', true);
for (const entry of [
  { type: 'identity', label: 'Personal identity', site: '', values: { firstName: 'Alex', lastName: 'Morgan', email: 'alex@example.com', phone: '+44 7700 900123' } },
  { type: 'login', label: 'Example account', site: 'https://example.com', values: { username: 'demo@example.com', password: 'fictional-test-value-only' } },
  { type: 'address', label: 'Home address', site: '', values: { fullName: 'Alex Morgan', address1: '123 Example Street', city: 'London', postalCode: 'SW1A 1AA', country: 'United Kingdom' } },
]) vault.data.entries.push({ ...entry, id: randomBytes(12).toString('hex'), updatedAt: new Date().toISOString() });
vault.audit('Demo workspace created', 'Fictional data for UI testing only');
vault.lock();
const app = createApp({ dataPath });
const previewAccount = await app.store.signup({ name: 'Alex Morgan', email: 'alex@example.com', password: 'local-ui-test-only-password' });
app.store.importLegacy(previewAccount, 'local-ui-test-only-password');
app.server.listen(4318, '127.0.0.1', () => console.log('Disposable UI preview at http://127.0.0.1:4318'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await app.close(); await rm(dir, { recursive: true, force: true }); process.exit(0); });
