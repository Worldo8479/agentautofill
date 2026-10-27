import { randomBytes, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Vault } from './vault.js';

const derive = promisify(scrypt);
const hash = value => createHash('sha256').update(value).digest('hex');
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
export class AccountError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const check = (condition, status, message) => { if (!condition) throw new AccountError(status, message); };
const normalizeEmail = email => typeof email === 'string' ? email.trim().toLowerCase() : '';
const passwordHash = (password, salt) => derive(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

export class AccountStore {
  constructor({ directory, legacyPath, now = () => Date.now() }) {
    this.now = now;
    this.legacyPath = legacyPath;
    this.sessions = new Map();
    this.databasePath = join(directory, 'accounts.enc');
    const keyPath = join(directory, 'account-key');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (!existsSync(keyPath)) {
      if (existsSync(this.databasePath)) throw new Error('The account encryption key is missing. Restore account-key from your backup.');
      writeFileSync(keyPath, randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
    }
    this.database = new Vault(this.databasePath);
    this.database.unlock(readFileSync(keyPath, 'utf8').trim(), !this.database.exists);
    const data = this.database.data;
    data.accounts ??= [];
    data.passes ??= [];
    this.passes = new Map(data.passes.map(pass => [pass.id, pass]));
    // A process interruption must never make an in-flight capability replayable.
    for (const pass of this.passes.values()) if (['validating', 'running'].includes(pass.status)) pass.status = 'failed';
    this.save();
  }
  get accounts() { return this.database.data.accounts; }
  get legacyAvailable() { return !!this.legacyPath && existsSync(this.legacyPath) && !this.database.data.legacyOwnerId; }
  publicUser(account) { return { id: account.id, name: account.name, email: account.email }; }
  save() { this.database.data.passes = [...this.passes.values()]; this.database.save(); }
  async signup({ name, email, password }) {
    email = normalizeEmail(email);
    check(typeof name === 'string' && name.trim().length > 0 && name.length <= 80, 400, 'Enter your name (up to 80 characters).');
    check(email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), 400, 'Enter a valid email address.');
    check(typeof password === 'string' && password.length >= 12 && password.length <= 1024, 400, 'Use a password of 12 to 1,024 characters.');
    const salt = randomBytes(32).toString('hex');
    const verifier = await passwordHash(password, salt);
    // Check after the asynchronous hash too, so concurrent signups cannot create duplicates.
    check(!this.accounts.some(account => account.email === email), 409, 'An account with this email already exists. Log in instead.');
    check(this.accounts.length < 100, 400, 'This local installation supports up to 100 accounts.');
    const account = { id: randomBytes(16).toString('hex'), name: name.trim(), email, passwordSalt: salt, passwordHash: verifier.toString('hex'), createdAt: new Date(this.now()).toISOString(), entries: [], activity: [] };
    verifier.fill(0);
    this.accounts.push(account);
    this.workspace(account).audit('Account created', 'Your private workspace is ready.');
    return account;
  }
  async login({ email, password }) {
    email = normalizeEmail(email);
    check(typeof password === 'string' && password.length > 0 && password.length <= 1024 && email.length <= 254, 401, 'Email or password is incorrect.');
    const account = this.accounts.find(item => item.email === email);
    // Perform the same expensive operation for unknown email addresses.
    const verifier = await passwordHash(password, account?.passwordSalt || '0'.repeat(64));
    const expected = Buffer.from(account?.passwordHash || '0'.repeat(128), 'hex');
    const valid = timingSafeEqual(verifier, expected);
    verifier.fill(0);
    check(account && valid, 401, 'Email or password is incorrect.');
    return account;
  }
  createSession(account) {
    this.pruneSessions();
    const existing = [...this.sessions.entries()].filter(([, session]) => session.accountId === account.id);
    if (existing.length >= 10) this.sessions.delete(existing[0][0]);
    const token = randomBytes(32).toString('base64url');
    const session = { accountId: account.id, csrf: randomBytes(32).toString('base64url'), expiresAt: this.now() + SESSION_MS };
    this.sessions.set(hash(token), session);
    return { token, ...session };
  }
  session(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
    const id = hash(token);
    const session = this.sessions.get(id);
    if (!session) return null;
    if (session.expiresAt <= this.now()) { this.sessions.delete(id); return null; }
    const account = this.accounts.find(item => item.id === session.accountId);
    return account ? { ...session, account } : null;
  }
  logout(token) { if (token) this.sessions.delete(hash(token)); }
  pruneSessions() { for (const [id, session] of this.sessions) if (session.expiresAt <= this.now()) this.sessions.delete(id); }
  workspace(account) {
    return {
      data: account,
      metadata: () => account.entries.map(({ values, ...entry }) => ({ ...entry, fields: Object.keys(values) })),
      audit: (action, detail) => {
        account.activity.unshift({ id: randomBytes(8).toString('hex'), action, detail, at: new Date(this.now()).toISOString() });
        account.activity = account.activity.slice(0, 100);
        this.save();
      },
    };
  }
  importLegacy(account, password) {
    check(this.legacyAvailable, 409, 'There is no unclaimed legacy vault to import.');
    const legacy = new Vault(this.legacyPath);
    try {
      try { legacy.unlock(password); } catch { throw new AccountError(400, 'The previous vault password is incorrect, or the file is damaged.'); }
      check(account.entries.length + legacy.data.entries.length <= 500, 400, 'Import would exceed the 500-item limit.');
      const imported = legacy.data.entries.map(entry => ({ ...entry, id: randomBytes(12).toString('hex') }));
      account.entries.push(...imported);
      this.database.data.legacyOwnerId = account.id;
      this.workspace(account).audit('Previous vault imported', `${imported.length} items imported. Original encrypted file preserved.`);
      return imported.length;
    } finally { legacy.lock(); }
  }
  close() { this.sessions.clear(); this.database.lock(); }
}
