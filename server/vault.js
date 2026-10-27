import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, readFileSync, mkdirSync, writeFileSync, renameSync } from 'node:fs';
import { dirname } from 'node:path';

// The only persisted payload is authenticated ciphertext. The key never goes to disk.
export class Vault {
  constructor(path) { this.path = path; this.key = null; this.data = null; }
  get exists() { return existsSync(this.path); }
  get unlocked() { return !!this.key; }
  unlock(password, create = false) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('Use a master password of at least 12 characters.');
    if (create && this.exists) throw new Error('A vault already exists.');
    if (!create && !this.exists) throw new Error('Create your vault first.');
    const envelope = this.exists ? JSON.parse(readFileSync(this.path, 'utf8')) : null;
    const salt = envelope ? Buffer.from(envelope.salt, 'base64') : randomBytes(32);
    const key = scryptSync(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    let data;
    try {
      if (envelope) {
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
        decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
        data = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString());
      } else data = { entries: [], activity: [] };
    } catch { key.fill(0); throw new Error('The master password is incorrect, or the vault file is damaged.'); }
    this.key?.fill(0);
    this.key = key; this.salt = salt; this.data = data;
    if (!envelope) this.save();
  }
  save() {
    if (!this.key) throw new Error('Vault is locked.');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(this.data), 'utf8'), cipher.final()]);
    const envelope = { version: 1, salt: this.salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    writeFileSync(`${this.path}.tmp`, JSON.stringify(envelope), { mode: 0o600 });
    renameSync(`${this.path}.tmp`, this.path);
  }
  lock() { this.key?.fill(0); this.key = null; this.data = null; }
  metadata() { return this.data.entries.map(({ values, ...entry }) => ({ ...entry, fields: Object.keys(values) })); }
  audit(action, detail) {
    this.data.activity.unshift({ id: randomBytes(8).toString('hex'), action, detail, at: new Date().toISOString() });
    this.data.activity = this.data.activity.slice(0, 100);
    this.save();
  }
}
