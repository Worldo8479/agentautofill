import { randomBytes, generateKeyPairSync, publicEncrypt, privateDecrypt, createCipheriv, createDecipheriv, constants } from 'node:crypto';

const context = id => Buffer.from(`agentautofill:receiving-form:v1:${id}`);

export function newRecipientKey() {
  return generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  }).privateKey;
}

// Only the receiving server retains the private key. The agent transports this envelope unchanged.
export function seal(publicKey, id, values) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(context(id));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(values), 'utf8'), cipher.final()]);
    const wrappedKey = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: context(id) }, key);
    return Buffer.from(JSON.stringify({ v: 1, key: wrappedKey.toString('base64url'), iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), data: ciphertext.toString('base64url') })).toString('base64url');
  } finally { key.fill(0); }
}

export function unseal(privateKey, id, payload) {
  const envelope = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  if (envelope.v !== 1 || !['key', 'iv', 'tag', 'data'].every(field => typeof envelope[field] === 'string' && /^[A-Za-z0-9_-]+$/.test(envelope[field]))) throw new Error('Invalid envelope');
  const iv = Buffer.from(envelope.iv, 'base64url');
  const tag = Buffer.from(envelope.tag, 'base64url');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid envelope');
  const key = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: context(id) }, Buffer.from(envelope.key, 'base64url'));
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(context(id));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64url')), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } finally { key.fill(0); plaintext?.fill(0); }
}
