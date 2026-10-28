import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey } from 'node:crypto';
import { newRecipientKey, seal, unseal } from '../server/envelope.js';

test('envelopes require the receiver private key, authenticate ciphertext and bind the receiving form', () => {
  const privateKey = newRecipientKey();
  const publicKey = createPublicKey(privateKey);
  const secret = { password: 'fictional-password-that-must-stay-encrypted', city: 'London' };
  const payload = seal(publicKey, 'form-a', secret);
  assert.notEqual(payload, seal(publicKey, 'form-a', secret));
  assert.deepEqual(unseal(privateKey, 'form-a', payload), secret);
  assert.throws(() => unseal(publicKey, 'form-a', payload));
  assert.throws(() => unseal(newRecipientKey(), 'form-a', payload));
  assert.throws(() => unseal(privateKey, 'form-b', payload));
  const envelope = JSON.parse(Buffer.from(payload, 'base64url').toString());
  assert.ok(!JSON.stringify(envelope).includes(secret.password));
  for (const field of ['key', 'iv', 'tag', 'data']) {
    const bytes = Buffer.from(envelope[field], 'base64url'); bytes[0] ^= 1;
    const tampered = Buffer.from(JSON.stringify({ ...envelope, [field]: bytes.toString('base64url') })).toString('base64url');
    assert.throws(() => unseal(privateKey, 'form-a', tampered));
  }
});
