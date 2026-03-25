// A02: Cryptographic Failures — AES-256-GCM for PII encryption
const { createCipheriv, createDecipheriv, randomBytes } = require('crypto');

const ALG = 'aes-256-gcm';

function getKey() {
  const hex = process.env.AES_KEY;
  if (!hex || hex.length !== 64) throw new Error('AES_KEY must be 64 hex chars (32 bytes)');
  return Buffer.from(hex, 'hex');
}

function encryptField(plaintext) {
  if (!plaintext) return plaintext;
  const iv  = randomBytes(12);
  const cipher = createCipheriv(ALG, getKey(), iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, enc, tag].map((b) => b.toString('hex')).join(':');
}

function decryptField(ciphertext) {
  if (!ciphertext || !ciphertext.includes(':')) return ciphertext;
  try {
    const [ivHex, encHex, tagHex] = ciphertext.split(':');
    const decipher = createDecipheriv(ALG, getKey(), Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8');
  } catch (_) {
    return '[decryption error]';
  }
}

module.exports = { encryptField, decryptField };
