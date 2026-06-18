import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  type CipherGCM,
  type DecipherGCM,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

export type EncryptedPayload = {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
};

function loadKey(): Buffer {
  const raw = process.env.SECRETS_ENC_KEY;
  if (!raw) {
    throw new Error(
      'SECRETS_ENC_KEY is not set. Provide a base64-encoded 32-byte key.',
    );
  }
  let key: Buffer;
  try {
    key = Buffer.from(raw, 'base64');
  } catch {
    throw new Error('SECRETS_ENC_KEY is not valid base64.');
  }
  if (key.length !== KEY_BYTES) {
    throw new Error(
      `SECRETS_ENC_KEY must decode to ${KEY_BYTES} bytes; got ${key.length}.`,
    );
  }
  return key;
}

export function encrypt(plaintext: string): EncryptedPayload {
  const key = loadKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv) as CipherGCM;
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

export function decrypt(payload: EncryptedPayload): string {
  const { ciphertext, iv, authTag } = payload;
  if (iv.length !== IV_BYTES) {
    throw new Error(`Invalid IV length: expected ${IV_BYTES}, got ${iv.length}.`);
  }
  if (authTag.length !== AUTH_TAG_BYTES) {
    throw new Error(
      `Invalid auth tag length: expected ${AUTH_TAG_BYTES}, got ${authTag.length}.`,
    );
  }
  const key = loadKey();
  const decipher = createDecipheriv(ALGORITHM, key, iv) as DecipherGCM;
  decipher.setAuthTag(authTag);
  try {
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  } catch (err) {
    throw new Error(
      `Decryption failed (auth tag mismatch or corrupted ciphertext): ${(err as Error).message}`,
    );
  }
}
