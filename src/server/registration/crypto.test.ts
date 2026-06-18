import { randomBytes } from 'node:crypto';

import { decrypt, encrypt } from './crypto.js';

describe('registration/crypto', () => {
  const ORIG_ENV = { ...process.env };

  beforeEach(() => {
    delete process.env.SECRETS_ENC_KEY;
  });

  afterEach(() => {
    process.env = { ...ORIG_ENV };
  });

  function setKey(): void {
    process.env.SECRETS_ENC_KEY = randomBytes(32).toString('base64');
  }

  it('round-trips encrypt -> decrypt', () => {
    setKey();
    const plaintext = 'xoxb-some-slack-app-secret-12345';
    const payload = encrypt(plaintext);

    expect(payload.ciphertext).toBeInstanceOf(Buffer);
    expect(payload.iv).toBeInstanceOf(Buffer);
    expect(payload.authTag).toBeInstanceOf(Buffer);
    expect(payload.iv.length).toBe(12);
    expect(payload.authTag.length).toBe(16);

    const recovered = decrypt(payload);
    expect(recovered).toBe(plaintext);
  });

  it('produces a unique IV per encryption call', () => {
    setKey();
    const a = encrypt('same-input');
    const b = encrypt('same-input');
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it('throws on tampered ciphertext (auth tag mismatch)', () => {
    setKey();
    const payload = encrypt('hello world');
    const tampered = Buffer.from(payload.ciphertext);
    tampered[0] = tampered[0] ^ 0xff;
    expect(() =>
      decrypt({ ciphertext: tampered, iv: payload.iv, authTag: payload.authTag }),
    ).toThrow(/Decryption failed/);
  });

  it('throws on tampered auth tag', () => {
    setKey();
    const payload = encrypt('hello world');
    const tampered = Buffer.from(payload.authTag);
    tampered[0] = tampered[0] ^ 0xff;
    expect(() =>
      decrypt({ ciphertext: payload.ciphertext, iv: payload.iv, authTag: tampered }),
    ).toThrow(/Decryption failed/);
  });

  it('throws when SECRETS_ENC_KEY is missing on first encrypt call', () => {
    expect(() => encrypt('something')).toThrow(/SECRETS_ENC_KEY is not set/);
  });

  it('throws when SECRETS_ENC_KEY is missing on first decrypt call', () => {
    expect(() =>
      decrypt({
        ciphertext: Buffer.alloc(1),
        iv: Buffer.alloc(12),
        authTag: Buffer.alloc(16),
      }),
    ).toThrow(/SECRETS_ENC_KEY is not set/);
  });

  it('throws when SECRETS_ENC_KEY decodes to wrong byte length', () => {
    process.env.SECRETS_ENC_KEY = Buffer.from('too-short').toString('base64');
    expect(() => encrypt('something')).toThrow(/must decode to 32 bytes/);
  });
});
