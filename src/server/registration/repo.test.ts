import { randomBytes } from 'node:crypto';
import type { Pool, QueryResult } from 'pg';

import { encrypt } from './crypto.js';
import { __setPoolForTests } from './db.js';
import {
  deleteById,
  ensureSchema,
  findMatchingSecret,
  insertSecret,
  listByEmail,
} from './repo.js';

type QueryCall = { text: string; params?: ReadonlyArray<unknown> };

function makeMockPool(responder: (call: QueryCall) => QueryResult<Record<string, unknown>>): {
  pool: Pool;
  calls: QueryCall[];
  query: ReturnType<typeof vi.fn>;
} {
  const calls: QueryCall[] = [];
  const query = vi.fn(
    async (text: string, params?: ReadonlyArray<unknown>): Promise<QueryResult<Record<string, unknown>>> => {
      const call = { text, params };
      calls.push(call);
      return responder(call);
    },
  );
  const pool = { query } as unknown as Pool;
  return { pool, calls, query };
}

function emptyResult<T extends Record<string, unknown>>(): QueryResult<T> {
  return {
    rows: [] as T[],
    rowCount: 0,
    command: '',
    oid: 0,
    fields: [],
  };
}

describe('registration/repo', () => {
  const ORIG_ENV = { ...process.env };
  let restorePool: () => void = () => undefined;

  beforeEach(() => {
    process.env.SECRETS_ENC_KEY = randomBytes(32).toString('base64');
  });

  afterEach(() => {
    restorePool();
    process.env = { ...ORIG_ENV };
  });

  describe('ensureSchema', () => {
    it('issues a single CREATE TABLE / INDEX / EXTENSION batch', async () => {
      const { pool, calls } = makeMockPool(() => emptyResult());
      restorePool = __setPoolForTests(pool);

      await ensureSchema();

      expect(calls.length).toBe(1);
      const sql = calls[0].text;
      expect(sql).toMatch(/CREATE EXTENSION IF NOT EXISTS pgcrypto/);
      expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS slack_app_secrets/);
      expect(sql).toMatch(/CREATE INDEX IF NOT EXISTS idx_slack_app_secrets_email/);
      expect(calls[0].params).toBeUndefined();
    });
  });

  describe('insertSecret', () => {
    it('encrypts the plaintext and inserts ciphertext/iv/auth_tag/email', async () => {
      const { pool, calls } = makeMockPool(() => ({
        ...emptyResult(),
        rows: [{ id: 'abc-123' }],
        rowCount: 1,
      }));
      restorePool = __setPoolForTests(pool);

      const result = await insertSecret('plaintext-secret', 'user@example.com');

      expect(result).toEqual({ id: 'abc-123' });
      expect(calls.length).toBe(1);
      expect(calls[0].text).toMatch(/INSERT INTO slack_app_secrets/);
      expect(calls[0].text).toMatch(/RETURNING id/);
      const params = calls[0].params!;
      expect(params).toHaveLength(4);
      expect(Buffer.isBuffer(params[0])).toBe(true); // ciphertext
      expect(Buffer.isBuffer(params[1])).toBe(true); // iv
      expect((params[1] as Buffer).length).toBe(12);
      expect(Buffer.isBuffer(params[2])).toBe(true); // auth tag
      expect((params[2] as Buffer).length).toBe(16);
      expect(params[3]).toBe('user@example.com');
    });
  });

  describe('findMatchingSecret', () => {
    it('returns null when no rows match', async () => {
      const { pool, calls } = makeMockPool(() => emptyResult());
      restorePool = __setPoolForTests(pool);

      const result = await findMatchingSecret('any');
      expect(result).toBeNull();
      expect(calls.length).toBe(1);
      expect(calls[0].text).toMatch(/SELECT id, ciphertext, iv, auth_tag, registered_by_email/);
    });

    it('returns id+email and fires last_used_at update on match', async () => {
      const candidate = 'matching-secret';
      const { ciphertext, iv, authTag } = encrypt(candidate);
      const otherEnc = encrypt('different-secret');

      const { pool, calls, query } = makeMockPool((call) => {
        if (call.text.startsWith('UPDATE')) {
          return emptyResult();
        }
        return {
          ...emptyResult(),
          rows: [
            {
              id: 'row-1',
              ciphertext: otherEnc.ciphertext,
              iv: otherEnc.iv,
              auth_tag: otherEnc.authTag,
              registered_by_email: 'other@example.com',
            },
            {
              id: 'row-2',
              ciphertext,
              iv,
              auth_tag: authTag,
              registered_by_email: 'owner@example.com',
            },
          ],
          rowCount: 2,
        };
      });
      restorePool = __setPoolForTests(pool);

      const result = await findMatchingSecret(candidate);
      expect(result).toEqual({ id: 'row-2', registeredByEmail: 'owner@example.com' });

      // Allow microtask queue to flush the fire-and-forget UPDATE
      await new Promise((resolve) => setImmediate(resolve));

      const updateCalls = calls.filter((c) => c.text.startsWith('UPDATE'));
      expect(updateCalls.length).toBe(1);
      expect(updateCalls[0].text).toMatch(/last_used_at = now\(\)/);
      expect(updateCalls[0].params).toEqual(['row-2']);
      expect(query).toHaveBeenCalled();
    });

    it('skips rows that fail to decrypt', async () => {
      const candidate = 'matching-secret';

      const { pool } = makeMockPool((call) => {
        if (call.text.startsWith('UPDATE')) return emptyResult();
        return {
          ...emptyResult(),
          rows: [
            {
              id: 'bad-row',
              ciphertext: Buffer.from('garbage'),
              iv: Buffer.alloc(12),
              auth_tag: Buffer.alloc(16),
              registered_by_email: 'x@example.com',
            },
          ],
          rowCount: 1,
        };
      });
      restorePool = __setPoolForTests(pool);

      const result = await findMatchingSecret(candidate);
      expect(result).toBeNull();
    });
  });

  describe('listByEmail', () => {
    it('selects rows by email ordered by created_at desc', async () => {
      const now = new Date();
      const { pool, calls } = makeMockPool(() => ({
        ...emptyResult(),
        rows: [
          { id: 'a', created_at: now, last_used_at: null },
          { id: 'b', created_at: now, last_used_at: now },
        ],
        rowCount: 2,
      }));
      restorePool = __setPoolForTests(pool);

      const out = await listByEmail('user@example.com');

      expect(out).toEqual([
        { id: 'a', created_at: now, last_used_at: null },
        { id: 'b', created_at: now, last_used_at: now },
      ]);
      expect(calls.length).toBe(1);
      expect(calls[0].text).toMatch(/SELECT id, created_at, last_used_at/);
      expect(calls[0].text).toMatch(/WHERE registered_by_email = \$1/);
      expect(calls[0].text).toMatch(/ORDER BY created_at DESC/);
      expect(calls[0].params).toEqual(['user@example.com']);
    });
  });

  describe('deleteById', () => {
    it('returns true when a row is deleted (owner match)', async () => {
      const { pool, calls } = makeMockPool(() => ({
        ...emptyResult(),
        rowCount: 1,
      }));
      restorePool = __setPoolForTests(pool);

      const ok = await deleteById('row-1', 'owner@example.com');
      expect(ok).toBe(true);
      expect(calls[0].text).toMatch(/DELETE FROM slack_app_secrets/);
      expect(calls[0].text).toMatch(/WHERE id = \$1 AND registered_by_email = \$2/);
      expect(calls[0].params).toEqual(['row-1', 'owner@example.com']);
    });

    it('returns false when no row is deleted (not owner / not found)', async () => {
      const { pool } = makeMockPool(() => ({
        ...emptyResult(),
        rowCount: 0,
      }));
      restorePool = __setPoolForTests(pool);

      const ok = await deleteById('row-1', 'someone-else@example.com');
      expect(ok).toBe(false);
    });

    it('treats null rowCount as zero deletions', async () => {
      const { pool } = makeMockPool(() => ({
        ...emptyResult(),
        rowCount: null as unknown as number,
      }));
      restorePool = __setPoolForTests(pool);

      const ok = await deleteById('row-1', 'whoever@example.com');
      expect(ok).toBe(false);
    });
  });
});
