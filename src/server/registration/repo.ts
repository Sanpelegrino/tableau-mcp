import { timingSafeEqual } from 'node:crypto';

import { query } from './db.js';
import { decrypt, encrypt } from './crypto.js';

const SCHEMA_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS slack_app_secrets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ciphertext bytea NOT NULL,
  iv bytea NOT NULL,
  auth_tag bytea NOT NULL,
  registered_by_email text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

ALTER TABLE slack_app_secrets ADD COLUMN IF NOT EXISTS label text;

CREATE INDEX IF NOT EXISTS idx_slack_app_secrets_email
  ON slack_app_secrets(registered_by_email);
`;

export async function ensureSchema(): Promise<void> {
  await query(SCHEMA_SQL);
}

export async function countRegistered(): Promise<number> {
  const result = await query<{ count: string }>(
    `SELECT COUNT(*)::text AS count FROM slack_app_secrets`,
  );
  const row = result.rows[0];
  if (!row) return 0;
  const n = Number(row.count);
  return Number.isFinite(n) ? n : 0;
}

export async function insertSecret(
  plaintextSecret: string,
  registeredByEmail: string,
  label?: string,
): Promise<{ id: string }> {
  const { ciphertext, iv, authTag } = encrypt(plaintextSecret);
  const cleanLabel = label?.trim() ? label.trim().slice(0, 200) : null;
  const result = await query(
    `INSERT INTO slack_app_secrets (ciphertext, iv, auth_tag, registered_by_email, label)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id`,
    [ciphertext, iv, authTag, registeredByEmail, cleanLabel],
  );
  const row = result.rows[0] as { id: string };
  return { id: row.id };
}

export async function findMatchingSecret(
  candidatePlaintext: string,
): Promise<{ id: string; registeredByEmail: string } | null> {
  const result = await query(
    `SELECT id, ciphertext, iv, auth_tag, registered_by_email
     FROM slack_app_secrets`,
  );

  const candidateBuf = Buffer.from(candidatePlaintext, 'utf8');

  for (const raw of result.rows) {
    const row = raw as {
      id: string;
      ciphertext: Buffer;
      iv: Buffer;
      auth_tag: Buffer;
      registered_by_email: string;
    };
    let plaintext: string;
    try {
      plaintext = decrypt({
        ciphertext: row.ciphertext,
        iv: row.iv,
        authTag: row.auth_tag,
      });
    } catch {
      continue;
    }

    const storedBuf = Buffer.from(plaintext, 'utf8');
    if (storedBuf.length !== candidateBuf.length) continue;
    if (!timingSafeEqual(storedBuf, candidateBuf)) continue;

    // Fire-and-forget last_used_at update; ignore errors.
    void query(
      `UPDATE slack_app_secrets SET last_used_at = now() WHERE id = $1`,
      [row.id],
    ).catch(() => {
      /* swallow */
    });

    return { id: row.id, registeredByEmail: row.registered_by_email };
  }

  return null;
}

export async function listByEmail(
  email: string,
): Promise<Array<{ id: string; label: string | null; created_at: Date; last_used_at: Date | null }>> {
  const result = await query(
    `SELECT id, label, created_at, last_used_at
     FROM slack_app_secrets
     WHERE registered_by_email = $1
     ORDER BY created_at DESC`,
    [email],
  );
  return result.rows.map((raw) => {
    const row = raw as {
      id: string;
      label: string | null;
      created_at: Date;
      last_used_at: Date | null;
    };
    return {
      id: row.id,
      label: row.label,
      created_at: row.created_at,
      last_used_at: row.last_used_at,
    };
  });
}

export async function deleteById(
  id: string,
  requesterEmail: string,
): Promise<boolean> {
  const result = await query(
    `DELETE FROM slack_app_secrets
     WHERE id = $1 AND registered_by_email = $2`,
    [id, requesterEmail],
  );
  return (result.rowCount ?? 0) > 0;
}
