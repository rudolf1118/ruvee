import { createHash, randomBytes } from 'node:crypto';

/**
 * Reopening codes (backup-restore.md §3.13, D-30 option B). A code is 32 random bytes, shown as
 * `RC1-` and unpadded base64url, printed only by `ruvee-admin` on the host. Only its SHA-256 is
 * stored, in the restore tool's own table, with the restore and the account it is for. It
 * authenticates a reopening together with the snapshot-time credentials; it is never key
 * material, and nothing decrypts with it.
 */
/** In the restore tool's control schema (restore-control.ts), out of reach of restored SQL. */
export const REOPEN_CODES_TABLE = 'ruvee_control.reopen_codes';
export const REOPEN_CODE_TTL_MS = 60 * 60_000;
/** Failed attempts (a wrong code, or the right one with wrong credentials) before revocation. */
export const REOPEN_MAX_FAILURES = 5;

const CODE = /^RC1-([A-Za-z0-9_-]{43})$/;

export function newReopenCode(): { code: string; hash: Buffer } {
  const bytes = randomBytes(32);
  return {
    code: `RC1-${bytes.toString('base64url')}`,
    hash: createHash('sha256').update(bytes).digest(),
  };
}

/** The stored hash of a code, or undefined if it is not a well-formed code. */
export function reopenCodeHash(code: string): Buffer | undefined {
  const body = CODE.exec(code)?.[1];
  if (!body) return undefined;
  const bytes = Buffer.from(body, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== body) return undefined;
  return createHash('sha256').update(bytes).digest();
}

/** The table `restore` creates next to the guard; never part of a backup. */
export const REOPEN_CODES_DDL = `CREATE TABLE ${REOPEN_CODES_TABLE} (
  id uuid PRIMARY KEY,
  restore_id uuid NOT NULL,
  account_id uuid NOT NULL,
  code_hash bytea NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  failed_attempts integer NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  consumed_at timestamptz,
  session_id uuid UNIQUE,
  via text CHECK (via IN ('password', 'recovery')),
  CHECK ((consumed_at IS NULL) = (session_id IS NULL) AND (session_id IS NULL) = (via IS NULL))
)`;
