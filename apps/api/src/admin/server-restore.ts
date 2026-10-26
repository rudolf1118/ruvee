import { createHash, randomUUID } from 'node:crypto';
import {
  createReadStream,
  existsSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import pg from 'pg';
import { z } from 'zod';
import type { PgTools } from './pg-tools.js';

/**
 * Server backup and restore (backup-restore.md §3). Local tooling only: there is no remote
 * administration endpoint, and nothing here can decrypt anything (INV-18).
 *
 * Until D-29 (encryption at rest and key custody) is approved, a backup can be taken only of a
 * synthetic, task-owned test database, and a restore accepts only such backups.
 */

export const BACKUP_FORMAT = 'ruvee-server-backup/1';
export const GUARD_TABLE = 'ruvee_restore_guard';
/** Names of the throwaway databases the test suites create; nothing else may be backed up yet. */
const SYNTHETIC_DATABASE = /^ruvee_(it|e2e)_[0-9a-f]+$/;

export class RestoreError extends Error {
  constructor(
    readonly stage: 'verify' | 'prepare' | 'load' | 'migrate' | 'policy' | 'review' | 'complete',
    message: string,
  ) {
    super(message);
    this.name = 'RestoreError';
  }
}

export const sidecarSchema = z.strictObject({
  format: z.literal(BACKUP_FORMAT),
  /** True for every backup until D-29 is approved. */
  synthetic: z.literal(true),
  snapshotAt: z.iso.datetime({ offset: false }),
  dump: z.strictObject({
    file: z.string().regex(/^[A-Za-z0-9._-]{1,128}\.dump$/),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size: z.int().min(1),
  }),
  schema: z.strictObject({ migration: z.string().regex(/^[0-9]{14}_[a-z0-9_]{1,100}$/) }),
  config: z.strictObject({
    publicOrigin: z.string().max(256),
    sessionCookieSecure: z.enum(['true', 'false']),
    extensionOrigins: z.string().max(2000),
  }),
});
export type Sidecar = z.infer<typeof sidecarSchema>;

async function withClient<T>(url: string, run: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', () => {
        resolve(hash.digest('hex'));
      });
  });
}

const databaseName = (url: string) => decodeURIComponent(new URL(url).pathname.slice(1));

// ---- Backup ----

export interface BackupOptions {
  readonly databaseUrl: string;
  readonly outDir: string;
  readonly tools: PgTools;
  /** Required until D-29: backups of real data need approved encryption and key custody. */
  readonly syntheticTestOnly: boolean;
  readonly config: Sidecar['config'];
  readonly now?: () => Date;
}

/**
 * One `pg_dump` (one repeatable-read snapshot), written as `.partial` and renamed only after its
 * SHA-256 and the sidecar are written. The restore guard is never part of a backup.
 */
export async function createBackup(options: BackupOptions) {
  if (!options.syntheticTestOnly)
    throw new RestoreError(
      'verify',
      'backups of real data need an approved encryption and key-custody approach (D-29); ' +
        'only --synthetic-test-only is available',
    );
  const name = databaseName(options.databaseUrl);
  if (!SYNTHETIC_DATABASE.test(name))
    throw new RestoreError('verify', 'only a synthetic ruvee_it_* or ruvee_e2e_* database');
  const migration = await withClient(options.databaseUrl, async (c) => {
    const rows = await c.query<{ migration_name: string }>(
      `SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL
       ORDER BY migration_name DESC LIMIT 1`,
    );
    return rows.rows[0]?.migration_name;
  });
  if (!migration) throw new RestoreError('verify', 'the database has no applied migrations');
  const snapshotAt = (options.now ?? (() => new Date()))();
  const stamp = snapshotAt.toISOString().replace(/[-:.]/g, '');
  const file = `ruvee-${stamp}.dump`;
  const partial = join(options.outDir, `${file}.partial`);
  const dumpPath = join(options.outDir, file);
  if (existsSync(dumpPath) || existsSync(partial))
    throw new RestoreError('verify', 'a backup with that name already exists');
  await options.tools.dump(options.databaseUrl, partial, [GUARD_TABLE]);
  const sidecar: Sidecar = {
    format: BACKUP_FORMAT,
    synthetic: true,
    snapshotAt: snapshotAt.toISOString(),
    dump: { file, sha256: await sha256File(partial), size: statSync(partial).size },
    schema: { migration },
    config: options.config,
  };
  const sidecarPath = join(options.outDir, `${file}.json`);
  writeFileSync(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  renameSync(partial, dumpPath);
  return { dumpPath, sidecarPath, sidecar };
}

// ---- Restore ----

export interface RestoreOptions {
  readonly sidecarPath: string;
  readonly targetDatabaseUrl: string;
  readonly tools: PgTools;
  /** Applies the repository's migrations to the target (prisma migrate deploy). */
  readonly migrate: (url: string) => void | Promise<void>;
  /** The repository's migration directory names, oldest first. */
  readonly knownMigrations: readonly string[];
  /** For tests: stop after a state, as an interruption would. */
  readonly stopAfter?: 'prepare' | 'load' | 'migrate';
}

export interface RestoreResult {
  readonly restoreId: string;
  readonly snapshotAt: string;
  readonly removed: {
    readonly sessions: number;
    readonly pairings: number;
    readonly setupTokens: number;
  };
}

/** VERIFY: everything about the backup, before anything is created. */
export async function verifyBackup(sidecarPath: string, knownMigrations: readonly string[]) {
  let sidecar: Sidecar;
  try {
    sidecar = sidecarSchema.parse(JSON.parse(readFileSync(sidecarPath, 'utf8')));
  } catch {
    throw new RestoreError('verify', 'the sidecar is not a valid Ruvee backup description');
  }
  const dumpPath = join(dirname(sidecarPath), sidecar.dump.file);
  if (basename(dumpPath) !== sidecar.dump.file || !existsSync(dumpPath))
    throw new RestoreError('verify', 'the dump named by the sidecar is missing');
  if (
    statSync(dumpPath).size !== sidecar.dump.size ||
    (await sha256File(dumpPath)) !== sidecar.dump.sha256
  )
    throw new RestoreError('verify', 'the dump does not match its sidecar (size or SHA-256)');
  if (!knownMigrations.includes(sidecar.schema.migration))
    throw new RestoreError(
      'verify',
      'the backup is from a newer or unknown schema; use the same or a newer Ruvee',
    );
  return { sidecar, dumpPath };
}

/**
 * VERIFY → PREPARE → LOAD → MIGRATE → APPLY POLICY (backup-restore.md §3.5, §3.6). Ends in the
 * `review` state: the installation stays closed until `completeRestore`.
 */
export async function restoreBackup(
  options: RestoreOptions,
): Promise<RestoreResult | { stoppedAfter: string; restoreId: string }> {
  const { sidecar, dumpPath } = await verifyBackup(options.sidecarPath, options.knownMigrations);
  const restoreId = randomUUID();
  const url = options.targetDatabaseUrl;

  // PREPARE: an empty database only, and the guard before any restored row exists.
  await withClient(url, async (c) => {
    const tables = await c.query<{ n: string }>(
      `SELECT count(*) AS n FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')`,
    );
    if (Number(tables.rows[0]?.n) !== 0)
      throw new RestoreError(
        'prepare',
        'the target database is not empty; restore only into a new, empty database',
      );
    await c.query(`CREATE TABLE ${GUARD_TABLE} (
      id smallint PRIMARY KEY CHECK (id = 1),
      state text NOT NULL CHECK (state IN ('restoring', 'review', 'open')),
      restore_id uuid NOT NULL,
      snapshot_at timestamptz NOT NULL,
      dump_sha256 text NOT NULL,
      started_at timestamptz NOT NULL DEFAULT now(),
      review_completed_at timestamptz
    )`);
    await c.query(
      `INSERT INTO ${GUARD_TABLE} (id, state, restore_id, snapshot_at, dump_sha256) VALUES (1, 'restoring', $1, $2, $3)`,
      [restoreId, sidecar.snapshotAt, sidecar.dump.sha256],
    );
  });
  if (options.stopAfter === 'prepare') return { stoppedAfter: 'prepare', restoreId };

  try {
    await options.tools.restore(url, dumpPath);
  } catch (error) {
    throw new RestoreError('load', error instanceof Error ? error.message : 'pg_restore failed');
  }
  if (options.stopAfter === 'load') return { stoppedAfter: 'load', restoreId };
  try {
    await options.migrate(url);
  } catch (error) {
    throw new RestoreError('migrate', error instanceof Error ? error.message : 'migration failed');
  }
  if (options.stopAfter === 'migrate') return { stoppedAfter: 'migrate', restoreId };

  // APPLY POLICY: one transaction; structural checks first.
  return withClient(url, async (c) => {
    await c.query('BEGIN');
    try {
      const bad = await c.query<{ n: string }>(
        `SELECT count(*) AS n FROM vaults v
         WHERE v.current_seq <> COALESCE((SELECT max(seq) FROM vault_commits WHERE vault_id = v.id), 0)`,
      );
      const badManifests = await c.query<{ n: string }>(
        `SELECT count(*) AS n FROM vault_commits WHERE octet_length(manifest) <> 198`,
      );
      if (Number(bad.rows[0]?.n) !== 0 || Number(badManifests.rows[0]?.n) !== 0)
        throw new RestoreError('policy', 'the restored vault history is not consistent');
      const sessions = await c.query(
        `UPDATE sessions SET revoked_at = now(), revoke_reason = 'restored' WHERE revoked_at IS NULL`,
      );
      const pairings = await c.query('DELETE FROM pairings');
      const setupTokens = await c.query('DELETE FROM bootstrap_tokens WHERE used_at IS NULL');
      const account = await c.query<{ id: string }>('SELECT id FROM accounts LIMIT 1');
      await c.query(
        `INSERT INTO security_events (id, account_id, type, details, created_at)
         VALUES ($1, $2, 'server_restored', $3, now())`,
        [randomUUID(), account.rows[0]?.id ?? null, JSON.stringify({ restoreId })],
      );
      await c.query(
        `UPDATE ${GUARD_TABLE} SET state = 'review' WHERE id = 1 AND state = 'restoring'`,
      );
      await c.query('COMMIT');
      return {
        restoreId,
        snapshotAt: sidecar.snapshotAt,
        removed: {
          sessions: sessions.rowCount ?? 0,
          pairings: pairings.rowCount ?? 0,
          setupTokens: setupTokens.rowCount ?? 0,
        },
      };
    } catch (error) {
      await c.query('ROLLBACK');
      if (error instanceof RestoreError) throw error;
      throw new RestoreError(
        'policy',
        error instanceof Error ? error.message : 'restore policy failed',
      );
    }
  });
}

// ---- Review ----

export interface RestoreReview {
  readonly state: 'restoring' | 'review' | 'open';
  readonly restoreId: string;
  readonly snapshotAt: string;
  readonly dumpSha256: string;
  readonly account: { readonly username: string } | null;
  readonly devices: readonly {
    readonly id: string;
    readonly platform: string;
    readonly status: string;
    readonly enrolledAt: string | null;
    readonly lastSeenAt: string | null;
  }[];
  /** What becomes valid again when maintenance ends (backup-restore.md §3.6a). */
  readonly validAgain: {
    readonly passwordSetAt: string | null;
    readonly recoveryKitSetAt: string | null;
    readonly keysetVersion: number | null;
    readonly activeDevices: number;
  };
}

async function guard(c: pg.Client) {
  const exists = await c.query<{ t: string | null }>(
    `SELECT to_regclass('public.${GUARD_TABLE}') AS t`,
  );
  if (!exists.rows[0]?.t)
    throw new RestoreError('review', 'this database was not restored with ruvee-admin restore');
  const row = await c.query<{
    state: 'restoring' | 'review' | 'open';
    restore_id: string;
    snapshot_at: Date;
    dump_sha256: string;
  }>(`SELECT state, restore_id, snapshot_at, dump_sha256 FROM ${GUARD_TABLE} WHERE id = 1`);
  const g = row.rows[0];
  if (!g) throw new RestoreError('review', 'the restore guard is incomplete');
  return g;
}

const isoOrNull = (d: Date | null) => (d === null ? null : d.toISOString());

export async function reviewRestore(databaseUrl: string): Promise<RestoreReview> {
  return withClient(databaseUrl, async (c) => {
    const g = await guard(c);
    const account = await c.query<{ username_normalized: string }>(
      'SELECT username_normalized FROM accounts LIMIT 1',
    );
    const devices = await c.query<{
      id: string;
      platform: string;
      status: string;
      enrolled_at: Date | null;
      last_seen_at: Date | null;
    }>('SELECT id, platform, status, enrolled_at, last_seen_at FROM devices ORDER BY created_at');
    const password = await c.query<{ updated_at: Date }>(
      'SELECT updated_at FROM opaque_credentials LIMIT 1',
    );
    const keys = await c.query<{ updated_at: Date; keyset_version: string }>(
      'SELECT updated_at, keyset_version FROM account_keys LIMIT 1',
    );
    const kit = await c.query<{ created_at: Date }>(
      `SELECT created_at FROM security_events WHERE type IN ('recovery_key_rotated', 'recovery_completed', 'bootstrap_used')
       ORDER BY created_at DESC LIMIT 1`,
    );
    return {
      state: g.state,
      restoreId: g.restore_id,
      snapshotAt: g.snapshot_at.toISOString(),
      dumpSha256: g.dump_sha256,
      account: account.rows[0] ? { username: account.rows[0].username_normalized } : null,
      devices: devices.rows.map((d) => ({
        id: d.id,
        platform: d.platform,
        status: d.status,
        enrolledAt: isoOrNull(d.enrolled_at),
        lastSeenAt: isoOrNull(d.last_seen_at),
      })),
      validAgain: {
        passwordSetAt: isoOrNull(password.rows[0]?.updated_at ?? null),
        recoveryKitSetAt: isoOrNull(kit.rows[0]?.created_at ?? keys.rows[0]?.updated_at ?? null),
        keysetVersion: keys.rows[0] ? Number(keys.rows[0].keyset_version) : null,
        activeDevices: devices.rows.filter((d) => d.status === 'active').length,
      },
    };
  });
}

/** Revokes a device again during the review: authentication state only, nothing decrypted. */
export async function revokeDeviceInReview(
  databaseUrl: string,
  deviceId: string,
  reason: 'lost' | 'retired',
) {
  if (!z.uuid().safeParse(deviceId).success) throw new RestoreError('review', 'not a device id');
  return withClient(databaseUrl, async (c) => {
    const g = await guard(c);
    if (g.state !== 'review')
      throw new RestoreError(
        'review',
        'devices can be revoked only while the restore is in review',
      );
    await c.query('BEGIN');
    try {
      const device = await c.query<{ account_id: string }>(
        `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1 AND status <> 'revoked' RETURNING account_id`,
        [deviceId],
      );
      const accountId = device.rows[0]?.account_id;
      if (!accountId) throw new RestoreError('review', 'no such device, or it is already revoked');
      await c.query(
        `UPDATE sessions SET revoked_at = now(), revoke_reason = 'device_revoked' WHERE device_id = $1 AND revoked_at IS NULL`,
        [deviceId],
      );
      await c.query(
        `INSERT INTO security_events (id, account_id, device_id, type, details, created_at)
         VALUES ($1, $2, NULL, 'device_revoked', $3, now())`,
        [randomUUID(), accountId, JSON.stringify({ revokedDeviceId: deviceId, reason })],
      );
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    }
  });
}

/** OPEN: only from `review`, with the printed restore id and both acknowledgements. */
export async function completeRestore(
  databaseUrl: string,
  options: { restoreId: string; devicesReviewed: boolean; acceptRestoredCredentials: boolean },
) {
  if (!options.devicesReviewed || !options.acceptRestoredCredentials)
    throw new RestoreError(
      'complete',
      'review the devices and accept that the snapshot-time password, Recovery Kit and keys become valid again',
    );
  return withClient(databaseUrl, async (c) => {
    const g = await guard(c);
    if (g.state !== 'review')
      throw new RestoreError(
        'complete',
        g.state === 'open'
          ? 'already open'
          : 'the restore did not finish; start again into a new database',
      );
    if (g.restore_id !== options.restoreId)
      throw new RestoreError('complete', 'that is not this restore');
    await c.query('BEGIN');
    try {
      const account = await c.query<{ id: string }>('SELECT id FROM accounts LIMIT 1');
      await c.query(
        `INSERT INTO security_events (id, account_id, type, details, created_at)
         VALUES ($1, $2, 'restore_review_completed', $3, now())`,
        [
          randomUUID(),
          account.rows[0]?.id ?? null,
          JSON.stringify({ restoreId: options.restoreId }),
        ],
      );
      await c.query(
        `UPDATE ${GUARD_TABLE} SET state = 'open', review_completed_at = now() WHERE id = 1 AND state = 'review'`,
      );
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    }
  });
}

/** The repository's migrations, oldest first (their directory names). */
export function knownMigrations(migrationsDir: string): string[] {
  return readdirSync(migrationsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9]{14}_/.test(d.name))
    .map((d) => d.name)
    .sort();
}
