import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { pipeline as streamPipeline, type Readable, type Writable } from 'node:stream';
import pg from 'pg';
import { z } from 'zod';
import {
  ageFailure,
  BACKUP_FORMAT,
  BackupError,
  backupDigest,
  checkRecipient,
  encryptBytesToFile,
  encryptToFile,
  fsyncPath,
  META_FORMAT,
  newBackupId,
  openBackup,
  openNewFile,
  Tap,
  verifyDump,
  type BackupMeta,
  type Manifest,
  type OpenOutput,
} from './backup-files.js';
import type { PgTools } from './pg-tools.js';

/**
 * Server backup and restore (backup-restore.md §3). Local tooling only: there is no remote
 * administration endpoint, and nothing here can decrypt the vault (INV-18). Backups are
 * encrypted with age to the configured recipient (D-29 option B, backup-files.ts); restoring
 * needs the owner's offline identity for that one run.
 *
 * Until M1 is accepted for real data (D-19, D-30), a backup can be taken only of a synthetic,
 * task-owned test database.
 */

export { BACKUP_FORMAT };
export const GUARD_TABLE = 'ruvee_restore_guard';
/** Names of the throwaway databases the test suites create; nothing else may be backed up yet. */
const SYNTHETIC_DATABASE = /^ruvee_(it|e2e)_[0-9a-f]+$/;

export class RestoreError extends Error {
  constructor(
    readonly stage:
      'backup' | 'verify' | 'prepare' | 'load' | 'migrate' | 'policy' | 'review' | 'complete',
    message: string,
  ) {
    super(message);
    this.name = 'RestoreError';
  }
}

const fromBackupError = (error: unknown, fallback: RestoreError['stage']): RestoreError => {
  if (error instanceof RestoreError) return error;
  if (error instanceof BackupError) return new RestoreError(error.stage, error.message);
  return new RestoreError(fallback, error instanceof Error ? error.message : 'failed');
};

async function withClient<T>(url: string, run: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

const databaseName = (url: string) => decodeURIComponent(new URL(url).pathname.slice(1));

// ---- Backup ----

export interface BackupOptions {
  readonly databaseUrl: string;
  readonly outDir: string;
  readonly tools: PgTools;
  /** The age X25519 recipient (public key) from the server's configuration. */
  readonly recipient: string | undefined;
  /** Required until M1 is accepted for real data. */
  readonly syntheticTestOnly: boolean;
  readonly config: BackupMeta['config'];
  readonly now?: () => Date;
  /** Interruption (SIGINT, SIGTERM): stops every stage and removes what was written. */
  readonly signal?: AbortSignal;
  /** For fault injection in tests (a full disk); the default creates owner-only new files. */
  readonly openOutput?: OpenOutput;
}

export interface BackupResult {
  readonly manifestPath: string;
  readonly dumpPath: string;
  readonly metaPath: string;
  /** SHA-256 of the manifest: the operator keeps it apart from backup storage (§3.2a). */
  readonly digest: string;
  readonly manifest: Manifest;
  readonly snapshotAt: string;
}

/**
 * One `pg_dump` (one repeatable-read snapshot), streamed into age; the metadata encrypted too;
 * the manifest written last. Everything is written as `.partial`, owner-only, and renamed only
 * after every stage succeeded and was flushed: a failed `pg_dump`, a failed encryption, a full
 * disk or an interruption removes the partial files, and a killed process leaves only
 * `.partial` files, which nothing treats as a backup. The restore guard is never in a backup.
 */
export async function createBackup(options: BackupOptions): Promise<BackupResult> {
  if (!options.syntheticTestOnly)
    throw new RestoreError(
      'backup',
      'backups of real data wait until M1 is accepted for real data (D-19, D-30); ' +
        'only --synthetic-test-only is available',
    );
  const recipient = (() => {
    try {
      return checkRecipient(options.recipient);
    } catch (error) {
      throw fromBackupError(error, 'backup');
    }
  })();
  const name = databaseName(options.databaseUrl);
  if (!SYNTHETIC_DATABASE.test(name))
    throw new RestoreError('backup', 'only a synthetic ruvee_it_* or ruvee_e2e_* database');
  let outStat;
  try {
    outStat = lstatSync(options.outDir);
  } catch {
    throw new RestoreError('backup', 'the output directory does not exist');
  }
  if (!outStat.isDirectory())
    throw new RestoreError('backup', 'the output path is not a directory');
  const migration = await withClient(options.databaseUrl, async (c) => {
    const rows = await c.query<{ migration_name: string }>(
      `SELECT migration_name FROM _prisma_migrations WHERE finished_at IS NOT NULL
       ORDER BY migration_name DESC LIMIT 1`,
    );
    return rows.rows[0]?.migration_name;
  });
  if (!migration) throw new RestoreError('backup', 'the database has no applied migrations');

  const snapshotAt = (options.now ?? (() => new Date()))();
  const stem = `ruvee-${snapshotAt.toISOString().replace(/[-:.]/g, '')}`;
  const final = {
    dump: join(options.outDir, `${stem}.dump.age`),
    meta: join(options.outDir, `${stem}.meta.age`),
    manifest: join(options.outDir, `${stem}.manifest.json`),
  };
  const partial = Object.fromEntries(
    Object.entries(final).map(([k, v]) => [k, `${v}.partial`]),
  ) as typeof final;
  for (const path of [...Object.values(final), ...Object.values(partial)])
    if (existsSync(path))
      throw new RestoreError('backup', 'a backup with that name already exists');

  const open = options.openOutput ?? openNewFile;
  const written: string[] = [];
  const track = (path: string) => {
    written.push(path);
    return path;
  };
  const run = options.tools.dump(options.databaseUrl, [GUARD_TABLE]);
  const onAbort = () => {
    run.kill();
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    options.signal?.throwIfAborted();
    const plain = new Tap();
    // pg_dump's output goes straight into encryption; an error on either side destroys both.
    const source: Readable = streamPipeline(run.stdout, plain, () => undefined);
    const [dump] = await Promise.all([
      encryptToFile(recipient, source, track(partial.dump), open, options.signal),
      // A pg_dump that fails after writing part of a dump still ends its output normally:
      // only its exit status says the dump is incomplete.
      run.done,
    ]);
    fsyncPath(partial.dump);
    const backupId = newBackupId();
    const meta: BackupMeta = {
      format: META_FORMAT,
      backupId,
      synthetic: true,
      snapshotAt: snapshotAt.toISOString(),
      dump: { sha256: plain.digest(), size: plain.bytes },
      schema: { migration },
      config: options.config,
    };
    options.signal?.throwIfAborted();
    const metaFile = await encryptBytesToFile(
      recipient,
      new TextEncoder().encode(JSON.stringify(meta)),
      track(partial.meta),
      open,
    );
    fsyncPath(partial.meta);
    const manifest: Manifest = {
      format: BACKUP_FORMAT,
      backupId,
      recipient,
      files: {
        dump: { file: `${stem}.dump.age`, ...dump },
        meta: { file: `${stem}.meta.age`, ...metaFile },
      },
    };
    const manifestBytes = new TextEncoder().encode(`${JSON.stringify(manifest, null, 2)}\n`);
    await new Promise<void>((resolve, reject) => {
      const out: Writable = open(track(partial.manifest));
      out.on('error', reject);
      out.end(manifestBytes, () => {
        resolve();
      });
    });
    fsyncPath(partial.manifest);
    options.signal?.throwIfAborted();
    // Publish: the data files first, the manifest last. Only a manifest makes a set complete.
    renameSync(partial.dump, track(final.dump));
    renameSync(partial.meta, track(final.meta));
    renameSync(partial.manifest, track(final.manifest));
    fsyncPath(options.outDir);
    return {
      manifestPath: final.manifest,
      dumpPath: final.dump,
      metaPath: final.meta,
      digest: backupDigest(manifestBytes),
      manifest,
      snapshotAt: meta.snapshotAt,
    };
  } catch (error) {
    run.kill();
    // Only the exact files this run created.
    for (const path of written) rmSync(path, { force: true });
    if (options.signal?.aborted)
      throw new RestoreError('backup', 'interrupted; nothing was published');
    throw fromBackupError(error, 'backup');
  } finally {
    options.signal?.removeEventListener('abort', onAbort);
  }
}

// ---- Restore ----

export interface RestoreOptions {
  readonly manifestPath: string;
  /** The owner's offline age identity, for this run only; never configuration. */
  readonly identityPath: string;
  /** The backup digest the operator kept apart from backup storage, or explicitly none. */
  readonly trustedDigest: string | false;
  readonly targetDatabaseUrl: string;
  readonly tools: PgTools;
  /** Applies the repository's migrations to the target (prisma migrate deploy). */
  readonly migrate: (url: string) => void | Promise<void>;
  /** The repository's migration directory names, oldest first. */
  readonly knownMigrations: readonly string[];
  readonly maxDumpBytes?: number;
  /** For tests: stop after a state, as an interruption would. */
  readonly stopAfter?: 'prepare' | 'load' | 'migrate';
  /** For tests: runs after VERIFY and PREPARE, before LOAD (a file changed in between). */
  readonly beforeLoad?: () => void | Promise<void>;
}

export interface RestoreResult {
  readonly restoreId: string;
  readonly snapshotAt: string;
  readonly digest: string;
  readonly provenance: 'trusted-digest' | 'unchecked';
  readonly removed: {
    readonly sessions: number;
    readonly pairings: number;
    readonly setupTokens: number;
  };
}

/**
 * LOAD: decrypts the dump again straight into `pg_restore`. Its input ends only after the last
 * chunk authenticated and the plaintext's SHA-256 and size matched; on any failure `pg_restore`
 * is killed before its input is closed, so it never sees a clean end of a bad dump. Whatever
 * happens, the guard is still `restoring`: nothing here can make the installation openable.
 */
async function load(backup: Awaited<ReturnType<typeof openBackup>>, url: string, tools: PgTools) {
  const run = tools.restore(url);
  // A pg_restore that exits early makes writes fail; `run.done` reports why.
  run.stdin.on('error', () => undefined);
  const { plaintext, tap } = await backup.decryptDump();
  try {
    for await (const chunk of plaintext as AsyncIterable<Buffer>) {
      if (!run.stdin.write(chunk))
        await new Promise<void>((resolve, reject) => {
          run.stdin.once('drain', resolve);
          run.done.catch(reject);
        });
    }
    if (tap.bytes !== backup.meta.dump.size || tap.digest() !== backup.meta.dump.sha256)
      throw new RestoreError('load', 'the decrypted dump does not match its metadata');
  } catch (error) {
    run.kill();
    run.stdin.destroy();
    // Reported as LOAD: the guard says `restoring`, and the target must be discarded.
    const message =
      error instanceof RestoreError || error instanceof BackupError
        ? error.message
        : ageFailure().message;
    throw new RestoreError('load', `${message}; discard this database and start again`);
  }
  run.stdin.end();
  try {
    await run.done;
  } catch (error) {
    throw new RestoreError('load', error instanceof Error ? error.message : 'pg_restore failed');
  }
}

/**
 * VERIFY → PREPARE → LOAD → MIGRATE → APPLY POLICY (backup-restore.md §3.5, §3.6). VERIFY
 * authenticates and checks the whole backup, every byte of the dump included, before anything is
 * created. Ends in the `review` state: the installation stays closed until `completeRestore`.
 */
export async function restoreBackup(
  options: RestoreOptions,
): Promise<RestoreResult | { stoppedAfter: string; restoreId: string }> {
  let backup;
  try {
    backup = await openBackup({
      manifestPath: options.manifestPath,
      identityPath: options.identityPath,
      trustedDigest: options.trustedDigest,
      ...(options.maxDumpBytes ? { maxDumpBytes: options.maxDumpBytes } : {}),
    });
    if (!options.knownMigrations.includes(backup.meta.schema.migration))
      throw new RestoreError(
        'verify',
        'the backup is from a newer or unknown schema; use the same or a newer Ruvee',
      );
    await verifyDump(backup);
  } catch (error) {
    throw fromBackupError(error, 'verify');
  }
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
      backup_digest text NOT NULL,
      provenance text NOT NULL CHECK (provenance IN ('trusted-digest', 'unchecked')),
      started_at timestamptz NOT NULL DEFAULT now(),
      review_completed_at timestamptz
    )`);
    await c.query(
      `INSERT INTO ${GUARD_TABLE} (id, state, restore_id, snapshot_at, backup_digest, provenance)
       VALUES (1, 'restoring', $1, $2, $3, $4)`,
      [restoreId, backup.meta.snapshotAt, backup.digest, backup.provenance],
    );
  });
  if (options.stopAfter === 'prepare') return { stoppedAfter: 'prepare', restoreId };

  await options.beforeLoad?.();
  await load(backup, url, options.tools);
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
      // Every commit from 1 to current_seq, none missing, none beyond.
      const gaps = await c.query<{ n: string }>(
        `SELECT count(*) AS n FROM vaults v
         WHERE (SELECT count(*) FROM vault_commits WHERE vault_id = v.id) <> v.current_seq`,
      );
      if (
        Number(bad.rows[0]?.n) !== 0 ||
        Number(badManifests.rows[0]?.n) !== 0 ||
        Number(gaps.rows[0]?.n) !== 0
      )
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
        snapshotAt: backup.meta.snapshotAt,
        digest: backup.digest,
        provenance: backup.provenance,
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
  /** SHA-256 of the backup's manifest: compare it with the operator's own record. */
  readonly backupDigest: string;
  readonly provenance: 'trusted-digest' | 'unchecked';
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
    backup_digest: string;
    provenance: 'trusted-digest' | 'unchecked';
  }>(
    `SELECT state, restore_id, snapshot_at, backup_digest, provenance FROM ${GUARD_TABLE} WHERE id = 1`,
  );
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
      backupDigest: g.backup_digest,
      provenance: g.provenance,
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
