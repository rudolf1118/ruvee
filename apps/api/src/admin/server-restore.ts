import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { pipeline as streamPipeline, type Readable, type Writable } from 'node:stream';
import type pg from 'pg';
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
  passMatches,
  openNewFile,
  Tap,
  verifyDump,
  type BackupMeta,
  type Manifest,
  type OpenOutput,
  type OpenedBackup,
  type VerifyHooks,
} from './backup-files.js';
import {
  newReopenCode,
  REOPEN_CODE_TTL_MS,
  REOPEN_CODES_DDL,
  REOPEN_CODES_TABLE,
} from '../reopen/reopen-codes.js';
import {
  assertEmptyDatabase,
  CONTROL_SCHEMA,
  createControlSchema,
  createLoader,
  loaderRoleName,
  GUARD_TABLE,
  restoredObjectProblems,
  retireLoader,
} from './restore-control.js';
import { connectTo, DumpHeaderCheck, parseDbTarget, type DbTarget } from './db-target.js';
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

export { BACKUP_FORMAT, GUARD_TABLE };
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

/** Parses the URL once (db-target.ts) and refuses it as `stage` when it is not acceptable. */
function targetOf(url: string, stage: RestoreError['stage']): DbTarget {
  try {
    return parseDbTarget(url);
  } catch (error) {
    throw new RestoreError(stage, error instanceof Error ? error.message : 'invalid URL');
  }
}

/** A client on exactly the named database (it checks `current_database()`). */
async function withClient<T>(url: string, run: (client: pg.Client) => Promise<T>): Promise<T> {
  const client = await connectTo(targetOf(url, 'verify'));
  try {
    return await run(client);
  } finally {
    await client.end();
  }
}

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
  // The name is checked on the one parsed target, which node-pg and pg_dump both use, and again
  // on the connection (current_database) and in pg_dump's own archive header (R7).
  const target = targetOf(options.databaseUrl, 'backup');
  if (!SYNTHETIC_DATABASE.test(target.database))
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
  const run = options.tools.dump(target, {
    tables: [],
    // The restore tool's own state is never part of a backup (R8).
    schemas: [CONTROL_SCHEMA],
  });
  const onAbort = () => {
    run.kill();
  };
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    options.signal?.throwIfAborted();
    const plain = new Tap();
    // pg_dump's output goes straight into encryption; an error on either side destroys both.
    // Nothing passes before the archive header names the checked database.
    const source: Readable = streamPipeline(
      run.stdout,
      new DumpHeaderCheck(target.database),
      plain,
      () => undefined,
    );
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
  /** Where the private staging directory for the dump's ciphertext is made (R9). */
  readonly stagingRoot?: string;
  /** For tests: adversarial changes to the source files at each boundary (R9). */
  readonly hooks?: VerifyHooks;
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
 * chunk authenticated and the plaintext's SHA-256 and size matched. The last chunk is held back
 * until then (review R15): whatever else happens, `pg_restore` never receives a complete archive
 * that was not verified, so even a clean end of input, as when the `docker exec` client of
 * RUVEE_PG_TOOLS_PREFIX is killed and the `pg_restore` inside the container keeps running, leaves
 * it a truncated archive that it rolls back. On any failure `pg_restore` is killed. A tool that
 * exits before reading its whole input fails LOAD instead of leaving it waiting. Whatever
 * happens, the guard is still `restoring`: nothing here can make the installation openable.
 */
async function load(
  backup: Awaited<ReturnType<typeof openBackup>>,
  target: DbTarget,
  tools: PgTools,
) {
  const run = tools.restore(target);
  // A pg_restore that exits early makes writes fail; `run.done` reports why.
  run.stdin.on('error', () => undefined);
  const exited = run.done.then(
    () => {
      throw new RestoreError('load', 'pg_restore ended before it read the whole dump');
    },
    (error: unknown) => {
      throw error;
    },
  );
  exited.catch(() => undefined);
  const write = async (chunk: Buffer) => {
    if (run.stdin.write(chunk)) return;
    // Waits for room in the pipe, or for pg_restore to end, whichever comes first.
    await Promise.race([new Promise<void>((resolve) => run.stdin.once('drain', resolve)), exited]);
  };
  let held: Buffer | undefined;
  try {
    // Inside the handler: a staged file whose header no longer decrypts fails as LOAD too, with
    // pg_restore killed first.
    const { plaintext, tap, cipher } = await backup.decryptDump();
    for await (const chunk of plaintext as AsyncIterable<Buffer>) {
      if (held) await write(held);
      held = chunk;
    }
    // The input ends only if this pass read exactly the ciphertext VERIFY checked, and it
    // decrypted to exactly the plaintext the metadata names (R9).
    if (!passMatches(backup, tap, cipher))
      throw new RestoreError('load', 'the decrypted dump does not match its metadata');
    if (held) await write(held);
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
  let backup: OpenedBackup;
  try {
    backup = await openBackup({
      manifestPath: options.manifestPath,
      identityPath: options.identityPath,
      trustedDigest: options.trustedDigest,
      ...(options.maxDumpBytes ? { maxDumpBytes: options.maxDumpBytes } : {}),
      ...(options.stagingRoot ? { stagingRoot: options.stagingRoot } : {}),
      ...(options.hooks ? { hooks: options.hooks } : {}),
    });
  } catch (error) {
    throw fromBackupError(error, 'verify');
  }
  // The staged ciphertext lives exactly as long as this restore (R9).
  try {
    try {
      if (!options.knownMigrations.includes(backup.meta.schema.migration))
        throw new RestoreError(
          'verify',
          'the backup is from a newer or unknown schema; use the same or a newer Ruvee',
        );
      await verifyDump(backup);
    } catch (error) {
      throw fromBackupError(error, 'verify');
    }
    return await restoreVerified(options, backup);
  } finally {
    backup.cleanup();
  }
}

/** PREPARE to APPLY POLICY, from a backup VERIFY passed, read only from its staged copy. */
async function restoreVerified(
  options: RestoreOptions,
  backup: OpenedBackup,
): Promise<RestoreResult | { stoppedAfter: string; restoreId: string }> {
  const restoreId = randomUUID();
  const url = options.targetDatabaseUrl;

  // PREPARE: an empty database only; the control schema, the guard and the loader role before
  // any restored row exists (R8: the loader cannot reach the control schema).
  const target = targetOf(url, 'prepare');
  const loaderName = loaderRoleName(restoreId);
  await withClient(url, async (c) => {
    if (!(await assertEmptyDatabase(c)))
      throw new RestoreError(
        'prepare',
        'the target database is not empty; restore only into a new, empty database',
      );
    await createControlSchema(c);
    await c.query(`CREATE TABLE ${GUARD_TABLE} (
      id smallint PRIMARY KEY CHECK (id = 1),
      state text NOT NULL CHECK (state IN ('restoring', 'review', 'reopening', 'open')),
      restore_id uuid NOT NULL,
      snapshot_at timestamptz NOT NULL,
      backup_digest text NOT NULL,
      provenance text NOT NULL CHECK (provenance IN ('trusted-digest', 'unchecked')),
      started_at timestamptz NOT NULL DEFAULT now(),
      review_completed_at timestamptz,
      reopened_at timestamptz,
      loader_role text NOT NULL
    )`);
    await c.query(REOPEN_CODES_DDL);
    await c.query(
      `INSERT INTO ${GUARD_TABLE} (id, state, restore_id, snapshot_at, backup_digest, provenance, loader_role)
       VALUES (1, 'restoring', $1, $2, $3, $4, $5)`,
      [restoreId, backup.meta.snapshotAt, backup.digest, backup.provenance, loaderName],
    );
  });
  if (options.stopAfter === 'prepare') return { stoppedAfter: 'prepare', restoreId };

  try {
    await options.beforeLoad?.();
    const loader = await withClient(url, (c) => createLoader(c, target.database, loaderName));
    // LOAD as the loader role: restored SQL runs with only its privileges.
    await load(backup, { ...target, user: loader.name, password: loader.password }, options.tools);
    // Then, as the admin role: the guard untouched, and nothing Ruvee would not create.
    await withClient(url, async (c) => {
      const g = await guard(c);
      if (g.state !== 'restoring' || g.restore_id !== restoreId)
        throw new RestoreError(
          'load',
          'the restore guard changed during LOAD; discard this database',
        );
      const problems = await restoredObjectProblems(c);
      if (problems.length > 0)
        throw new RestoreError(
          'load',
          `the dump contains objects Ruvee never creates: ${problems.join(', ')}; discard this database`,
        );
    });
  } finally {
    // The loader role exists only for LOAD, whatever happened.
    await withClient(url, (c) => retireLoader(c, loaderName)).catch(() => undefined);
  }
  if (options.stopAfter === 'load') return { stoppedAfter: 'load', restoreId };
  try {
    await options.migrate(url);
  } catch (error) {
    throw new RestoreError('migrate', error instanceof Error ? error.message : 'migration failed');
  }
  if (options.stopAfter === 'migrate') return { stoppedAfter: 'migrate', restoreId };

  // APPLY POLICY: one transaction; the guard re-checked under lock, structural checks first.
  return withClient(url, async (c) => {
    await c.query('BEGIN');
    try {
      const locked = await c.query<{ state: string; restore_id: string }>(
        `SELECT state, restore_id FROM ${GUARD_TABLE} WHERE id = 1 FOR UPDATE`,
      );
      if (locked.rows[0]?.state !== 'restoring' || locked.rows[0].restore_id !== restoreId)
        throw new RestoreError('policy', 'the restore guard is not in the expected state');
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
      const moved = await c.query(
        `UPDATE ${GUARD_TABLE} SET state = 'review' WHERE id = 1 AND state = 'restoring' AND restore_id = $1`,
        [restoreId],
      );
      if (moved.rowCount !== 1)
        throw new RestoreError('policy', 'the restore guard is not in the expected state');
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
  readonly state: 'restoring' | 'review' | 'reopening' | 'open';
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
  const exists = await c.query<{ t: string | null }>(`SELECT to_regclass('${GUARD_TABLE}') AS t`);
  if (!exists.rows[0]?.t)
    throw new RestoreError('review', 'this database was not restored with ruvee-admin restore');
  const row = await c.query<{
    state: 'restoring' | 'review' | 'reopening' | 'open';
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

/** A reopening code as `ruvee-admin` prints it, once (backup-restore.md §3.13). */
export interface IssuedReopenCode {
  readonly code: string;
  readonly expiresAt: string;
}

/**
 * Issues the one usable reopening code: every earlier code of this restore, consumed ones
 * included, is revoked and every reopen session ended, in the same transaction. Runs inside an
 * open transaction on `c` that holds the guard row's lock, which a reopening's completion takes
 * first too: a completion either finished before this or sees its session ended (R13).
 */
async function issueCode(
  c: pg.Client,
  restoreId: string,
  accountId: string,
): Promise<IssuedReopenCode> {
  // A consumed code links the reopen session it created; revoking it ends that reopening.
  await c.query(`UPDATE ${REOPEN_CODES_TABLE} SET revoked_at = now() WHERE revoked_at IS NULL`);
  await c.query(
    `UPDATE sessions SET revoked_at = now(), revoke_reason = 'reopened' WHERE kind = 'reopen' AND revoked_at IS NULL`,
  );
  const { code, hash } = newReopenCode();
  const expires = await c.query<{ expires_at: Date }>(
    `INSERT INTO ${REOPEN_CODES_TABLE} (id, restore_id, account_id, code_hash, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5)) RETURNING expires_at`,
    [randomUUID(), restoreId, accountId, hash, REOPEN_CODE_TTL_MS / 1000],
  );
  await c.query(
    `INSERT INTO security_events (id, account_id, type, details, created_at)
     VALUES ($1, $2, 'reopen_code_issued', $3, now())`,
    [randomUUID(), accountId, JSON.stringify({ restoreId })],
  );
  return { code, expiresAt: (expires.rows[0]?.expires_at ?? new Date()).toISOString() };
}

async function transaction<T>(c: pg.Client, run: () => Promise<T>): Promise<T> {
  await c.query('BEGIN');
  try {
    const result = await run();
    await c.query('COMMIT');
    return result;
  } catch (error) {
    await c.query('ROLLBACK');
    throw error;
  }
}

/**
 * Ends the review, only from `review`, with the printed restore id and both acknowledgements.
 * With an account, the installation goes to `reopening` and a reopening code is issued: nothing
 * opens until the owner completes the reopening (§3.13). Without one (a snapshot taken before the
 * account existed), it opens: registration still needs a new setup token.
 */
export async function completeRestore(
  databaseUrl: string,
  options: { restoreId: string; devicesReviewed: boolean; acceptRestoredCredentials: boolean },
): Promise<{ state: 'reopening'; reopen: IssuedReopenCode } | { state: 'open' }> {
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
        g.state === 'open' || g.state === 'reopening'
          ? 'the review is already complete'
          : 'the restore did not finish; start again into a new database',
      );
    if (g.restore_id !== options.restoreId)
      throw new RestoreError('complete', 'that is not this restore');
    return transaction(c, async () => {
      const account = await c.query<{ id: string }>('SELECT id FROM accounts LIMIT 1');
      const accountId = account.rows[0]?.id ?? null;
      await c.query(
        `INSERT INTO security_events (id, account_id, type, details, created_at)
         VALUES ($1, $2, 'restore_review_completed', $3, now())`,
        [randomUUID(), accountId, JSON.stringify({ restoreId: options.restoreId })],
      );
      const next = accountId === null ? 'open' : 'reopening';
      const moved = await c.query(
        `UPDATE ${GUARD_TABLE} SET state = $1, review_completed_at = now(),
           reopened_at = CASE WHEN $1 = 'open' THEN now() ELSE NULL END
         WHERE id = 1 AND state = 'review'`,
        [next],
      );
      if (moved.rowCount !== 1) throw new RestoreError('complete', 'the review changed meanwhile');
      if (accountId === null) return { state: 'open' as const };
      return {
        state: 'reopening' as const,
        reopen: await issueCode(c, options.restoreId, accountId),
      };
    });
  });
}

/**
 * The host-authorized retry path: a new reopening code when the last one expired, was used up by
 * failures, or its reopen session was lost. Revokes every earlier code and reopen session. Only
 * while `reopening`; it never opens anything.
 */
export async function issueReopenCode(
  databaseUrl: string,
  options: { restoreId: string },
): Promise<IssuedReopenCode> {
  return withClient(databaseUrl, async (c) => {
    const g = await guard(c);
    if (g.state !== 'reopening')
      throw new RestoreError('complete', 'a reopening code exists only while reopening');
    if (g.restore_id !== options.restoreId)
      throw new RestoreError('complete', 'that is not this restore');
    return transaction(c, async () => {
      // Locked and checked again inside the transaction: a reopening that completed meanwhile
      // has opened the installation, and then no code is issued.
      const locked = await c.query<{ state: string; restore_id: string }>(
        `SELECT state, restore_id FROM ${GUARD_TABLE} WHERE id = 1 FOR UPDATE`,
      );
      const now = locked.rows[0];
      if (now?.state !== 'reopening' || now.restore_id !== options.restoreId)
        throw new RestoreError('complete', 'a reopening code exists only while reopening');
      const account = await c.query<{ id: string }>('SELECT id FROM accounts LIMIT 1');
      const accountId = account.rows[0]?.id;
      if (!accountId) throw new RestoreError('complete', 'the restored database has no account');
      return issueCode(c, options.restoreId, accountId);
    });
  });
}

/** The repository's migrations, oldest first (their directory names). */
export function knownMigrations(migrationsDir: string): string[] {
  return readdirSync(migrationsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^[0-9]{14}_/.test(d.name))
    .map((d) => d.name)
    .sort();
}
