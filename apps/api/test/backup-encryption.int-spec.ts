import { spawn } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { Decrypter, Encrypter } from 'age-encryption';
import { backupDigest, type Manifest } from '../src/admin/backup-files.js';
import { pgToolsFromEnv, type PgTools } from '../src/admin/pg-tools.js';
import {
  completeRestore,
  createBackup,
  knownMigrations,
  restoreBackup,
  reviewRestore,
  type BackupResult,
} from '../src/admin/server-restore.js';
import { registerAccount, startHarness, type Harness } from './support/api-harness.js';
import { testBackupKey, type TestBackupKey } from './support/backup-keys.js';
import { syntheticAccount } from './support/synthetic-client.js';
import { createTempDatabase, migrate, query, type TempDatabase } from './support/temp-database.js';

/**
 * Encrypted backups (D-29 option B, backup-restore.md §3.2) with real pg_dump, pg_restore and
 * age. Synthetic data and disposable identities only.
 */

const MIGRATIONS = knownMigrations(new URL('../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
const USERNAME = 'synthetic-backup-sentinel-user';

/** The start of a custom-format archive (pg_backup_archiver.c WriteHead) naming `database`. */
function archiveHeader(database: string): Buffer {
  const int = (n: number) => {
    const b = Buffer.alloc(5);
    b.writeUInt32LE(n, 1);
    return b;
  };
  const name = Buffer.from(database);
  return Buffer.concat([
    Buffer.from('PGDMP'),
    Buffer.from([1, 16, 0, 4, 8, 1, 0]),
    ...Array.from({ length: 7 }, () => int(0)),
    int(name.length),
    name,
  ]);
}

describe('encrypted server backups (real dumps, real age)', () => {
  let h: Harness;
  let key: TestBackupKey;
  let outDir: string;
  let backup: BackupResult;
  /** A second, independently valid backup made with the same public recipient. */
  let other: BackupResult;
  const scratch: string[] = [];
  const targets: TempDatabase[] = [];

  const dir = () => {
    const d = mkdtempSync(join(tmpdir(), 'ruvee-backup-enc-it-'));
    scratch.push(d);
    return d;
  };
  async function target() {
    const db = await createTempDatabase();
    targets.push(db);
    return db;
  }
  const tableCount = async (url: string) =>
    Number(
      (
        await query<{ n: string }>(
          url,
          `SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'public'`,
        )
      )[0]?.n,
    );

  const backupArgs = (outDir: string, extra: Partial<Parameters<typeof createBackup>[0]> = {}) => ({
    databaseUrl: h.db.operator.url,
    outDir,
    tools,
    recipient: key.recipient,
    syntheticTestOnly: true,
    config,
    ...extra,
  });
  const restoreArgs = (
    manifestPath: string,
    target: TempDatabase,
    extra: Partial<Parameters<typeof restoreBackup>[0]> = {},
  ) => ({
    manifestPath,
    identityPath: key.identityPath,
    trustedDigest: false as const,
    targetDatabaseUrl: target.operator.url,
    runtimeRole: target.runtime.name,
    tools,
    migrate,
    knownMigrations: MIGRATIONS,
    ...extra,
  });

  /** A copy of a backup set in a new directory, optionally changed, with its manifest. */
  function copySet(
    b: BackupResult,
    change: (paths: { dump: string; meta: string; manifest: string }) => void = () => undefined,
  ) {
    const d = dir();
    const paths = {
      dump: join(d, b.manifest.files.dump.file),
      meta: join(d, b.manifest.files.meta.file),
      manifest: join(d, `${b.manifest.files.dump.file.replace('.dump.age', '')}.manifest.json`),
    };
    copyFileSync(b.dumpPath, paths.dump);
    copyFileSync(b.metaPath, paths.meta);
    copyFileSync(b.manifestPath, paths.manifest);
    change(paths);
    return paths;
  }
  /** What an attacker who can write to backup storage does: makes the manifest match again. */
  function rehash(paths: { dump: string; meta: string; manifest: string }) {
    const m = JSON.parse(readFileSync(paths.manifest, 'utf8')) as Manifest;
    const entry = (p: string) => {
      const bytes = readFileSync(p);
      return { size: bytes.length, sha256: backupDigest(bytes) };
    };
    m.files.dump = { ...m.files.dump, ...entry(paths.dump) };
    m.files.meta = { ...m.files.meta, ...entry(paths.meta) };
    writeFileSync(paths.manifest, JSON.stringify(m));
  }
  const flipByte = (path: string, at: (size: number) => number) => {
    const bytes = readFileSync(path);
    const i = at(bytes.length);
    bytes[i] = (bytes[i] ?? 0) ^ 0x01;
    writeFileSync(path, bytes);
  };

  beforeAll(async () => {
    h = await startHarness();
    await registerAccount(h, await syntheticAccount(USERNAME));
    key = await testBackupKey();
    outDir = dir();
    backup = await createBackup(backupArgs(outDir));
    other = await createBackup(backupArgs(dir(), { now: () => new Date(Date.now() + 2000) }));
  }, 120_000);

  afterAll(async () => {
    for (const db of targets) await db.drop();
    await (h as Harness | undefined)?.close();
    for (const d of scratch) rmSync(d, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  describe('backup', () => {
    it('writes three owner-only files: two age files and a manifest without secrets', async () => {
      expect(readdirSync(outDir).sort()).toEqual(
        [
          backup.manifest.files.dump.file,
          backup.manifest.files.meta.file,
          `${backup.manifest.files.dump.file.replace('.dump.age', '')}.manifest.json`,
        ].sort(),
      );
      for (const path of [backup.dumpPath, backup.metaPath]) {
        const bytes = readFileSync(path);
        expect(bytes.subarray(0, 22).toString()).toBe('age-encryption.org/v1\n');
        // Neither the custom-format dump's magic nor any row data is visible.
        expect(bytes.includes(Buffer.from('PGDMP'))).toBe(false);
        expect(bytes.includes(Buffer.from(USERNAME))).toBe(false);
      }
      const manifestText = readFileSync(backup.manifestPath, 'utf8');
      expect(Object.keys(JSON.parse(manifestText) as object).sort()).toEqual([
        'backupId',
        'files',
        'format',
        'recipient',
      ]);
      expect(manifestText).not.toMatch(/snapshot|publicOrigin|migration|127\.0\.0\.1/);
      expect(backup.digest).toBe(backupDigest(readFileSync(backup.manifestPath)));
      // The metadata opens with the identity, and only with it.
      const d = new Decrypter();
      d.addIdentity(readFileSync(key.identityPath, 'utf8').split('\n')[1] ?? '');
      const meta = JSON.parse(await d.decrypt(readFileSync(backup.metaPath), 'text')) as {
        config: object;
        backupId: string;
      };
      expect(meta).toMatchObject({ config, backupId: backup.manifest.backupId });
    });

    it('refuses a missing, malformed or private-key "recipient" and writes nothing', async () => {
      const identityLine = readFileSync(key.identityPath, 'utf8').split('\n')[1];
      for (const recipient of [undefined, '', 'age1notakey', identityLine]) {
        const d = dir();
        await expect(createBackup(backupArgs(d, { recipient }))).rejects.toMatchObject({
          stage: 'backup',
          message: expect.stringMatching(/public key only/) as unknown,
        });
        expect(readdirSync(d)).toEqual([]);
      }
    });

    it('publishes nothing when pg_dump fails after writing part of a dump', async () => {
      const failing: PgTools = {
        ...tools,
        dump: (target) => {
          // Stands in for pg_dump: a valid archive header for the checked database (so the
          // header check passes), 300 kB of output, then a failure exit status.
          const child = spawn('sh', ['-c', 'cat; head -c 300000 /dev/urandom; exit 3'], {
            stdio: ['pipe', 'pipe', 'ignore'],
          });
          child.stdin.end(archiveHeader(target.database));
          const done = new Promise<void>((resolve, reject) => {
            child.on('close', (code) => {
              if (code === 0) resolve();
              else reject(new Error(`pg_dump failed (exit ${String(code)})`));
            });
          });
          done.catch(() => undefined);
          return { stdout: child.stdout, done, kill: () => child.kill('SIGKILL') };
        },
      };
      const d = dir();
      await expect(createBackup(backupArgs(d, { tools: failing }))).rejects.toThrow(/exit 3/);
      expect(readdirSync(d)).toEqual([]);
    });

    it('publishes nothing when the disk fills up during the dump', async () => {
      const d = dir();
      const full = (path: string) => {
        let written = 0;
        const real = new Writable({
          write(chunk: Buffer, _encoding, callback) {
            written += chunk.length;
            if (written > 4096) {
              const error = Object.assign(new Error('ENOSPC: no space left on device'), {
                code: 'ENOSPC',
              });
              callback(error);
              return;
            }
            callback();
          },
        });
        // The file exists, as a real partial write would leave it.
        writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
        return real;
      };
      await expect(createBackup(backupArgs(d, { openOutput: full }))).rejects.toThrow(/ENOSPC/);
      expect(readdirSync(d)).toEqual([]);
    });

    it('publishes nothing when interrupted while pg_dump is streaming', async () => {
      const d = dir();
      const controller = new AbortController();
      const interrupting: PgTools = {
        ...tools,
        dump: (url, exclude) => {
          const run = tools.dump(url, exclude);
          run.stdout.once('data', () => {
            controller.abort();
          });
          return run;
        },
      };
      await expect(
        createBackup(backupArgs(d, { tools: interrupting, signal: controller.signal })),
      ).rejects.toThrow(/interrupted/);
      expect(readdirSync(d)).toEqual([]);
    });

    it('never treats a set without its published manifest as a backup', async () => {
      const paths = copySet(backup, (p) => {
        renameSync(p.manifest, `${p.manifest}.partial`);
      });
      const db = await target();
      await expect(
        restoreBackup(restoreArgs(`${paths.manifest}.partial`, db)),
      ).rejects.toMatchObject({ stage: 'verify' });
      await expect(restoreBackup(restoreArgs(paths.manifest, db))).rejects.toMatchObject({
        stage: 'verify',
      });
      expect(await tableCount(db.url)).toBe(0);
    });
  });

  describe('restore refuses, before creating anything', () => {
    let db: TempDatabase;
    beforeAll(async () => {
      db = await target();
    });
    afterEach(async () => {
      expect(await tableCount(db.url)).toBe(0);
    });

    const refused = async (
      manifestPath: string,
      message: RegExp,
      extra: Partial<Parameters<typeof restoreBackup>[0]> = {},
    ) => {
      await expect(restoreBackup(restoreArgs(manifestPath, db, extra))).rejects.toMatchObject({
        stage: 'verify',
        message: expect.stringMatching(message) as unknown,
      });
    };

    it('a wrong identity, and an identity file others can read', async () => {
      await refused(backup.manifestPath, /not the backup's recipient/, {
        identityPath: key.otherIdentityPath,
      });
      const loose = join(dir(), 'identity.txt');
      copyFileSync(key.identityPath, loose);
      chmodSync(loose, 0o644);
      await refused(backup.manifestPath, /readable by others/, { identityPath: loose });
    });

    it('a manifest that does not match the operator’s trusted digest', async () => {
      await refused(backup.manifestPath, /trusted digest/, { trustedDigest: other.digest });
      await refused(backup.manifestPath, /64 hexadecimal/, { trustedDigest: 'abc' });
    });

    it('a truncated or modified dump, even when the manifest was made to match', async () => {
      const truncated = copySet(backup, (p) => {
        truncateSync(p.dump, readFileSync(p.dump).length - 100);
      });
      await refused(truncated.manifest, /size or SHA-256/);
      rehash(truncated);
      await refused(truncated.manifest, /could not be decrypted and authenticated/);
      for (const at of [(n: number) => Math.floor(n / 2), (n: number) => n - 5]) {
        const modified = copySet(backup, (p) => {
          flipByte(p.dump, at);
        });
        await refused(modified.manifest, /size or SHA-256/);
        rehash(modified);
        await refused(modified.manifest, /could not be decrypted and authenticated/);
      }
    });

    it('modified or substituted metadata', async () => {
      const modified = copySet(backup, (p) => {
        flipByte(p.meta, (n) => n - 3);
        rehash(p);
      });
      await refused(modified.manifest, /could not be decrypted and authenticated/);
      // Another backup's metadata: valid age, valid schema, the wrong backup.
      const substituted = copySet(backup, (p) => {
        copyFileSync(other.metaPath, p.meta);
        rehash(p);
      });
      await refused(substituted.manifest, /belongs to another backup/);
    });

    it('a newer schema, forged by someone who knows only the public recipient', async () => {
      const forged = copySet(backup);
      const e = new Encrypter();
      e.addRecipient(key.recipient);
      writeFileSync(
        forged.meta,
        await e.encrypt(
          JSON.stringify({
            format: 'ruvee-server-backup-meta/2',
            backupId: backup.manifest.backupId,
            synthetic: true,
            snapshotAt: new Date().toISOString(),
            dump: { sha256: '0'.repeat(64), size: 1 },
            schema: { migration: '29991231000000_from_the_future' },
            config,
          }),
        ),
      );
      rehash(forged);
      await refused(forged.manifest, /newer or unknown schema/);
    });

    it('unsafe names, links, oversize files and other formats', async () => {
      const escaping = copySet(backup, (p) => {
        const m = JSON.parse(readFileSync(p.manifest, 'utf8')) as Manifest;
        m.files.dump.file = '../ruvee-20260101T000000000Z.dump.age';
        writeFileSync(p.manifest, JSON.stringify(m));
      });
      await refused(escaping.manifest, /not a supported Ruvee backup/);
      const elsewhere = copySet(backup, (p) => {
        const m = JSON.parse(readFileSync(p.manifest, 'utf8')) as Manifest;
        m.files.dump.file = other.manifest.files.dump.file;
        writeFileSync(p.manifest, JSON.stringify(m));
      });
      await refused(elsewhere.manifest, /outside its own backup set/);
      const linked = copySet(backup, (p) => {
        rmSync(p.dump);
        symlinkSync(backup.dumpPath, p.dump);
      });
      await refused(linked.manifest, /not a regular file/);
      await refused(backup.manifestPath, /larger than allowed/, { maxDumpBytes: 1024 });
      const old = copySet(backup, (p) => {
        writeFileSync(p.manifest, JSON.stringify({ format: 'ruvee-server-backup/1' }));
      });
      await refused(old.manifest, /not a supported Ruvee backup \(format 2\)/);
      const wrongName = join(dir(), 'backup.json');
      copyFileSync(backup.manifestPath, wrongName);
      await refused(wrongName, /manifest file name/);
    });
  });

  it('a backup forged with the public recipient restores only when provenance is not checked', async () => {
    // `other` is a complete, valid backup of different content: what anyone who knows the
    // recipient could produce. Only the operator's own digest tells it apart.
    const checked = await target();
    await expect(
      restoreBackup(restoreArgs(other.manifestPath, checked, { trustedDigest: backup.digest })),
    ).rejects.toMatchObject({ stage: 'verify' });
    expect(await tableCount(checked.url)).toBe(0);
    const unchecked = await target();
    const result = await restoreBackup(restoreArgs(other.manifestPath, unchecked));
    expect(result).toMatchObject({ provenance: 'unchecked', digest: other.digest });
    expect(await reviewRestore(unchecked.operator.url)).toMatchObject({
      provenance: 'unchecked',
      backupDigest: other.digest,
    });
  });

  it('a dump that fails to decrypt during LOAD leaves an installation that cannot be opened', async () => {
    const paths = copySet(backup);
    const db = await target();
    const stagingRoot = dir();
    await expect(
      restoreBackup(
        restoreArgs(paths.manifest, db, {
          trustedDigest: backup.digest,
          stagingRoot,
          // VERIFY passed; the staged copy LOAD reads changes in between (the source directory
          // is never read again, review R9).
          beforeLoad: () => {
            const [staging] = readdirSync(stagingRoot);
            flipByte(join(stagingRoot, staging ?? '', 'dump.age'), (n) => n - 5);
          },
        }),
      ),
    ).rejects.toMatchObject({ stage: 'load' });
    const [guard] = await query<{ state: string; restore_id: string }>(
      db.url,
      'SELECT state, restore_id FROM ruvee_control.restore_guard',
    );
    expect(guard?.state).toBe('restoring');
    await expect(
      completeRestore(db.operator.url, {
        restoreId: guard?.restore_id ?? '',
        devicesReviewed: true,
        acceptRestoredCredentials: true,
      }),
    ).rejects.toMatchObject({ stage: 'complete' });
  });

  it('restores the genuine backup with its trusted digest', async () => {
    const db = await target();
    const result = await restoreBackup(
      restoreArgs(backup.manifestPath, db, { trustedDigest: backup.digest }),
    );
    expect(result).toMatchObject({ provenance: 'trusted-digest', digest: backup.digest });
    const accounts = await query<{ username_normalized: string }>(
      db.url,
      'SELECT username_normalized FROM accounts',
    );
    expect(accounts).toEqual([{ username_normalized: USERNAME }]);
  });
});
