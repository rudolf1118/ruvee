import {
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pgToolsFromEnv } from '../../src/admin/pg-tools.js';
import {
  createBackup,
  knownMigrations,
  restoreBackup,
  type BackupResult,
} from '../../src/admin/server-restore.js';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import { testBackupKey, type TestBackupKey } from '../support/backup-keys.js';
import { syntheticAccount } from '../support/synthetic-client.js';
import { createTempDatabase, migrate, query } from '../support/temp-database.js';

/**
 * Regression for predeployment-review R9: the bytes VERIFY checks are the bytes LOAD uses. The
 * manifest, metadata and identity are read once each through one descriptor that refuses links;
 * the dump is copied once into a private staging directory and every pass reads that copy.
 * Synthetic data only.
 */
const MIGRATIONS = knownMigrations(new URL('../../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
const SERVER_URL = process.env.DATABASE_URL ?? '';

describe('REVIEW R9 (regression): verified bytes are the bytes restored', () => {
  let h: Harness;
  let other: Harness;
  let key: TestBackupKey;
  let genuine: BackupResult;
  /** A complete, valid set of different content made with the same recipient. */
  let forged: BackupResult;
  const scratch: string[] = [];

  const dir = () => {
    const d = mkdtempSync(join(tmpdir(), 'ruvee-review-r9-'));
    scratch.push(d);
    return d;
  };

  /** A copy of `b` in a new directory; returns the paths of its three files. */
  function copyOf(b: BackupResult) {
    const d = dir();
    const stem = b.manifest.files.dump.file.replace('.dump.age', '');
    const paths = {
      dir: d,
      manifest: join(d, `${stem}.manifest.json`),
      meta: join(d, b.manifest.files.meta.file),
      dump: join(d, b.manifest.files.dump.file),
    };
    copyFileSync(b.manifestPath, paths.manifest);
    copyFileSync(b.metaPath, paths.meta);
    copyFileSync(b.dumpPath, paths.dump);
    return paths;
  }

  async function restore(
    manifestPath: string,
    extra: Partial<Parameters<typeof restoreBackup>[0]> = {},
  ) {
    process.env.DATABASE_URL = SERVER_URL;
    const target = await createTempDatabase();
    try {
      const outcome = await restoreBackup({
        manifestPath,
        identityPath: key.identityPath,
        trustedDigest: genuine.digest,
        targetDatabaseUrl: target.url,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
        ...extra,
      }).then(
        () => ({ ok: true as const }),
        (e: unknown) => ({ ok: false as const, e: e as { stage?: string; message?: string } }),
      );
      const usernames = outcome.ok
        ? (
            await query<{ u: string }>(target.url, 'SELECT username_normalized AS u FROM accounts')
          ).map((r) => r.u)
        : [];
      const [tables] = await query<{ n: string }>(
        target.url,
        `SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'public'`,
      );
      return { outcome, usernames, publicTables: Number(tables?.n) };
    } finally {
      await target.drop();
    }
  }

  beforeAll(async () => {
    h = await startHarness();
    await registerAccount(h, await syntheticAccount('synthetic-r9-genuine'));
    key = await testBackupKey();
    genuine = await createBackup({
      databaseUrl: h.db.url,
      outDir: dir(),
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    process.env.DATABASE_URL = SERVER_URL;
    vi.resetModules();
    other = await startHarness();
    await registerAccount(other, await syntheticAccount('synthetic-r9-forged'));
    forged = await createBackup({
      databaseUrl: other.db.url,
      outDir: dir(),
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
      now: () => new Date(Date.now() + 5000),
    });
  }, 120_000);

  afterAll(async () => {
    await (other as Harness | undefined)?.close();
    await (h as Harness | undefined)?.close();
    for (const d of scratch) rmSync(d, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  it('restores the genuine set, and removes its staging directory', async () => {
    const root = dir();
    const r = await restore(copyOf(genuine).manifest, { stagingRoot: root });
    expect(r.outcome.ok).toBe(true);
    expect(r.usernames).toEqual(['synthetic-r9-genuine']);
    expect(readdirSync(root)).toEqual([]);
  });

  it.each(['manifest', 'meta', 'dump'] as const)(
    'refuses a symbolic link in place of the %s, even to the genuine file',
    async (file) => {
      const p = copyOf(genuine);
      const real = join(dir(), 'real');
      copyFileSync(p[file], real);
      rmSync(p[file]);
      symlinkSync(real, p[file]);
      const r = await restore(p.manifest);
      expect(r.outcome).toMatchObject({ ok: false, e: { stage: 'verify' } });
      expect(r.outcome.ok ? '' : r.outcome.e.message).toMatch(/not a regular file/);
      expect(r.publicTables).toBe(0);
    },
  );

  it('refuses a symbolic link in place of the identity file', async () => {
    const link = join(dir(), 'identity-link.txt');
    symlinkSync(key.identityPath, link);
    const r = await restore(copyOf(genuine).manifest, { identityPath: link });
    expect(r.outcome).toMatchObject({ ok: false, e: { stage: 'verify' } });
  });

  it.each([
    ['meta', 'meta'],
    ['dump', 'dump'],
  ] as const)(
    'refuses a %s swapped for the forged one just before it is read (rename)',
    async (file, boundary) => {
      const p = copyOf(genuine);
      const r = await restore(p.manifest, {
        hooks: {
          beforeOpen: (f) => {
            if (f !== boundary) return;
            const swapped = join(p.dir, 'incoming');
            copyFileSync(file === 'meta' ? forged.metaPath : forged.dumpPath, swapped);
            renameSync(swapped, p[file]);
          },
        },
      });
      expect(r.outcome).toMatchObject({ ok: false, e: { stage: 'verify' } });
      expect(r.outcome.ok ? '' : r.outcome.e.message).toMatch(/does not match the manifest/);
      expect(r.publicTables).toBe(0);
    },
  );

  it('refuses a dump replaced by a link just before it is opened', async () => {
    const p = copyOf(genuine);
    const elsewhere = join(dir(), 'genuine.dump.age');
    copyFileSync(p.dump, elsewhere);
    const r = await restore(p.manifest, {
      hooks: {
        beforeOpen: (f) => {
          if (f !== 'dump') return;
          rmSync(p.dump);
          symlinkSync(elsewhere, p.dump);
        },
      },
    });
    expect(r.outcome).toMatchObject({ ok: false, e: { stage: 'verify' } });
  });

  it('ignores every change to the source set after it was read: the verified copy is restored', async () => {
    const p = copyOf(genuine);
    const r = await restore(p.manifest, {
      hooks: {
        // After the manifest, metadata and dump were read and staged, the attacker replaces the
        // whole set in place and by rename: none of it is read again.
        beforeOpen: (f) => {
          if (f !== 'identity') return;
          writeFileSync(p.manifest, readFileSync(forged.manifestPath));
          copyFileSync(forged.metaPath, p.meta);
          const swapped = join(p.dir, 'incoming');
          copyFileSync(forged.dumpPath, swapped);
          renameSync(swapped, p.dump);
        },
      },
    });
    expect(r.outcome.ok).toBe(true);
    expect(r.usernames).toEqual(['synthetic-r9-genuine']);
  });

  it('fails LOAD, leaving nothing open, when the staged copy itself changes after VERIFY', async () => {
    const root = dir();
    let seen: string[] = [];
    const p = copyOf(genuine);
    process.env.DATABASE_URL = SERVER_URL;
    const target = await createTempDatabase();
    try {
      await expect(
        restoreBackup({
          manifestPath: p.manifest,
          identityPath: key.identityPath,
          trustedDigest: genuine.digest,
          targetDatabaseUrl: target.url,
          tools,
          migrate,
          knownMigrations: MIGRATIONS,
          stagingRoot: root,
          beforeLoad: () => {
            const [staging] = readdirSync(root);
            const stagedDir = join(root, staging ?? '');
            seen = readdirSync(stagedDir);
            const staged = join(stagedDir, 'dump.age');
            // Only ciphertext is staged.
            expect(readFileSync(staged).subarray(0, 22).toString()).toBe('age-encryption.org/v1\n');
            // A same-user process replaces it with the forged, validly encrypted dump.
            copyFileSync(forged.dumpPath, staged);
          },
        }),
      ).rejects.toMatchObject({ stage: 'load' });
      expect(seen).toEqual(['dump.age']);
      const [guard] = await query<{ state: string }>(
        target.url,
        'SELECT state FROM ruvee_control.restore_guard',
      );
      expect(guard?.state).toBe('restoring');
      expect(readdirSync(root)).toEqual([]);
    } finally {
      await target.drop();
    }
  });
});
