import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Test-only: one Ruvee installation whose API this test starts and stops itself, so that a
 * server restore can happen under the same web origin (the browsers keep their local data).
 * Every database is a `ruvee_e2e_<hex>` it creates and drops; every file is in its own
 * temporary directory. Backup, restore, review and opening go through the real `ruvee-admin`
 * commands, as an operator would run them. Synthetic data and a synthetic age identity only.
 */

const apiRoot = new URL('../../api/', import.meta.url).pathname;

function adminUrl(): string {
  const url = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
  if (!url) throw new Error('Set RUVEE_E2E_ADMIN_DATABASE_URL');
  return url;
}

function urlFor(name: string): string {
  const u = new URL(adminUrl());
  u.pathname = `/${name}`;
  return u.toString();
}

function run(args: string[], env: Record<string, string> = {}): string {
  const result = spawnSync('node', args, {
    cwd: apiRoot,
    env: { ...process.env, ...env, PRISMA_HIDE_UPDATE_MESSAGE: '1' },
    encoding: 'utf8',
  });
  if (result.status !== 0)
    throw new Error(`node ${args.slice(0, 2).join(' ')} failed:\n${result.stderr}`);
  return result.stdout;
}

export class RestoreStack {
  readonly dir = mkdtempSync(join(tmpdir(), 'ruvee-restore-e2e-'));
  private readonly databases: string[] = [];
  private api: ChildProcess | undefined;
  private current = '';
  readonly setupFile = join(this.dir, 'opaque-server-setup');
  readonly identityFile = join(this.dir, 'synthetic-identity.txt');
  readonly backups = join(this.dir, 'backups');
  recipient = '';
  bootstrapToken = '';

  constructor(
    private readonly apiPort: number,
    private readonly publicOrigin: string,
  ) {}

  private newDatabase(): string {
    const name = `ruvee_e2e_${randomBytes(6).toString('hex')}`;
    run(['scripts/e2e-db.mjs', 'create', name]);
    this.databases.push(name);
    return name;
  }

  /** A fresh installation: database, migrations, OPAQUE setup, setup token, age key pair. */
  async init(): Promise<void> {
    const name = this.newDatabase();
    spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
      cwd: apiRoot,
      env: { ...process.env, DATABASE_URL: urlFor(name), PRISMA_HIDE_UPDATE_MESSAGE: '1' },
    });
    run(['dist/admin/cli.js', 'opaque-setup', '--out', this.setupFile]);
    const out = run(['dist/admin/cli.js', 'bootstrap-token'], { DATABASE_URL: urlFor(name) });
    this.bootstrapToken = /\n\s+([A-Za-z0-9_-]{43})\n/.exec(out)?.[1] ?? '';
    const keys = JSON.parse(run(['scripts/e2e-age-key.mjs'])) as {
      identity: string;
      recipient: string;
    };
    writeFileSync(this.identityFile, `${keys.identity}\n`, { mode: 0o600 });
    this.recipient = keys.recipient;
    mkdirSync(this.backups, { mode: 0o700 });
    await this.start(name);
  }

  /** Starts the built API on `name`; resolves once it is ready. */
  async start(name: string): Promise<void> {
    this.current = name;
    this.api = spawn('node', ['dist/main.js'], {
      cwd: apiRoot,
      env: {
        ...process.env,
        DATABASE_URL: urlFor(name),
        NODE_ENV: 'test',
        API_PORT: String(this.apiPort),
        API_HOST: '127.0.0.1',
        OPAQUE_SERVER_SETUP_FILE: this.setupFile,
        PUBLIC_ORIGIN: this.publicOrigin,
        SESSION_COOKIE_SECURE: 'false',
        EXTENSION_ORIGINS: '',
        LOG_LEVEL: 'warn',
      },
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    for (let i = 0; i < 100; i++) {
      try {
        const res = await fetch(`http://127.0.0.1:${String(this.apiPort)}/health/live`);
        if (res.ok) return;
      } catch {
        // not listening yet
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error('the API did not start');
  }

  async stop(): Promise<void> {
    const api = this.api;
    if (api?.exitCode !== null) return;
    await new Promise<void>((resolve) => {
      api.once('exit', () => {
        resolve();
      });
      api.kill('SIGTERM');
    });
    this.api = undefined;
  }

  /** `ruvee-admin backup` of the running installation; returns the manifest and digest. */
  backup(): { manifest: string; digest: string } {
    const out = run(
      ['dist/admin/cli.js', 'backup', '--out', this.backups, '--synthetic-test-only'],
      {
        DATABASE_URL: urlFor(this.current),
        BACKUP_AGE_RECIPIENT: this.recipient,
      },
    );
    const digest = /Backup digest: ([0-9a-f]{64})/.exec(out)?.[1] ?? '';
    const manifest = readdirSync(this.backups).find((f) => f.endsWith('.manifest.json')) ?? '';
    return { manifest: join(this.backups, manifest), digest };
  }

  /** `ruvee-admin restore` into a new, empty database; returns it and the restore id. */
  restore(backup: { manifest: string; digest: string }): { database: string; restoreId: string } {
    const database = this.newDatabase();
    const out = run(
      [
        'dist/admin/cli.js',
        'restore',
        '--manifest',
        backup.manifest,
        '--identity',
        this.identityFile,
        '--trusted-digest',
        backup.digest,
      ],
      { RESTORE_DATABASE_URL: urlFor(database) },
    );
    return { database, restoreId: /Restore id: ([0-9a-f-]{36})/.exec(out)?.[1] ?? '' };
  }

  review(database: string): string {
    return run(['dist/admin/cli.js', 'restore-review'], { RESTORE_DATABASE_URL: urlFor(database) });
  }

  /** `restore-complete`: ends the review; returns the reopening code it prints once. */
  complete(database: string, restoreId: string): string {
    const out = run(
      [
        'dist/admin/cli.js',
        'restore-complete',
        '--restore-id',
        restoreId,
        '--devices-reviewed',
        '--accept-restored-credentials',
      ],
      { RESTORE_DATABASE_URL: urlFor(database) },
    );
    return /\n\s+(RC1-[A-Za-z0-9_-]{43})\n/.exec(out)?.[1] ?? '';
  }

  /** `restore-reopen-code`: the host retry path; revokes the previous code. */
  reopenCode(database: string, restoreId: string): string {
    const out = run(['dist/admin/cli.js', 'restore-reopen-code', '--restore-id', restoreId], {
      RESTORE_DATABASE_URL: urlFor(database),
    });
    return /\n\s+(RC1-[A-Za-z0-9_-]{43})\n/.exec(out)?.[1] ?? '';
  }

  /** Stops the API and removes exactly what this stack created. */
  async cleanup(): Promise<void> {
    await this.stop();
    for (const name of this.databases) run(['scripts/e2e-db.mjs', 'drop', name]);
    rmSync(this.dir, { recursive: true, force: true });
  }
}
