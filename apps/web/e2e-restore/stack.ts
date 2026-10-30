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
 * commands, as an operator would run them. Each database has its own roles (database-roles.md,
 * F-25): migrations run as the schema owner, `ruvee-admin` as the operator, and the API as the
 * runtime role. Synthetic data and a synthetic age identity only.
 */

const apiRoot = new URL('../../api/', import.meta.url).pathname;

interface Role {
  readonly name: string;
  readonly url: string;
}
type Roles = Record<'owner' | 'operator' | 'runtime', Role>;

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
  private readonly databases = new Map<string, Roles>();
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
    if (!process.env.RUVEE_E2E_ADMIN_DATABASE_URL)
      throw new Error('Set RUVEE_E2E_ADMIN_DATABASE_URL');
    const name = `ruvee_e2e_${randomBytes(6).toString('hex')}`;
    this.databases.set(name, JSON.parse(run(['scripts/e2e-db.mjs', 'create', name])) as Roles);
    return name;
  }

  private roles(name: string): Roles {
    const roles = this.databases.get(name);
    if (!roles) throw new Error('not a database of this stack');
    return roles;
  }

  /** The operator's environment for `ruvee-admin` on `name`. */
  private operator(name: string, variable: 'RUVEE_ADMIN_DATABASE_URL' | 'RESTORE_DATABASE_URL') {
    const roles = this.roles(name);
    return { [variable]: roles.operator.url, RUVEE_RUNTIME_ROLE: roles.runtime.name };
  }

  /** A fresh installation: database, migrations, `init`, OPAQUE setup, setup token, age key pair. */
  async init(): Promise<void> {
    const name = this.newDatabase();
    spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
      cwd: apiRoot,
      env: {
        ...process.env,
        DATABASE_URL: this.roles(name).owner.url,
        PRISMA_HIDE_UPDATE_MESSAGE: '1',
      },
    });
    // Opened explicitly, as an operator does once for a new installation (review R14).
    run(['dist/admin/cli.js', 'init'], this.operator(name, 'RUVEE_ADMIN_DATABASE_URL'));
    run(['dist/admin/cli.js', 'opaque-setup', '--out', this.setupFile]);
    const out = run(
      ['dist/admin/cli.js', 'bootstrap-token'],
      this.operator(name, 'RUVEE_ADMIN_DATABASE_URL'),
    );
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
    // The API gets the runtime role's URL only, never the administrator's.
    const env = { ...process.env };
    delete env.RUVEE_E2E_ADMIN_DATABASE_URL;
    this.api = spawn('node', ['dist/main.js'], {
      cwd: apiRoot,
      env: {
        ...env,
        DATABASE_URL: this.roles(name).runtime.url,
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
        ...this.operator(this.current, 'RUVEE_ADMIN_DATABASE_URL'),
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
      this.operator(database, 'RESTORE_DATABASE_URL'),
    );
    return { database, restoreId: /Restore id: ([0-9a-f-]{36})/.exec(out)?.[1] ?? '' };
  }

  review(database: string): string {
    return run(
      ['dist/admin/cli.js', 'restore-review'],
      this.operator(database, 'RESTORE_DATABASE_URL'),
    );
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
      this.operator(database, 'RESTORE_DATABASE_URL'),
    );
    return /\n\s+(RC1-[A-Za-z0-9_-]{43})\n/.exec(out)?.[1] ?? '';
  }

  /** `restore-reopen-code`: the host retry path; revokes the previous code. */
  reopenCode(database: string, restoreId: string): string {
    const out = run(
      ['dist/admin/cli.js', 'restore-reopen-code', '--restore-id', restoreId],
      this.operator(database, 'RESTORE_DATABASE_URL'),
    );
    return /\n\s+(RC1-[A-Za-z0-9_-]{43})\n/.exec(out)?.[1] ?? '';
  }

  /** Stops the API and removes exactly what this stack created. */
  async cleanup(): Promise<void> {
    await this.stop();
    for (const name of this.databases.keys()) run(['scripts/e2e-db.mjs', 'drop', name]);
    rmSync(this.dir, { recursive: true, force: true });
  }
}
