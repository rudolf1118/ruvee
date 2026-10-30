/**
 * `ruvee-admin`: operator commands run on the server host (authentication.md §3). There is no
 * HTTP administration API. Output goes to this terminal only; nothing is logged.
 *
 *   ruvee-admin opaque-setup --out <path>   create the OPAQUE server setup file (mode 0600)
 *   ruvee-admin init                        mark the database as a fresh installation (once, before
 *                                           first use) and grant the runtime role its list; a
 *                                           database without it is never served
 *   ruvee-admin grant-runtime               set the runtime role's privileges to exactly its list
 *                                           (after every migration)
 *   ruvee-admin bootstrap-token             print a single-use setup token valid for 60 minutes
 *   ruvee-admin backup --out <dir> --synthetic-test-only
 *                                           encrypted dump of the database to BACKUP_AGE_RECIPIENT
 *   ruvee-admin restore --manifest <file> --identity <file> (--trusted-digest <sha256> | --no-trusted-digest)
 *                                           restore into RESTORE_DATABASE_URL (new, empty)
 *   ruvee-admin restore-review [--revoke-device <id> --reason lost|retired]
 *   ruvee-admin restore-complete --restore-id <id> --devices-reviewed --accept-restored-credentials
 *                                           ends the review; prints the reopening code once
 *   ruvee-admin restore-reopen-code --restore-id <id>
 *                                           a new reopening code (revokes the previous one)
 *
 * Restore commands read RESTORE_DATABASE_URL, never a command-line URL, so no password appears
 * in the process list (backup-restore.md §3.5, §3.6a). Every other database command reads
 * RUVEE_ADMIN_DATABASE_URL. Both are the **operator** role's credentials, never the API's
 * DATABASE_URL (database-roles.md, follow-up review F-25); RUVEE_RUNTIME_ROLE names the API's
 * role (a name, no password) for the commands that grant it its list.
 */
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { PrismaPg } from '@prisma/adapter-pg';
import * as opaque from '@serenity-kit/opaque';
import { randomToken, sha256 } from '../common/secrets.js';
import { PrismaClient } from '../generated/prisma/client.js';
import { applyRuntimeGrants, assertOperator, checkRoleName, RoleError } from './database-roles.js';
import { connectTo, DbTargetError, parseDbTarget } from './db-target.js';
import { InstallationError, initInstallation } from './installation.js';
import { pgToolsFromEnv } from './pg-tools.js';
import {
  completeRestore,
  issueReopenCode,
  type IssuedReopenCode,
  createBackup,
  knownMigrations,
  restoreBackup,
  RestoreError,
  reviewRestore,
  revokeDeviceInReview,
} from './server-restore.js';

// Operator commands act only on the URLs they are given: no inherited PG* variable (PGSERVICE,
// PGHOSTADDR, PGOPTIONS, PGDATABASE…) may redirect node-pg or the tools (predeployment-review R7).
for (const key of Object.keys(process.env))
  if (key.toUpperCase().startsWith('PG')) Reflect.deleteProperty(process.env, key);

const apiRoot = new URL('../../', import.meta.url).pathname;

function option(args: string[], name: string): string | undefined {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
}

function restoreUrl(): string {
  const url = process.env.RESTORE_DATABASE_URL;
  if (!url) fail('RESTORE_DATABASE_URL is not set (the new, empty database to restore into)');
  return url;
}

/** The operator role's URL for the commands that are not restore commands. */
function adminUrl(): string {
  const url = process.env.RUVEE_ADMIN_DATABASE_URL;
  if (!url)
    fail(
      'RUVEE_ADMIN_DATABASE_URL is not set (the operator role, not the API runtime DATABASE_URL; see docs/guides/database-roles.md)',
    );
  return url;
}

function runtimeRole(): string {
  try {
    return checkRoleName(process.env.RUVEE_RUNTIME_ROLE, 'RUVEE_RUNTIME_ROLE');
  } catch (error) {
    if (error instanceof RoleError) fail(`${error.message} (the API's database role)`);
    throw error;
  }
}

/** SIGINT and SIGTERM stop a backup or restore cleanly instead of killing it mid-write. */
function interruptible(): AbortSignal {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM'] as const)
    process.once(signal, () => {
      controller.abort();
    });
  return controller.signal;
}

async function backup(args: string[]): Promise<void> {
  const out = option(args, '--out');
  if (!out)
    fail(
      'usage: RUVEE_ADMIN_DATABASE_URL=… BACKUP_AGE_RECIPIENT=age1… ruvee-admin backup --out <dir> --synthetic-test-only',
    );
  const url = adminUrl();
  const result = await createBackup({
    databaseUrl: url,
    outDir: out,
    tools: pgToolsFromEnv(),
    recipient: process.env.BACKUP_AGE_RECIPIENT,
    syntheticTestOnly: args.includes('--synthetic-test-only'),
    signal: interruptible(),
    config: {
      publicOrigin: process.env.PUBLIC_ORIGIN ?? '',
      sessionCookieSecure: process.env.SESSION_COOKIE_SECURE === 'false' ? 'false' : 'true',
      extensionOrigins: process.env.EXTENSION_ORIGINS ?? '',
    },
  });
  process.stdout.write(
    `Wrote the encrypted backup ${result.manifestPath}\n` +
      `(snapshot of ${result.snapshotAt}, with ${result.manifest.files.dump.file} and ` +
      `${result.manifest.files.meta.file}).\n\n` +
      `Backup digest: ${result.digest}\n\n` +
      'Record this digest somewhere the backup storage cannot change (for example with the\n' +
      'offline identity). A restore checks it: it is the only proof that a backup is yours,\n' +
      'because anyone who knows the public recipient can make a backup that decrypts.\n' +
      'Synthetic test backup only: real-data backups wait until M1 is accepted (D-19, D-30).\n',
  );
}

async function restore(args: string[]): Promise<void> {
  const manifest = option(args, '--manifest');
  const identity = option(args, '--identity');
  const digest = option(args, '--trusted-digest');
  // Where the dump's ciphertext is staged privately for the restore (review R9).
  const staging = option(args, '--staging-dir');
  const unchecked = args.includes('--no-trusted-digest');
  if (!manifest || !identity || (!digest && !unchecked) || (digest && unchecked))
    fail(
      'usage: RESTORE_DATABASE_URL=… ruvee-admin restore --manifest <file> --identity <file>\n' +
        '       (--trusted-digest <sha256> | --no-trusted-digest) [--staging-dir <dir>]',
    );
  const result = await restoreBackup({
    manifestPath: manifest,
    identityPath: identity,
    trustedDigest: digest ?? false,
    ...(staging ? { stagingRoot: staging } : {}),
    targetDatabaseUrl: restoreUrl(),
    runtimeRole: runtimeRole(),
    tools: pgToolsFromEnv(),
    knownMigrations: knownMigrations(`${apiRoot}prisma/migrations`),
    migrate: (url) => {
      const run = spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
        cwd: apiRoot,
        env: { ...process.env, DATABASE_URL: url, PRISMA_HIDE_UPDATE_MESSAGE: '1' },
        encoding: 'utf8',
      });
      if (run.status !== 0) throw new Error('prisma migrate deploy failed');
    },
  });
  if (!('removed' in result)) return;
  process.stdout.write(
    `Restored the snapshot of ${result.snapshotAt}.\nRestore id: ${result.restoreId}\n` +
      (result.provenance === 'unchecked'
        ? `Provenance NOT checked: compare the backup digest ${result.digest} with your own record.\n`
        : 'The backup digest matched the one you supplied.\n') +
      `Ended ${String(result.removed.sessions)} sessions, deleted ${String(result.removed.pairings)} ` +
      `pairings and ${String(result.removed.setupTokens)} unused setup tokens.\n` +
      'The installation is in maintenance: every API request is refused until you complete the\n' +
      'review. You can now delete the identity file from this host. Next: ruvee-admin restore-review\n',
  );
}

async function review(args: string[]): Promise<void> {
  const url = restoreUrl();
  const device = option(args, '--revoke-device');
  if (device) {
    const reason = option(args, '--reason');
    if (reason !== 'lost' && reason !== 'retired') fail('--reason lost|retired');
    await revokeDeviceInReview(url, device, reason);
    process.stdout.write(`Revoked ${device.slice(0, 8)}… (${reason}).\n`);
    if (reason === 'lost')
      process.stdout.write(
        'After opening, replace the Secret Key from an enrolled device (Security): the server\n' +
          'cannot rotate it, and rotating it never revokes copies already taken.\n',
      );
  }
  const r = await reviewRestore(url);
  const lines = [
    `Restore ${r.restoreId}: ${r.state}`,
    `Snapshot of ${r.snapshotAt}, backup digest ${r.backupDigest}`,
    r.provenance === 'unchecked'
      ? 'Provenance NOT checked at restore: compare the digest with your own record before opening.'
      : 'Provenance: the digest matched the operator-supplied record.',
    r.account ? `Account: ${r.account.username}` : 'No account: the snapshot predates the account.',
    '',
    'Devices as of the snapshot (revoke any removed after it, before opening):',
    ...r.devices.map(
      (d) =>
        `  ${d.id}  ${d.platform.padEnd(9)} ${d.status.padEnd(8)} last seen ${d.lastSeenAt ?? 'never'}`,
    ),
    '',
    'For the reopening only, together with the host-issued code, these work again:',
    `  the master password set ${r.validAgain.passwordSetAt ?? '(none)'} (from a device active below)`,
    `  the Recovery Kit of ${r.validAgain.recoveryKitSetAt ?? '(none)'}`,
    `  keyset version ${String(r.validAgain.keysetVersion ?? '(none)')}, and the Secret Key in it`,
    `  ${String(r.validAgain.activeDevices)} active devices, with whatever keys they hold`,
    'The reopening replaces the password and the Recovery Kit before anything else opens; then',
    'replace the Secret Key if a device was lost. The server cannot know about devices added or',
    'removed, password, kit or Secret Key changes, recoveries or item changes after the snapshot.',
    'Ending sessions and replacing the Secret Key never revoke ciphertext or keys that anyone',
    'already copied, from this server or a device.',
    '',
    `To open: ruvee-admin restore-complete --restore-id ${r.restoreId} --devices-reviewed --accept-restored-credentials`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

async function complete(args: string[]): Promise<void> {
  const id = option(args, '--restore-id');
  if (!id)
    fail(
      'usage: ruvee-admin restore-complete --restore-id <id> --devices-reviewed --accept-restored-credentials',
    );
  const result = await completeRestore(restoreUrl(), {
    restoreId: id,
    devicesReviewed: args.includes('--devices-reviewed'),
    acceptRestoredCredentials: args.includes('--accept-restored-credentials'),
  });
  if (result.state === 'open') {
    process.stdout.write(
      'The snapshot had no account: the installation is open, and setting up needs a new token\n' +
        '(ruvee-admin bootstrap-token).\n',
    );
    return;
  }
  printReopenCode(result.reopen, id);
}

/**
 * The reopening code goes to this terminal only, once (backup-restore.md §3.13). It is never
 * logged, and only its hash is stored.
 */
function printReopenCode(reopen: IssuedReopenCode, restoreId: string): void {
  process.stdout.write(
    'The review is complete. The installation now waits to be reopened by its owner: every\n' +
      'other request is still refused.\n\n' +
      `Reopening code (single use, expires ${reopen.expiresAt}; only its hash is stored):\n\n` +
      `  ${reopen.code}\n\n` +
      'Give it to the owner in person. In the web app, the owner enters it together with the\n' +
      'master password or the Recovery Kit as of the backup, then must set a new password and a\n' +
      'new Recovery Kit before anything else works. Five failed attempts with it revoke it.\n' +
      `New code (revokes this one and any reopening in progress):\n` +
      `  ruvee-admin restore-reopen-code --restore-id ${restoreId}\n`,
  );
}

async function reopenCode(args: string[]): Promise<void> {
  const id = option(args, '--restore-id');
  if (!id) fail('usage: RESTORE_DATABASE_URL=… ruvee-admin restore-reopen-code --restore-id <id>');
  printReopenCode(await issueReopenCode(restoreUrl(), { restoreId: id }), id);
}

const BOOTSTRAP_TOKEN_TTL_MS = 60 * 60 * 1000;

function fail(message: string): never {
  process.stderr.write(`ruvee-admin: ${message}\n`);
  process.exit(1);
}

async function opaqueSetup(args: string[]): Promise<void> {
  const at = args.indexOf('--out');
  const out = at >= 0 ? args[at + 1] : undefined;
  if (!out) fail('usage: ruvee-admin opaque-setup --out <path>');
  if (existsSync(out)) fail('refusing to overwrite an existing file');
  await opaque.ready;
  // 'wx' fails if the file appeared meanwhile; the mode applies on creation.
  writeFileSync(out, `${opaque.server.createSetup()}\n`, { mode: 0o600, flag: 'wx' });
  process.stdout.write(
    `Wrote the OPAQUE server setup to ${out} (mode 0600).\n` +
      'Back it up offline. Losing it makes every login fail until the Recovery Kit is used;\n' +
      'anyone who has it together with the database can guess passwords offline.\n',
  );
}

async function bootstrapToken(): Promise<void> {
  const url = adminUrl();
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });
  try {
    if ((await prisma.account.count()) > 0)
      fail('an account already exists; registration is closed');
    const token = randomToken();
    const now = Date.now();
    await prisma.bootstrapToken.create({
      data: {
        id: randomUUID(),
        tokenHash: sha256(Buffer.from(token, 'base64url')),
        createdAt: new Date(now),
        expiresAt: new Date(now + BOOTSTRAP_TOKEN_TTL_MS),
      },
    });
    process.stdout.write(
      `Setup token (single use, expires in 60 minutes; only its hash is stored):\n\n  ${token}\n\n`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

/**
 * A fresh installation is opened explicitly (predeployment-review R14): until `init`, the API
 * serves nothing but health checks, so a database that was never set up, or a restore target,
 * can never be mistaken for an open installation.
 */
async function adminClient() {
  try {
    return await connectTo(parseDbTarget(adminUrl()));
  } catch (error) {
    if (error instanceof DbTargetError) fail(error.message);
    throw error;
  }
}

async function init(): Promise<void> {
  const role = runtimeRole();
  const c = await adminClient();
  try {
    await initInstallation(c, role);
  } catch (error) {
    if (error instanceof InstallationError) fail(error.message);
    throw error;
  } finally {
    await c.end();
  }
  process.stdout.write(
    'Initialized as a fresh installation. The API now serves it; next: ruvee-admin bootstrap-token\n',
  );
}

/**
 * After every `prisma migrate deploy` (which runs as the schema owner): the runtime role gets
 * exactly its list, including a table the migration added only once runtime-privileges.ts lists
 * it. Also how a database set up before F-25 is moved to the separated roles (the guide).
 */
async function grantRuntime(): Promise<void> {
  const role = runtimeRole();
  const c = await adminClient();
  try {
    await assertOperator(c, role);
    await c.query('BEGIN');
    try {
      await applyRuntimeGrants(c, role);
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    }
  } catch (error) {
    if (error instanceof RoleError) fail(error.message);
    throw error;
  } finally {
    await c.end();
  }
  process.stdout.write(`The runtime role ${role} now has exactly its listed privileges.\n`);
}

const [command, ...rest] = process.argv.slice(2);
switch (command) {
  case 'init':
    await init();
    break;
  case 'grant-runtime':
    await grantRuntime();
    break;
  case 'opaque-setup':
    await opaqueSetup(rest);
    break;
  case 'bootstrap-token':
    await bootstrapToken();
    break;
  case 'backup':
  case 'restore':
  case 'restore-review':
  case 'restore-complete':
  case 'restore-reopen-code':
    try {
      if (command === 'backup') await backup(rest);
      else if (command === 'restore') await restore(rest);
      else if (command === 'restore-review') await review(rest);
      else if (command === 'restore-reopen-code') await reopenCode(rest);
      else await complete(rest);
    } catch (error) {
      if (error instanceof RestoreError) fail(`${error.stage}: ${error.message}`);
      throw error;
    }
    break;
  default:
    fail(
      'commands: init | grant-runtime | opaque-setup | bootstrap-token | backup | restore | restore-review | restore-complete | restore-reopen-code',
    );
}
