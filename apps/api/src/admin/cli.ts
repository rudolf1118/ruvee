/**
 * `ruvee-admin`: operator commands run on the server host (authentication.md §3). There is no
 * HTTP administration API. Output goes to this terminal only; nothing is logged.
 *
 *   ruvee-admin opaque-setup --out <path>   create the OPAQUE server setup file (mode 0600)
 *   ruvee-admin bootstrap-token             print a single-use setup token valid for 60 minutes
 *   ruvee-admin backup --out <dir> --synthetic-test-only
 *                                           dump DATABASE_URL (synthetic only until D-29)
 *   ruvee-admin restore --sidecar <path>    restore into RESTORE_DATABASE_URL (new, empty)
 *   ruvee-admin restore-review [--revoke-device <id> --reason lost|retired]
 *   ruvee-admin restore-complete --restore-id <id> --devices-reviewed --accept-restored-credentials
 *
 * Restore commands read RESTORE_DATABASE_URL, never a command-line URL, so no password appears
 * in the process list (backup-restore.md §3.5, §3.6a).
 */
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { PrismaPg } from '@prisma/adapter-pg';
import * as opaque from '@serenity-kit/opaque';
import { randomToken, sha256 } from '../common/secrets.js';
import { PrismaClient } from '../generated/prisma/client.js';
import { pgToolsFromEnv } from './pg-tools.js';
import {
  completeRestore,
  createBackup,
  knownMigrations,
  restoreBackup,
  RestoreError,
  reviewRestore,
  revokeDeviceInReview,
} from './server-restore.js';

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

async function backup(args: string[]): Promise<void> {
  const url = process.env.DATABASE_URL;
  const out = option(args, '--out');
  if (!url || !out)
    fail('usage: DATABASE_URL=… ruvee-admin backup --out <dir> --synthetic-test-only');
  const result = await createBackup({
    databaseUrl: url,
    outDir: out,
    tools: pgToolsFromEnv(),
    syntheticTestOnly: args.includes('--synthetic-test-only'),
    config: {
      publicOrigin: process.env.PUBLIC_ORIGIN ?? '',
      sessionCookieSecure: process.env.SESSION_COOKIE_SECURE === 'false' ? 'false' : 'true',
      extensionOrigins: process.env.EXTENSION_ORIGINS ?? '',
    },
  });
  process.stdout.write(
    `Wrote ${result.dumpPath}\nand ${result.sidecarPath} (SHA-256 ${result.sidecar.dump.sha256}).\n` +
      'This is an unencrypted synthetic test backup; real-data backups wait for D-29.\n',
  );
}

async function restore(args: string[]): Promise<void> {
  const sidecar = option(args, '--sidecar');
  if (!sidecar) fail('usage: RESTORE_DATABASE_URL=… ruvee-admin restore --sidecar <path>');
  const result = await restoreBackup({
    sidecarPath: sidecar,
    targetDatabaseUrl: restoreUrl(),
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
      `Ended ${String(result.removed.sessions)} sessions, deleted ${String(result.removed.pairings)} ` +
      `pairings and ${String(result.removed.setupTokens)} unused setup tokens.\n` +
      'The installation is in maintenance: every API request is refused until you complete the\n' +
      'review. Next: ruvee-admin restore-review\n',
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
    `Snapshot of ${r.snapshotAt}, dump SHA-256 ${r.dumpSha256}`,
    r.account ? `Account: ${r.account.username}` : 'No account: the snapshot predates the account.',
    '',
    'Devices as of the snapshot (revoke any removed after it, before opening):',
    ...r.devices.map(
      (d) =>
        `  ${d.id}  ${d.platform.padEnd(9)} ${d.status.padEnd(8)} last seen ${d.lastSeenAt ?? 'never'}`,
    ),
    '',
    'When maintenance ends, these become valid again:',
    `  the master password set ${r.validAgain.passwordSetAt ?? '(none)'}`,
    `  the Recovery Kit of ${r.validAgain.recoveryKitSetAt ?? '(none)'}`,
    `  keyset version ${String(r.validAgain.keysetVersion ?? '(none)')}, and the Secret Key in it`,
    `  ${String(r.validAgain.activeDevices)} active devices, with whatever keys they hold`,
    'If you changed the password, replaced the Recovery Kit or the Secret Key after the snapshot,',
    'repeat it right after opening. The server cannot know about devices added or removed,',
    'password, kit or Secret Key changes, recoveries or item changes after the snapshot.',
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
  await completeRestore(restoreUrl(), {
    restoreId: id,
    devicesReviewed: args.includes('--devices-reviewed'),
    acceptRestoredCredentials: args.includes('--accept-restored-credentials'),
  });
  process.stdout.write(
    'The installation is open. If the snapshot had no account, registration needs a new token.\n',
  );
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
  const url = process.env.DATABASE_URL;
  if (!url) fail('DATABASE_URL is not set');
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

const [command, ...rest] = process.argv.slice(2);
switch (command) {
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
    try {
      if (command === 'backup') await backup(rest);
      else if (command === 'restore') await restore(rest);
      else if (command === 'restore-review') await review(rest);
      else await complete(rest);
    } catch (error) {
      if (error instanceof RestoreError) fail(`${error.stage}: ${error.message}`);
      throw error;
    }
    break;
  default:
    fail(
      'commands: opaque-setup | bootstrap-token | backup | restore | restore-review | restore-complete',
    );
}
