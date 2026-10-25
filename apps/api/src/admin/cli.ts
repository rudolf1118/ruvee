/**
 * `ruvee-admin`: operator commands run on the server host (authentication.md §3). There is no
 * HTTP administration API. Output goes to this terminal only; nothing is logged.
 *
 *   ruvee-admin opaque-setup --out <path>   create the OPAQUE server setup file (mode 0600)
 *   ruvee-admin bootstrap-token             print a single-use setup token valid for 60 minutes
 */
import { randomUUID } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { PrismaPg } from '@prisma/adapter-pg';
import * as opaque from '@serenity-kit/opaque';
import { randomToken, sha256 } from '../common/secrets.js';
import { PrismaClient } from '../generated/prisma/client.js';

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
  default:
    fail('commands: opaque-setup --out <path> | bootstrap-token');
}
