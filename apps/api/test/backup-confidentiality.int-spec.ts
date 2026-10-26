import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { TABLE_INVENTORY } from '../src/admin/backup-inventory.js';
import { openBackup } from '../src/admin/backup-files.js';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
import { createBackup, type BackupResult } from '../src/admin/server-restore.js';
import { sessionCookie, startHarness, WRITE_HEADERS, type Harness } from './support/api-harness.js';
import { testBackupKey, type TestBackupKey } from './support/backup-keys.js';
import {
  finishRegistration,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { VaultWriter } from './support/vault-writer.js';
import { registerStartResponseSchema } from '@ruvee/contracts';

/**
 * R13 (backup-restore.md §6): what a decrypted backup contains, against the documented
 * boundary (§3.1, security-invariants INV-01, INV-13, INV-21). Every secret is a sentinel made
 * for this test. A decrypted dump deliberately holds authentication records (the OPAQUE
 * registration record, hashes of tokens and of `RAK`) and ciphertext (wraps, items, manifests);
 * it must never hold a plaintext vault secret, a key, a password, a Recovery Key, a raw token or
 * the OPAQUE server setup.
 */

const tools = pgToolsFromEnv();
const ITEM_TITLE = 'R13-SENTINEL-TITLE-7f3a9c';
const ITEM_PASSWORD = 'R13-SENTINEL-ITEM-PASSWORD-e41b0d';
const ITEM_NOTE = 'R13-SENTINEL-NOTE-a90c55';
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha256Hex = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

describe('R13: a decrypted backup holds authentication records and ciphertext, never secrets', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let key: TestBackupKey;
  let outDir: string;
  let backup: BackupResult;
  let sql: string;
  let sessionToken: string;
  let unusedSetupToken: string;
  let registrationRecord: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-r13-owner');
    // Registration by hand, to know the record and the raw setup token.
    const token = await h.bootstrapToken();
    const reg = startRegistration();
    const start = await h
      .post('/api/v1/auth/register/start', {
        bootstrapToken: token,
        username: account.username,
        registrationRequest: reg.registrationRequest,
      })
      .expect(200);
    registrationRecord = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(start.body).registrationResponse,
    );
    const finished = await h
      .post('/api/v1/auth/register/finish', account.finish(registrationRecord, token))
      .expect(201);
    const cookie = sessionCookie(finished);
    sessionToken = cookie.slice(cookie.indexOf('=') + 1);
    const writer = new VaultWriter(h, account, cookie);
    await writer.add();
    await writer.add({
      v: 1,
      type: 'login',
      title: ITEM_TITLE,
      login: { username: 'r13@mail.example', password: ITEM_PASSWORD, urls: [], notes: ITEM_NOTE },
    });
    // A setup token minted after the account: refused by the API, but its hash is in the dump.
    unusedSetupToken = await h.bootstrapToken();

    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-r13-it-'));
    backup = await createBackup({
      databaseUrl: h.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config: {
        publicOrigin: WRITE_HEADERS.Origin,
        sessionCookieSecure: 'true',
        extensionOrigins: '',
      },
    });
    // Decrypt with the synthetic identity and turn the dump into SQL, all in memory.
    const opened = await openBackup({
      manifestPath: backup.manifestPath,
      identityPath: key.identityPath,
      trustedDigest: backup.digest,
    });
    const { plaintext } = await opened.decryptDump();
    const run = tools.toSql();
    const chunks: Buffer[] = [];
    run.stdout.on('data', (c: Buffer) => chunks.push(c));
    await pipeline(plaintext, run.stdin);
    await run.done;
    opened.cleanup();
    sql = Buffer.concat(chunks).toString('utf8');
  }, 120_000);

  afterAll(async () => {
    await (h as Harness | undefined)?.close();
    rmSync(outDir, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  it('is the whole database: every inventoried table, and never the restore guard', () => {
    for (const table of Object.keys(TABLE_INVENTORY))
      expect(sql, table).toMatch(new RegExp(`COPY public\\.${table} `));
    // The restore tool's control schema (guard and reopening codes) is never in a backup.
    expect(sql).not.toContain('ruvee_control');
    expect(sql).not.toContain('restore_guard');
    expect(sql).not.toContain('reopen_codes');
  });

  it('holds no plaintext vault secret, key, password or Recovery Key', () => {
    const forbidden: Record<string, string> = {
      'item title': ITEM_TITLE,
      'item password': ITEM_PASSWORD,
      'item note': ITEM_NOTE,
      'master password': SYNTHETIC_PASSWORD,
      'Recovery Key text': account.recoveryKeyText,
      'Recovery Key, compact': account.recoveryKeyText.replace(/-/g, ''),
      'account key (hex)': hex(account.accountKey),
      'account key (base64url)': b64(account.accountKey),
      'vault key (hex)': hex(account.vaultKey),
      'vault key (base64url)': b64(account.vaultKey),
      'Secret Key (hex)': hex(account.secretKey),
      'Secret Key (base64url)': b64(account.secretKey),
    };
    const rak = account.crypto.deriveRecoveryKeys(
      account.crypto.parseRecoveryKey(account.recoveryKeyText),
    );
    forbidden['recovery auth key (hex)'] = hex(rak.recoveryAuthKey);
    forbidden['recovery wrap key (hex)'] = hex(rak.recoveryWrapKey);
    for (const [what, value] of Object.entries(forbidden)) expect(sql, what).not.toContain(value);
  });

  it('holds no raw token and no OPAQUE server setup, only hashes (INV-13, INV-21)', () => {
    const setup = readFileSync(process.env.OPAQUE_SERVER_SETUP_FILE ?? '', 'utf8').trim();
    expect(sql, 'OPAQUE server setup').not.toContain(setup);
    // Deliberately present: the SHA-256 the server stores instead (session tokens are hashed
    // as text, setup tokens over their decoded bytes; session.service.ts, admin/cli.ts).
    for (const [what, token, hash] of [
      ['session token', sessionToken, sha256Hex(Buffer.from(sessionToken, 'utf8'))],
      [
        'unused setup token',
        unusedSetupToken,
        sha256Hex(Buffer.from(unusedSetupToken, 'base64url')),
      ],
    ] as const) {
      expect(sql, what).not.toContain(token);
      expect(sql, `${what} hash`).toContain(hash);
    }
  });

  it('deliberately holds the authentication records the boundary allows', () => {
    // The OPAQUE registration record (with the setup file: offline guessing, V-01) and the
    // username are authentication records; both are expected in a dump.
    expect(sql).toContain(account.username);
    expect(sql).toContain(hex(Buffer.from(registrationRecord, 'base64url')).slice(0, 64));
  });

  it('shows none of it in the files at rest: ciphertext and a manifest without metadata', () => {
    const atRest = [backup.dumpPath, backup.metaPath, backup.manifestPath]
      .map((p) => readFileSync(p).toString('latin1'))
      .join('\n');
    for (const value of [
      account.username,
      ITEM_TITLE,
      sessionToken,
      unusedSetupToken,
      hex(account.accountKey),
      WRITE_HEADERS.Origin,
    ])
      expect(atRest).not.toContain(value);
  });
});
