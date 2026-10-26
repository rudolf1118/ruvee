import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  createReadStream,
  createWriteStream,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  type Stats,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import {
  pipeline as streamPipeline,
  Readable,
  Transform,
  Writable,
  type TransformCallback,
} from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { Decrypter, Encrypter, identityToRecipient } from 'age-encryption';
import { z } from 'zod';

/**
 * The encrypted backup set (backup-restore.md §3.2, D-29 option B). Three files with one stem:
 *
 *   <stem>.dump.age       age(pg_dump --format=custom), streamed; no plaintext file ever exists
 *   <stem>.meta.age       age(JSON): snapshot time, schema, configuration, the dump's plaintext
 *                         SHA-256 and size, the backup id
 *   <stem>.manifest.json  plain: the backup id, the recipient, each ciphertext's size and SHA-256;
 *                         written last, so a set without it is never a complete backup
 *
 * Encryption is the age format (age-encryption.org/v1) through `age-encryption`, the reference
 * TypeScript implementation by age's author, pinned exactly. Nothing here implements a
 * primitive or a format. Files are X25519-only: the server holds the recipient (public key);
 * the identity (private key) is held offline by the owner and is needed only to restore.
 *
 * age does not authenticate the sender: anyone who knows the recipient can make a set that
 * decrypts. The manifest's own SHA-256, the "backup digest", proves provenance only when the
 * operator compares it with a copy kept apart from backup storage (§3.2a).
 */

export const BACKUP_FORMAT = 'ruvee-server-backup/2';
export const META_FORMAT = 'ruvee-server-backup-meta/2';
/** An age X25519 recipient (Bech32, `age1` + 58 characters). Post-quantum recipients: not in D-29. */
export const RECIPIENT = /^age1[02-9ac-hj-np-z]{58}$/;
const IDENTITY = /^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$/;
const STEM = /^ruvee-[0-9]{8}T[0-9]{9}Z$/;
const SHA256 = /^[0-9a-f]{64}$/;

export const MAX_MANIFEST_BYTES = 4096;
export const MAX_META_BYTES = 64 * 1024;
const MAX_IDENTITY_FILE_BYTES = 4096;
/** Bound on a dump's ciphertext; larger sets are refused before anything is read. */
export const DEFAULT_MAX_DUMP_BYTES = 16 * 2 ** 30;

export class BackupError extends Error {
  constructor(
    readonly stage: 'backup' | 'verify',
    message: string,
  ) {
    super(message);
    this.name = 'BackupError';
  }
}

const fileEntry = (kind: 'dump' | 'meta') =>
  z.strictObject({
    file: z
      .string()
      .max(64)
      .regex(new RegExp(`^ruvee-[0-9]{8}T[0-9]{9}Z\\.${kind}\\.age$`)),
    size: z.int().min(1),
    sha256: z.string().regex(SHA256),
  });

export const manifestSchema = z.strictObject({
  format: z.literal(BACKUP_FORMAT),
  backupId: z.uuid(),
  recipient: z.string().regex(RECIPIENT),
  files: z.strictObject({ dump: fileEntry('dump'), meta: fileEntry('meta') }),
});
export type Manifest = z.infer<typeof manifestSchema>;

export const metaSchema = z.strictObject({
  format: z.literal(META_FORMAT),
  backupId: z.uuid(),
  /** True for every backup until M1 is accepted for real data (D-19, D-30). */
  synthetic: z.literal(true),
  snapshotAt: z.iso.datetime({ offset: false }),
  dump: z.strictObject({ sha256: z.string().regex(SHA256), size: z.int().min(1) }),
  schema: z.strictObject({ migration: z.string().regex(/^[0-9]{14}_[a-z0-9_]{1,100}$/) }),
  config: z.strictObject({
    publicOrigin: z.string().max(256),
    sessionCookieSecure: z.enum(['true', 'false']),
    extensionOrigins: z.string().max(2000),
  }),
});
export type BackupMeta = z.infer<typeof metaSchema>;

/** Counts and hashes what passes through; fails once more than `maxBytes` went by. */
export class Tap extends Transform {
  readonly hash = createHash('sha256');
  bytes = 0;
  constructor(private readonly maxBytes = Number.POSITIVE_INFINITY) {
    super();
  }
  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) {
    this.bytes += chunk.length;
    if (this.bytes > this.maxBytes) {
      callback(new BackupError('verify', 'more data than the backup declares'));
      return;
    }
    this.hash.update(chunk);
    callback(null, chunk);
  }
  digest(): string {
    return this.hash.digest('hex');
  }
}

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

export function backupDigest(manifestBytes: Uint8Array): string {
  return sha256(manifestBytes);
}

/** Opens a new file for writing: refuses an existing one, owner-only from creation. */
export type OpenOutput = (path: string) => Writable;
export const openNewFile: OpenOutput = (path) =>
  createWriteStream(path, { flags: 'wx', mode: 0o600 });

export function fsyncPath(path: string): void {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function checkRecipient(recipient: string | undefined): string {
  if (!recipient || !RECIPIENT.test(recipient))
    throw new BackupError(
      'backup',
      'BACKUP_AGE_RECIPIENT must be an age X25519 recipient (age1…): the public key only',
    );
  return recipient;
}

export const ageFailure = () =>
  new BackupError(
    'verify',
    'the backup could not be decrypted and authenticated: a wrong identity, or a damaged, ' +
      'truncated or altered file',
  );

/**
 * Streams `source` through age to a new file. Resolves with the ciphertext's size and SHA-256
 * once every byte is written and flushed; the caller decides whether the result is published.
 */
export async function encryptToFile(
  recipient: string,
  source: Readable,
  path: string,
  open: OpenOutput,
  signal?: AbortSignal,
): Promise<{ size: number; sha256: string }> {
  const encrypter = new Encrypter();
  encrypter.addRecipient(recipient);
  const encrypted = await encrypter.encrypt(
    Readable.toWeb(source) as unknown as ReadableStream<Uint8Array>,
  );
  const tap = new Tap();
  await pipeline(
    Readable.fromWeb(encrypted as unknown as WebReadableStream<Uint8Array>),
    tap,
    open(path),
    ...(signal ? [{ signal }] : []),
  );
  return { size: tap.bytes, sha256: tap.digest() };
}

export async function encryptBytesToFile(
  recipient: string,
  bytes: Uint8Array,
  path: string,
  open: OpenOutput,
): Promise<{ size: number; sha256: string }> {
  const encrypter = new Encrypter();
  encrypter.addRecipient(recipient);
  const ciphertext = await encrypter.encrypt(bytes);
  await pipeline(Readable.from([Buffer.from(ciphertext)]), open(path));
  return { size: ciphertext.length, sha256: sha256(ciphertext) };
}

/** A plain file, not a link or anything else, of at most `maxBytes`. */
function regularFile(path: string, what: string, maxBytes: number): Stats {
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch {
    throw new BackupError('verify', `${what} is missing`);
  }
  if (!stat.isFile()) throw new BackupError('verify', `${what} is not a regular file`);
  if (stat.size > maxBytes) throw new BackupError('verify', `${what} is larger than allowed`);
  return stat;
}

function hashFile(path: string): Promise<string> {
  const tap = new Tap();
  return pipeline(
    createReadStream(path),
    tap,
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  ).then(() => tap.digest());
}

/**
 * Reads the offline identity for one restore. The file must be the operator's own (no group or
 * other permissions), hold exactly one X25519 identity, and match the backup's recipient. Its
 * contents are never logged or put in an error. (JavaScript cannot zero a string; the process
 * ends after the restore.)
 */
export async function readIdentity(path: string, recipient: string): Promise<string> {
  const stat = regularFile(path, 'the identity file', MAX_IDENTITY_FILE_BYTES);
  if ((stat.mode & 0o077) !== 0)
    throw new BackupError(
      'verify',
      'the identity file is readable by others; keep it owner-only (chmod 600)',
    );
  const keys = readFileSync(path, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
  const [identity] = keys;
  if (keys.length !== 1 || !identity || !IDENTITY.test(identity))
    throw new BackupError('verify', 'the identity file must hold exactly one age X25519 identity');
  if ((await identityToRecipient(identity)) !== recipient)
    throw new BackupError('verify', "this identity is not the backup's recipient");
  return identity;
}

export interface OpenedBackup {
  readonly manifest: Manifest;
  readonly meta: BackupMeta;
  /** SHA-256 of the manifest file: what the operator compares with their own record. */
  readonly digest: string;
  readonly provenance: 'trusted-digest' | 'unchecked';
  /** The dump's plaintext, decrypted as it is read. The caller checks `tap` at the end. */
  decryptDump(): Promise<{ plaintext: Readable; tap: Tap }>;
}

/**
 * VERIFY, before anything is created: the manifest (bounded, exact schema, its digest against
 * the operator's), both files (plain files in the manifest's directory, named by its stem,
 * bounded, sizes and SHA-256 as listed), the identity, and the encrypted metadata (decrypted,
 * exact schema, the same backup id). The dump itself is verified by `verifyDump`.
 */
export async function openBackup(options: {
  manifestPath: string;
  identityPath: string;
  /** The digest the operator kept apart from backup storage; `false`: explicitly not checked. */
  trustedDigest: string | false;
  maxDumpBytes?: number;
}): Promise<OpenedBackup> {
  const manifestPath = options.manifestPath;
  const name = basename(manifestPath);
  const stem = name.endsWith('.manifest.json') ? name.slice(0, -'.manifest.json'.length) : '';
  if (!STEM.test(stem)) throw new BackupError('verify', 'not a Ruvee backup manifest file name');
  regularFile(manifestPath, 'the manifest', MAX_MANIFEST_BYTES);
  const manifestBytes = readFileSync(manifestPath);
  const digest = backupDigest(manifestBytes);
  if (options.trustedDigest !== false) {
    if (!SHA256.test(options.trustedDigest))
      throw new BackupError('verify', 'the trusted digest must be 64 hexadecimal characters');
    if (options.trustedDigest !== digest)
      throw new BackupError(
        'verify',
        'the manifest does not match the trusted digest you supplied: this is not that backup',
      );
  }
  let manifest: Manifest;
  try {
    manifest = manifestSchema.parse(JSON.parse(manifestBytes.toString('utf8')));
  } catch {
    throw new BackupError('verify', 'the manifest is not a supported Ruvee backup (format 2)');
  }
  if (
    manifest.files.dump.file !== `${stem}.dump.age` ||
    manifest.files.meta.file !== `${stem}.meta.age`
  )
    throw new BackupError('verify', 'the manifest names files outside its own backup set');
  const dir = dirname(manifestPath);
  const dumpPath = join(dir, manifest.files.dump.file);
  const metaPath = join(dir, manifest.files.meta.file);
  const maxDump = options.maxDumpBytes ?? DEFAULT_MAX_DUMP_BYTES;
  for (const [path, entry, max, what] of [
    [dumpPath, manifest.files.dump, maxDump, 'the encrypted dump'],
    [metaPath, manifest.files.meta, MAX_META_BYTES, 'the encrypted metadata'],
  ] as const) {
    if (entry.size > max) throw new BackupError('verify', `${what} is larger than allowed`);
    const stat = regularFile(path, what, max);
    if (stat.size !== entry.size || (await hashFile(path)) !== entry.sha256)
      throw new BackupError('verify', `${what} does not match the manifest (size or SHA-256)`);
  }
  const identity = await readIdentity(options.identityPath, manifest.recipient);
  const decrypter = new Decrypter();
  decrypter.addIdentity(identity);
  let meta: BackupMeta;
  try {
    const metaPlain = await decrypter.decrypt(readFileSync(metaPath), 'text');
    meta = metaSchema.parse(JSON.parse(metaPlain));
  } catch (error) {
    if (error instanceof z.ZodError || error instanceof SyntaxError)
      throw new BackupError('verify', 'the backup metadata is not a supported format');
    throw ageFailure();
  }
  if (meta.backupId !== manifest.backupId)
    throw new BackupError('verify', 'the metadata belongs to another backup');

  const decryptDump = async () => {
    let plaintext;
    try {
      plaintext = await decrypter.decrypt(
        Readable.toWeb(createReadStream(dumpPath)) as unknown as ReadableStream<Uint8Array>,
      );
    } catch {
      throw ageFailure();
    }
    const tap = new Tap(meta.dump.size);
    // A decryption error destroys `tap` with that error; consumers report it as ageFailure.
    streamPipeline(
      Readable.fromWeb(plaintext as unknown as WebReadableStream<Uint8Array>),
      tap,
      () => undefined,
    );
    return { plaintext: tap as Readable, tap };
  };
  return {
    manifest,
    meta,
    digest,
    provenance: options.trustedDigest === false ? 'unchecked' : 'trusted-digest',
    decryptDump,
  };
}

/** Decrypts the whole dump once, authenticating every chunk, and checks its SHA-256 and size. */
export async function verifyDump(backup: OpenedBackup): Promise<void> {
  const { plaintext, tap } = await backup.decryptDump();
  try {
    await pipeline(
      plaintext,
      new Writable({
        write(_chunk, _encoding, callback) {
          callback();
        },
      }),
    );
  } catch (error) {
    if (error instanceof BackupError) throw error;
    throw ageFailure();
  }
  if (tap.bytes !== backup.meta.dump.size || tap.digest() !== backup.meta.dump.sha256)
    throw new BackupError('verify', 'the decrypted dump does not match its metadata');
}

export const newBackupId = () => randomUUID();
