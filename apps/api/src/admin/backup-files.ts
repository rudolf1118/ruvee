import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  constants,
  createWriteStream,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  promises as fsp,
  rmSync,
  type Stats,
} from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
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

/** Which source file is about to be opened; a test seam for adversarial changes (R9). */
export type SourceFile = 'manifest' | 'meta' | 'dump' | 'identity';
export interface VerifyHooks {
  beforeOpen?(file: SourceFile): void | Promise<void>;
}

/**
 * Opens a source file exactly once (predeployment-review R9): `O_NOFOLLOW` refuses a symbolic
 * link in the last path component, and the type and size come from the descriptor, so a rename
 * or a link swapped in after the open changes nothing for this read.
 */
async function openSource(path: string, what: string, maxBytes: number): Promise<FileHandle> {
  let handle: FileHandle;
  try {
    handle = await fsp.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') throw new BackupError('verify', `${what} is missing`);
    if (code === 'ELOOP' || code === 'EMLINK')
      throw new BackupError('verify', `${what} is not a regular file`);
    throw new BackupError('verify', `${what} cannot be read`);
  }
  const stat = await handle.stat();
  if (!stat.isFile()) {
    await handle.close();
    throw new BackupError('verify', `${what} is not a regular file`);
  }
  if (stat.size > maxBytes) {
    await handle.close();
    throw new BackupError('verify', `${what} is larger than allowed`);
  }
  return handle;
}

/** Everything from an open descriptor, refusing more than `maxBytes` (a file that grew). */
async function readAll(handle: FileHandle, what: string, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const buf = Buffer.alloc(Math.min(65_536, maxBytes + 1 - total));
    if (buf.length === 0) throw new BackupError('verify', `${what} is larger than allowed`);
    const { bytesRead } = await handle.read(buf, 0, buf.length, null);
    if (bytesRead === 0) break;
    total += bytesRead;
    chunks.push(buf.subarray(0, bytesRead));
  }
  return Buffer.concat(chunks);
}

/** Reads a small source file once, through one descriptor, and closes it. */
async function readSource(
  path: string,
  what: string,
  maxBytes: number,
): Promise<{ bytes: Buffer; stat: Stats }> {
  const handle = await openSource(path, what, maxBytes);
  try {
    const stat = await handle.stat();
    return { bytes: await readAll(handle, what, maxBytes), stat };
  } finally {
    await handle.close();
  }
}

/**
 * The offline identity for one restore, read once through one descriptor. The file must be the
 * operator's own (no group or other permissions), hold exactly one X25519 identity, and match the
 * backup's recipient. Its contents are never logged or put in an error. (JavaScript cannot zero a
 * string; the process ends after the restore.)
 */
export async function readIdentity(path: string, recipient: string): Promise<string> {
  const { bytes, stat } = await readSource(path, 'the identity file', MAX_IDENTITY_FILE_BYTES);
  if ((stat.mode & 0o077) !== 0)
    throw new BackupError(
      'verify',
      'the identity file is readable by others; keep it owner-only (chmod 600)',
    );
  const keys = bytes
    .toString('utf8')
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

/**
 * A private staging directory for one restore: created by this process with `mkdtemp`, owned by
 * its user, no group or other permissions. Only ciphertext is ever written to it, and it is
 * removed when the restore ends.
 */
function privateStagingDir(root: string): string {
  const dir = mkdtempSync(join(root, 'ruvee-restore-'));
  const stat = lstatSync(dir);
  const uid = process.getuid?.();
  if (!stat.isDirectory() || (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o077) !== 0) {
    rmSync(dir, { recursive: true, force: true });
    throw new BackupError('verify', 'the staging directory is not private to this user');
  }
  return dir;
}

export interface OpenedBackup {
  readonly manifest: Manifest;
  readonly meta: BackupMeta;
  /** SHA-256 of the manifest file: what the operator compares with their own record. */
  readonly digest: string;
  readonly provenance: 'trusted-digest' | 'unchecked';
  /**
   * The dump's plaintext, decrypted as it is read from the staged copy. The caller checks, at
   * the end, `tap` (plaintext: size and SHA-256 as in the metadata) and `cipher` (ciphertext:
   * size and SHA-256 as in the manifest) before treating the bytes as good.
   */
  decryptDump(): Promise<{ plaintext: Readable; tap: Tap; cipher: Tap }>;
  /** Removes the staged copy. Always called when the restore ends. */
  cleanup(): void;
}

/** True when both taps of a finished pass match what the manifest and metadata promise. */
export function passMatches(backup: OpenedBackup, tap: Tap, cipher: Tap): boolean {
  return (
    tap.bytes === backup.meta.dump.size &&
    tap.digest() === backup.meta.dump.sha256 &&
    cipher.bytes === backup.manifest.files.dump.size &&
    cipher.digest() === backup.manifest.files.dump.sha256
  );
}

/**
 * VERIFY, before anything is created (predeployment-review R9: the bytes verified are the bytes
 * used). The manifest and the metadata are read once each into memory, through one descriptor,
 * and everything checked about them is checked on those same bytes: the manifest's digest
 * against the operator's, its exact schema and file names, the metadata's size and SHA-256, its
 * decryption and schema. The dump is copied once, through one descriptor, into a private staging
 * directory while its SHA-256 is computed; every later read is of that copy, and each pass
 * hashes the ciphertext again. Nothing is read from the backup's own directory after this.
 */
export async function openBackup(options: {
  manifestPath: string;
  identityPath: string;
  /** The digest the operator kept apart from backup storage; `false`: explicitly not checked. */
  trustedDigest: string | false;
  maxDumpBytes?: number;
  /** Where the private staging directory is made; the system temporary directory by default. */
  stagingRoot?: string;
  hooks?: VerifyHooks;
}): Promise<OpenedBackup> {
  const manifestPath = options.manifestPath;
  const name = basename(manifestPath);
  const stem = name.endsWith('.manifest.json') ? name.slice(0, -'.manifest.json'.length) : '';
  if (!STEM.test(stem)) throw new BackupError('verify', 'not a Ruvee backup manifest file name');
  await options.hooks?.beforeOpen?.('manifest');
  const { bytes: manifestBytes } = await readSource(
    manifestPath,
    'the manifest',
    MAX_MANIFEST_BYTES,
  );
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
  const maxDump = options.maxDumpBytes ?? DEFAULT_MAX_DUMP_BYTES;
  if (manifest.files.dump.size > maxDump)
    throw new BackupError('verify', 'the encrypted dump is larger than allowed');
  if (manifest.files.meta.size > MAX_META_BYTES)
    throw new BackupError('verify', 'the encrypted metadata is larger than allowed');

  // The metadata: read once; hashed and decrypted from the same bytes.
  await options.hooks?.beforeOpen?.('meta');
  const { bytes: metaBytes } = await readSource(
    join(dir, manifest.files.meta.file),
    'the encrypted metadata',
    MAX_META_BYTES,
  );
  if (
    metaBytes.length !== manifest.files.meta.size ||
    sha256(metaBytes) !== manifest.files.meta.sha256
  )
    throw new BackupError(
      'verify',
      'the encrypted metadata does not match the manifest (size or SHA-256)',
    );

  // The dump: copied once into private staging, hashed as it is copied.
  const staging = privateStagingDir(options.stagingRoot ?? tmpdir());
  const stagedDump = join(staging, 'dump.age');
  const cleanup = () => {
    rmSync(staging, { recursive: true, force: true });
  };
  try {
    await options.hooks?.beforeOpen?.('dump');
    const source = await openSource(
      join(dir, manifest.files.dump.file),
      'the encrypted dump',
      maxDump,
    );
    const copied = createHash('sha256');
    let copiedBytes = 0;
    try {
      const out = await fsp.open(
        stagedDump,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        // One descriptor in, one out: the bytes hashed are exactly the bytes staged.
        const buf = Buffer.alloc(1 << 20);
        for (;;) {
          const { bytesRead } = await source.read(buf, 0, buf.length, null);
          if (bytesRead === 0) break;
          copiedBytes += bytesRead;
          if (copiedBytes > maxDump)
            throw new BackupError('verify', 'the encrypted dump is larger than allowed');
          const chunk = buf.subarray(0, bytesRead);
          copied.update(chunk);
          await out.write(chunk, 0, chunk.length);
        }
        await out.sync();
      } finally {
        await out.close();
      }
    } finally {
      await source.close();
    }
    if (
      copiedBytes !== manifest.files.dump.size ||
      copied.digest('hex') !== manifest.files.dump.sha256
    )
      throw new BackupError(
        'verify',
        'the encrypted dump does not match the manifest (size or SHA-256)',
      );

    await options.hooks?.beforeOpen?.('identity');
    const identity = await readIdentity(options.identityPath, manifest.recipient);
    const decrypter = new Decrypter();
    decrypter.addIdentity(identity);
    let meta: BackupMeta;
    try {
      const metaPlain = await decrypter.decrypt(metaBytes, 'text');
      meta = metaSchema.parse(JSON.parse(metaPlain));
    } catch (error) {
      if (error instanceof z.ZodError || error instanceof SyntaxError)
        throw new BackupError('verify', 'the backup metadata is not a supported format');
      throw ageFailure();
    }
    if (meta.backupId !== manifest.backupId)
      throw new BackupError('verify', 'the metadata belongs to another backup');

    const decryptDump = async () => {
      const handle = await openSource(stagedDump, 'the staged dump', maxDump);
      const cipher = new Tap(manifest.files.dump.size);
      const ciphertext = streamPipeline(handle.createReadStream(), cipher, () => undefined);
      let plaintext;
      try {
        plaintext = await decrypter.decrypt(
          Readable.toWeb(ciphertext) as unknown as ReadableStream<Uint8Array>,
        );
      } catch {
        ciphertext.destroy();
        throw ageFailure();
      }
      const tap = new Tap(meta.dump.size);
      // A decryption error destroys `tap` with that error; consumers report it as ageFailure.
      streamPipeline(
        Readable.fromWeb(plaintext as unknown as WebReadableStream<Uint8Array>),
        tap,
        () => undefined,
      );
      return { plaintext: tap as Readable, tap, cipher };
    };
    return {
      manifest,
      meta,
      digest,
      provenance: options.trustedDigest === false ? 'unchecked' : 'trusted-digest',
      decryptDump,
      cleanup,
    };
  } catch (error) {
    cleanup();
    throw error;
  }
}

/**
 * Decrypts the whole staged dump once, authenticating every chunk, and checks the plaintext's
 * SHA-256 and size against the metadata and the ciphertext's against the manifest.
 */
export async function verifyDump(backup: OpenedBackup): Promise<void> {
  const { plaintext, tap, cipher } = await backup.decryptDump();
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
  if (!passMatches(backup, tap, cipher))
    throw new BackupError('verify', 'the decrypted dump does not match its metadata');
}

export const newBackupId = () => randomUUID();
