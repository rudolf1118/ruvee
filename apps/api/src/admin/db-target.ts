import { Transform, type TransformCallback } from 'node:stream';
import pg from 'pg';

/**
 * The one database a backup or restore command acts on (predeployment-review R7). A connection
 * URL is parsed once, here; node-pg gets the resulting fields as a config object and the
 * PostgreSQL tools get them as explicit libpq keywords, so no second parser can read a different
 * database out of the same string. Query parameters, fragments and multiple hosts are refused:
 * each of them can redirect libpq (`?dbname=`, `?service=`, `?options=`, `?host=`).
 */
export interface DbTarget {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly password: string;
  readonly database: string;
}

const NAME = /^[A-Za-z0-9_]{1,63}$/;

export class DbTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DbTargetError';
  }
}

/** Never includes the URL or the password in an error. */
export function parseDbTarget(url: string): DbTarget {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new DbTargetError('the database URL is not a valid URL');
  }
  if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:')
    throw new DbTargetError('the database URL must be postgres:// or postgresql://');
  if (u.search !== '' || u.hash !== '')
    throw new DbTargetError(
      'the database URL must not carry query parameters or a fragment; they can redirect the tools',
    );
  const host = decodeURIComponent(u.hostname);
  if (!host || /[,/\s]/.test(host))
    throw new DbTargetError('the database URL must name exactly one host');
  const database = decodeURIComponent(u.pathname.slice(1));
  if (!NAME.test(database))
    throw new DbTargetError('the database name must be 1 to 63 letters, digits or underscores');
  const user = decodeURIComponent(u.username);
  if (!user) throw new DbTargetError('the database URL must name a user');
  const port = u.port === '' ? 5432 : Number(u.port);
  return { host, port, user, password: decodeURIComponent(u.password), database };
}

/**
 * node-pg falls back to `PG*` variables for every field left empty; the identity fields are
 * always set, and `options` is set explicitly so `PGOPTIONS` cannot change the session.
 */
export function pgClientConfig(target: DbTarget): pg.ClientConfig {
  return {
    host: target.host,
    port: target.port,
    user: target.user,
    password: target.password,
    database: target.database,
    options: '-c search_path=public',
  };
}

const quote = (value: string) => `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

/**
 * libpq keywords for `--dbname`, with no password (it goes in `PGPASSWORD`). `hostPort` replaces
 * host and port when the tools run elsewhere (RUVEE_PG_TOOLS_HOST); the database name never
 * changes.
 */
export function libpqConninfo(target: DbTarget, hostPort?: string): string {
  let host = target.host;
  let port = String(target.port);
  if (hostPort) {
    const at = hostPort.lastIndexOf(':');
    host = at > 0 ? hostPort.slice(0, at) : hostPort;
    port = at > 0 ? hostPort.slice(at + 1) : port;
  }
  return [
    `host=${quote(host)}`,
    `port=${quote(port)}`,
    `user=${quote(target.user)}`,
    `dbname=${quote(target.database)}`,
  ].join(' ');
}

/**
 * The environment for a PostgreSQL tool: the parent's, without any `PG*` variable (PGSERVICE,
 * PGHOSTADDR, PGOPTIONS, PGDATABASE… could each redirect or reconfigure libpq), plus the password.
 */
export function toolEnvironment(password: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env))
    if (!key.toUpperCase().startsWith('PG')) env[key] = value;
  env.PGPASSWORD = password;
  return env;
}

/** Connects to exactly `target` and refuses a connection that reports another database. */
export async function connectTo(target: DbTarget): Promise<pg.Client> {
  const client = new pg.Client(pgClientConfig(target));
  await client.connect();
  try {
    const row = await client.query<{ db: string; usr: string }>(
      'SELECT current_database() AS db, current_user AS usr',
    );
    if (row.rows[0]?.db !== target.database || row.rows[0].usr !== target.user)
      throw new DbTargetError('the connection reached another database or role than the one named');
    return client;
  } catch (error) {
    await client.end();
    throw error;
  }
}

/**
 * Checks, as the dump streams past, that `pg_dump` itself connected to `database`: the custom
 * format's header records the database it read (pg_backup_archiver.c `WriteHead`). Archive
 * versions other than 1.15 and later fail closed. Passes every byte through unchanged.
 */
export class DumpHeaderCheck extends Transform {
  private head = Buffer.alloc(0);
  private checked = false;

  constructor(private readonly database: string) {
    super();
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) {
    if (!this.checked) {
      this.head = Buffer.concat([this.head, chunk]);
      let result: string | null;
      try {
        result = readDumpDatabase(this.head);
      } catch (error) {
        callback(error as Error);
        return;
      }
      if (result === null) {
        // Held back until the header is read: nothing passes before the check.
        if (this.head.length > 4096) {
          callback(new DbTargetError('the dump does not start with a known archive header'));
          return;
        }
        callback();
        return;
      }
      if (result !== this.database) {
        callback(
          new DbTargetError('pg_dump read another database than the one checked; nothing written'),
        );
        return;
      }
      this.checked = true;
      const held = this.head;
      this.head = Buffer.alloc(0);
      callback(null, held);
      return;
    }
    callback(null, chunk);
  }

  override _flush(callback: TransformCallback) {
    callback(this.checked ? null : new DbTargetError('the dump ended before its archive header'));
  }
}

/** The database name in a custom-format archive header, or `null` if more bytes are needed. */
export function readDumpDatabase(buf: Buffer): string | null {
  if (buf.length < 12) return null;
  if (buf.subarray(0, 5).toString('latin1') !== 'PGDMP')
    throw new DbTargetError('not a custom-format archive');
  const [major, minor] = [buf[5] ?? 0, buf[6] ?? 0];
  const intSize = buf[8] ?? 0;
  if (major !== 1 || minor < 15 || intSize < 1 || intSize > 8)
    throw new DbTargetError('an archive version this check does not know');
  // magic, 3 version bytes, intSize, offSize, format, compression algorithm.
  let at = 12;
  const readInt = (): number | undefined => {
    if (buf.length < at + 1 + intSize) return undefined;
    const negative = buf[at] !== 0;
    let value = 0;
    for (let i = 0; i < intSize; i++) value += (buf[at + 1 + i] ?? 0) * 2 ** (8 * i);
    at += 1 + intSize;
    return negative ? -value : value;
  };
  // Seven creation-time fields, then the database name as a length-prefixed string.
  for (let i = 0; i < 7; i++) if (readInt() === undefined) return null;
  const length = readInt();
  if (length === undefined) return null;
  if (length < 0 || length > 255) throw new DbTargetError('an archive header out of bounds');
  if (buf.length < at + length) return null;
  return buf.subarray(at, at + length).toString('utf8');
}
