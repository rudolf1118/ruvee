import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

/**
 * Integration tests never migrate the database in DATABASE_URL. They create a uniquely named
 * database on the same server (`ruvee_it_<random>`), migrate that, and drop it afterwards.
 * The role in DATABASE_URL therefore needs CREATEDB.
 */
const PREFIX = 'ruvee_it_';
const apiRoot = new URL('../../', import.meta.url);

function adminUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL must point at a PostgreSQL server for integration tests');
  return url;
}

function withDatabase(url: string, database: string): string {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
}

export interface TempDatabase {
  readonly name: string;
  readonly url: string;
  drop(): Promise<void>;
}

export async function createTempDatabase(): Promise<TempDatabase> {
  const name = `${PREFIX}${randomBytes(6).toString('hex')}`;
  // Captured now: a harness later points DATABASE_URL at the temporary database itself.
  const serverUrl = adminUrl();
  const admin = new pg.Client({ connectionString: serverUrl });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${name}"`);
  } finally {
    await admin.end();
  }
  return {
    name,
    url: withDatabase(serverUrl, name),
    async drop() {
      if (!name.startsWith(PREFIX))
        throw new Error('refusing to drop a database the test did not create');
      const client = new pg.Client({ connectionString: serverUrl });
      await client.connect();
      try {
        await client.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      } finally {
        await client.end();
      }
    },
  };
}

/** `prisma migrate deploy` against the given database; throws with Prisma's output on failure. */
export function migrate(url: string): void {
  const result = spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
    cwd: apiRoot.pathname,
    env: { ...process.env, DATABASE_URL: url, PRISMA_HIDE_UPDATE_MESSAGE: '1' },
    encoding: 'utf8',
  });
  if (result.status !== 0)
    throw new Error(`prisma migrate deploy failed:\n${result.stdout}${result.stderr}`);
}

export async function runSqlFile(url: string, relativePath: string): Promise<void> {
  const sql = await readFile(new URL(relativePath, apiRoot), 'utf8');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

export async function query<T extends pg.QueryResultRow>(
  url: string,
  text: string,
  values: unknown[] = [],
): Promise<T[]> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return (await client.query<T>(text, values)).rows;
  } finally {
    await client.end();
  }
}
