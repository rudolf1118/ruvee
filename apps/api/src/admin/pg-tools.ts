import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { z } from 'zod';

/**
 * The PostgreSQL client tools a backup and a restore run (`pg_dump`, `pg_restore`). They must be
 * the server's major version or newer. By default they are found on PATH. `RUVEE_PG_TOOLS_PREFIX`
 * (a JSON array, never a shell string) runs them through another program, such as `docker exec`
 * into the database container; `RUVEE_PG_TOOLS_HOST` is then the host and port as seen from there.
 * The password goes in `PGPASSWORD`, never on a command line.
 */
export interface PgTools {
  dump(databaseUrl: string, outPath: string, excludeTables: readonly string[]): Promise<void>;
  restore(databaseUrl: string, inPath: string): Promise<void>;
}

const prefixSchema = z.array(z.string().min(1).max(200)).max(20);

export function pgToolsFromEnv(env: NodeJS.ProcessEnv = process.env): PgTools {
  const prefix = env.RUVEE_PG_TOOLS_PREFIX
    ? prefixSchema.parse(JSON.parse(env.RUVEE_PG_TOOLS_PREFIX))
    : [];
  const host = env.RUVEE_PG_TOOLS_HOST;

  const target = (databaseUrl: string) => {
    const url = new URL(databaseUrl);
    const password = decodeURIComponent(url.password);
    url.password = '';
    if (host) url.host = host;
    return { url: url.toString(), password };
  };

  const run = (
    tool: string,
    args: string[],
    password: string,
    io: {
      stdin?: string;
      stdout?: string;
    },
  ) =>
    new Promise<void>((resolve, reject) => {
      const [command, ...before] = prefix.length > 0 ? prefix : [tool];
      const argv = prefix.length > 0 ? [...before, tool, ...args] : args;
      const child = spawn(command ?? tool, argv, {
        env: { ...process.env, PGPASSWORD: password },
        stdio: [io.stdin ? 'pipe' : 'ignore', io.stdout ? 'pipe' : 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr?.on('data', (chunk: Buffer) => {
        // Kept short: tool errors name objects, not data.
        if (stderr.length < 4000) stderr += chunk.toString('utf8');
      });
      if (io.stdin && child.stdin) createReadStream(io.stdin).pipe(child.stdin);
      if (io.stdout && child.stdout)
        // Owner-only: the dump holds every wrap and verifier (backup-restore.md §3.1).
        child.stdout.pipe(createWriteStream(io.stdout, { flags: 'wx', mode: 0o600 }));
      child.on('error', reject);
      child.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`${tool} failed (exit ${String(code)}): ${stderr.trim()}`));
      });
    });

  return {
    async dump(databaseUrl, outPath, excludeTables) {
      const { url, password } = target(databaseUrl);
      await run(
        'pg_dump',
        [
          '--format=custom',
          '--no-owner',
          '--no-privileges',
          ...excludeTables.map((t) => `--exclude-table=${t}`),
          `--dbname=${url}`,
        ],
        password,
        { stdout: outPath },
      );
    },
    async restore(databaseUrl, inPath) {
      const { url, password } = target(databaseUrl);
      await run(
        'pg_restore',
        [
          '--exit-on-error',
          '--no-owner',
          '--no-privileges',
          '--single-transaction',
          `--dbname=${url}`,
        ],
        password,
        { stdin: inPath },
      );
    },
  };
}
