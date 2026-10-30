import { spawn, type ChildProcess } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { z } from 'zod';
import { libpqConninfo, toolEnvironment, type DbTarget } from './db-target.js';

/**
 * The PostgreSQL client tools a backup and a restore run (`pg_dump`, `pg_restore`). They must be
 * the server's major version or newer. By default they are found on PATH. `RUVEE_PG_TOOLS_PREFIX`
 * (a JSON array, never a shell string) runs them through another program, such as `docker exec`
 * into the database container; `RUVEE_PG_TOOLS_HOST` is then the host and port as seen from there.
 * The password goes in `PGPASSWORD`, never on a command line, and is never in an error message.
 *
 * Every tool streams: the plaintext dump goes straight from `pg_dump` into encryption, and from
 * decryption straight into `pg_restore`. No plaintext dump file is ever written
 * (backup-restore.md §3.2).
 */
export interface ToolRun {
  /** Resolves when the tool exited with status 0; rejects otherwise. */
  readonly done: Promise<void>;
  /** Stops the tool at once (SIGKILL), for a failed or interrupted pipeline. */
  kill(): void;
}

export interface PgTools {
  /** `pg_dump --format=custom` of the database to `stdout`. */
  dump(
    target: DbTarget,
    exclude: {
      readonly tables: readonly string[];
      /** Dumped with their definitions but without rows. */
      readonly tableData: readonly string[];
      readonly schemas: readonly string[];
    },
  ): ToolRun & { stdout: Readable };
  /** `pg_restore --single-transaction` into the database, reading the dump from `stdin`. */
  restore(target: DbTarget): ToolRun & { stdin: Writable };
  /** `pg_restore -f -`: the dump as SQL text, with no database (for the R13 scan). */
  toSql(): ToolRun & { stdin: Writable; stdout: Readable };
}

const prefixSchema = z.array(z.string().min(1).max(200)).max(20);

/** Tool errors name objects and connection targets, never data; the password is never in them. */
function redact(text: string, password: string): string {
  const short = text.trim().slice(0, 2000);
  return password ? short.split(password).join('[redacted]') : short;
}

export function pgToolsFromEnv(env: NodeJS.ProcessEnv = process.env): PgTools {
  const prefix = env.RUVEE_PG_TOOLS_PREFIX
    ? prefixSchema.parse(JSON.parse(env.RUVEE_PG_TOOLS_PREFIX))
    : [];
  const host = env.RUVEE_PG_TOOLS_HOST;

  const run = (tool: string, args: string[], password: string, stdin: boolean, stdout: boolean) => {
    const [command, ...before] = prefix.length > 0 ? prefix : [tool];
    const argv = prefix.length > 0 ? [...before, tool, ...args] : args;
    const child: ChildProcess = spawn(command ?? tool, argv, {
      // No inherited PG* variable can redirect the tool (predeployment-review R7).
      env: toolEnvironment(password),
      stdio: [stdin ? 'pipe' : 'ignore', stdout ? 'pipe' : 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < 4000) stderr += chunk.toString('utf8');
    });
    const done = new Promise<void>((resolve, reject) => {
      child.on('error', (error) => {
        reject(new Error(`${tool} could not be started: ${error.message}`));
      });
      child.on('close', (code, signal) => {
        if (code === 0) resolve();
        else
          reject(
            new Error(
              `${tool} failed (${signal ? `signal ${signal}` : `exit ${String(code)}`}): ${redact(stderr, password)}`,
            ),
          );
      });
    });
    // A caller that stops early still observes `done`; never an unhandled rejection.
    done.catch(() => undefined);
    return {
      child,
      done,
      kill: () => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      },
    };
  };

  return {
    dump(target, exclude) {
      const r = run(
        'pg_dump',
        [
          '--format=custom',
          '--no-owner',
          '--no-privileges',
          ...exclude.tables.map((t) => `--exclude-table=${t}`),
          ...exclude.tableData.map((t) => `--exclude-table-data=${t}`),
          ...exclude.schemas.map((n) => `--exclude-schema=${n}`),
          // Explicit libpq keywords from the one parsed target (db-target.ts), never a URL.
          `--dbname=${libpqConninfo(target, host)}`,
        ],
        target.password,
        false,
        true,
      );
      if (!r.child.stdout) throw new Error('pg_dump has no output stream');
      return { stdout: r.child.stdout, done: r.done, kill: r.kill };
    },
    restore(target) {
      const r = run(
        'pg_restore',
        [
          '--exit-on-error',
          '--no-owner',
          '--no-privileges',
          '--single-transaction',
          `--dbname=${libpqConninfo(target, host)}`,
        ],
        target.password,
        true,
        false,
      );
      if (!r.child.stdin) throw new Error('pg_restore has no input stream');
      return { stdin: r.child.stdin, done: r.done, kill: r.kill };
    },
    toSql() {
      const r = run('pg_restore', ['--file=-'], '', true, true);
      if (!r.child.stdin || !r.child.stdout) throw new Error('pg_restore has no streams');
      return { stdin: r.child.stdin, stdout: r.child.stdout, done: r.done, kill: r.kill };
    },
  };
}
