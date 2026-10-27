// The isolated backend for one test run: the repository's own test-only stack script
// (apps/api/scripts/e2e-stack.mjs, unchanged) creates a throwaway `ruvee_e2e_*` database on the
// PostgreSQL server in RUVEE_E2E_ADMIN_DATABASE_URL, migrates it, writes an OPAQUE server setup
// and a bootstrap token, and runs the built API; on exit it drops everything it created. The web
// app's static export is served by apps/web/scripts/serve-export.mjs with /api proxied, which is
// the single origin both the browser and the phone use. Every line either process prints is kept
// for the log scan.

import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../../../', import.meta.url));

export interface Stack {
  readonly origin: string;
  readonly bootstrapToken: string;
  readonly database: string;
  /** Everything the API and the web server printed. */
  logs(): string;
  stop(): Promise<void>;
}

async function waitFor(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out waiting for ${url}`);
}

function stopProcess(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
    }, 15_000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill('SIGTERM');
  });
}

export async function startStack(params: { webPort: number; apiPort: number }): Promise<Stack> {
  const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
  if (!adminUrl)
    throw new Error(
      'Set RUVEE_E2E_ADMIN_DATABASE_URL (a PostgreSQL server whose role may create databases).',
    );
  const origin = `http://127.0.0.1:${String(params.webPort)}`;
  const stateFile = join(tmpdir(), `ruvee-mobile-e2e-${String(params.webPort)}.json`);
  rmSync(stateFile, { force: true });
  const output: string[] = [];
  const collect = (child: ChildProcess) => {
    child.stdout?.on('data', (d: Buffer) => output.push(d.toString('utf8')));
    child.stderr?.on('data', (d: Buffer) => output.push(d.toString('utf8')));
  };

  const api = spawn('node', [join(repo, 'apps/api/scripts/e2e-stack.mjs')], {
    cwd: join(repo, 'apps/api'),
    env: {
      ...process.env,
      RUVEE_E2E_ADMIN_DATABASE_URL: adminUrl,
      RUVEE_E2E_STATE_FILE: stateFile,
      RUVEE_E2E_API_PORT: String(params.apiPort),
      RUVEE_E2E_PUBLIC_ORIGIN: origin,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  collect(api);
  const web = spawn('node', ['scripts/serve-export.mjs'], {
    cwd: join(repo, 'apps/web'),
    env: {
      ...process.env,
      RUVEE_EXPORT_DIR: 'out',
      RUVEE_EXPORT_PORT: String(params.webPort),
      RUVEE_API_ORIGIN: `http://127.0.0.1:${String(params.apiPort)}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  collect(web);

  const stop = async () => {
    await stopProcess(web);
    await stopProcess(api);
  };
  try {
    await waitFor(`http://127.0.0.1:${String(params.apiPort)}/health/ready`, 90_000);
    await waitFor(origin, 30_000);
  } catch (error) {
    await stop();
    throw new Error(`stack did not start: ${String(error)}\n${output.join('')}`);
  }
  const state = JSON.parse(readFileSync(stateFile, 'utf8')) as {
    bootstrapToken: string;
    database: string;
  };
  return {
    origin,
    bootstrapToken: state.bootstrapToken,
    database: state.database,
    logs: () => output.join(''),
    stop,
  };
}
