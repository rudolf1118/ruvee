import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dropDatabase, TEMP_DATABASE_NAME } from './temp-database.js';

/**
 * Global setup of the integration run. Workers append every temporary database they create to a
 * ledger in a directory made here; when the run ends, every database listed there is dropped by
 * its exact name (most are already gone). This covers a worker that was killed or crashed before
 * its own cleanup. Nothing is dropped by prefix, and no other directory is touched.
 */
export default function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'ruvee-it-ledger-'));
  // The main process never changes DATABASE_URL: its database is not a temporary one.
  const serverUrl = process.env.DATABASE_URL;
  process.env.RUVEE_IT_LEDGER_DIR = dir;
  return async () => {
    if (!serverUrl) throw new Error('DATABASE_URL is not set');
    const names = readdirSync(dir)
      .filter((f) => f.endsWith('.txt'))
      .flatMap((f) => readFileSync(join(dir, f), 'utf8').split('\n').filter(Boolean));
    for (const name of new Set(names))
      if (TEMP_DATABASE_NAME.test(name)) await dropDatabase(serverUrl, name);
    rmSync(dir, { recursive: true, force: true });
  };
}
