import { dropTracked } from './temp-database.js';

/**
 * After every integration test file: drop the temporary databases it created and did not drop,
 * for example because a `beforeAll` failed or a test timed out before its own cleanup. Only the
 * exact names this process created are dropped (temp-database.ts).
 */
afterAll(async () => {
  const left = await dropTracked();
  if (left.length > 0)
    process.stderr.write(
      `dropped ${String(left.length)} temporary database(s) a test left behind\n`,
    );
}, 60_000);
