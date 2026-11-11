import { PORTABLE_CHECKS, type PortableEnv } from './portable/checks.js';
import { nodeEnv } from './support/node-env.js';

let env: PortableEnv;

beforeAll(async () => {
  env = await nodeEnv();
});

describe('portable checks in Node (the same code runs in browsers)', () => {
  for (const check of PORTABLE_CHECKS) {
    it(`${check.category}: ${check.id}`, async () => {
      await check.run(env);
    });
  }
});
