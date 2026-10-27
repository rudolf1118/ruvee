import { z } from 'zod';
import { installRandom } from './random';

/**
 * Runs before any shared module is evaluated (index.js imports it first).
 *
 * - Randomness: see ./random.ts.
 * - Zod: jitless, as in the web app and the extension, so validators are never compiled with
 *   `new Function` and behave the same on every client.
 */
installRandom();
z.config({ jitless: true });
