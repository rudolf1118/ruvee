import { z } from 'zod';

/**
 * The CSP has no `'unsafe-eval'`. Zod would otherwise probe `new Function("")` on first parse to
 * decide whether to compile validators, which the browser blocks and Firefox reports as a CSP
 * violation. Jitless mode never tries. Imported first by the worker and the app.
 */
z.config({ jitless: true });
